import { spawn, spawnSync, type ChildProcessByStdio } from 'node:child_process'
import { existsSync } from 'node:fs'
import type { Readable } from 'node:stream'
import { connect, type Socket } from 'node:net'
import { join } from 'node:path'
import { EventEmitter } from 'node:events'

const MAX_FRAME = 8 << 20
const READY_TIMEOUT = 15_000
const RESTART_DELAYS = [500, 1_000, 2_000, 4_000, 8_000]

type Pending = {
  resolve: (value: unknown) => void
  reject: (err: Error) => void
  timer: NodeJS.Timeout
}

type Ready = {
  proto: number
  socket: string
  tcp: number
  token: string
}

export class BridgeError extends Error {
  constructor(message: string, readonly code = 'error') {
    super(message)
  }
}

/**
 * Supervises the Python bridge. The Python process owns the client,
 * certificates and HTTP; this class only moves framed JSON.
 */
export class Bridge extends EventEmitter {
  private child: ChildProcessByStdio<null, Readable, Readable> | null = null
  private socket: Socket | null = null
  private ready: Ready | null = null
  private seq = 0
  private pending = new Map<number, Pending>()
  private buf = Buffer.alloc(0)
  private restarts = 0
  private stopped = false
  private starting: Promise<void> | null = null

  constructor(
    private readonly repoRoot: string,
    private readonly python: string,
    private readonly configPath: string
  ) {
    super()
  }

  async start(): Promise<void> {
    if (this.ready) return
    if (this.starting) return this.starting
    this.starting = this.spawnOnce()
    try {
      await this.starting
    } finally {
      this.starting = null
    }
  }

  private async spawnOnce(): Promise<void> {
    const probe = spawnSync(this.python,
      ['-c', 'import cryptography'])
    if (probe.status !== 0) {
      this.emit('log',
        `[main] ${this.python} cannot import cryptography. ` +
        'Run install-deps-client.sh or point TORNADOC2_PYTHON at the ' +
        'client venv.\n')
    }
    const env = {
      ...process.env,
      PYTHONPATH: join(this.repoRoot, 'client')
    }
    const args = ['-m', 'tornado_client.bridge', '--no-unix']
    if (this.configPath) args.push('--config', this.configPath)
    this.child = spawn(this.python, args, {
      cwd: this.repoRoot,
      env,
      stdio: ['ignore', 'pipe', 'pipe']
    })

    this.child.stderr.on('data', (d: Buffer) => {
      this.emit('log', d.toString('utf8'))
    })
    this.child.on('error', (err) => {
      this.emit('log', `[main] bridge spawn: ${err.message}\n`)
    })
    this.child.on('exit', (code) => {
      this.ready = null
      this.socket?.destroy()
      this.socket = null
      this.failAll('bridge exited')
      if (!this.stopped) {
        const delay = RESTART_DELAYS[
          Math.min(this.restarts, RESTART_DELAYS.length - 1)
        ]
        this.restarts += 1
        this.emit('conn', { state: 'lost', code })
        setTimeout(() => void this.start().catch(() => undefined), delay)
      }
    })

    const info = await this.readReady()
    if (info.proto !== 1) throw new BridgeError('bridge proto mismatch')
    this.ready = info
    await this.openSocket(info)
    this.restarts = 0
    this.emit('conn', { state: 'ok' })
  }

  private readReady(): Promise<Ready> {
    const child = this.child!
    return new Promise((resolve, reject) => {
      let acc = ''
      const timer = setTimeout(
        () => reject(new BridgeError('bridge ready timeout', 'timeout')),
        READY_TIMEOUT
      )
      const bail = (why: string): void => {
        clearTimeout(timer)
        child.stdout.off('data', onData)
        reject(new BridgeError(why, 'down'))
      }
      child.once('error', (e) => bail(`bridge spawn: ${e.message}`))
      child.once('exit', (code) => bail(`bridge exited (${code})`))
      const onData = (d: Buffer): void => {
        acc += d.toString('utf8')
        const nl = acc.indexOf('\n')
        if (nl < 0) return
        const line = acc.slice(0, nl)
        acc = acc.slice(nl + 1)
        child.stdout.off('data', onData)
        clearTimeout(timer)
        if (!line.startsWith('READY ')) {
          reject(new BridgeError(`bad ready line: ${line}`))
          return
        }
        try {
          resolve(JSON.parse(line.slice(6)) as Ready)
        } catch (err) {
          reject(err as Error)
        }
      }
      child.stdout.on('data', onData)
    })
  }

  private openSocket(info: Ready): Promise<void> {
    return new Promise((resolve, reject) => {
      const sock = info.tcp ? connect(info.tcp, '127.0.0.1') : connect(info.socket)
      this.socket = sock
      sock.once('error', reject)
      sock.once('connect', () => {
        sock.off('error', reject)
        sock.on('data', (d) => this.onData(d))
        sock.on('error', (err) => this.failAll(err.message))
        void this.send('hello', { token: info.token }, 5_000)
          .then(() => resolve())
          .catch(reject)
      })
    })
  }

  private onData(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk])
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0)
      if (len > MAX_FRAME) {
        this.failAll('frame too large')
        return
      }
      if (this.buf.length < 4 + len) return
      const body = this.buf.subarray(4, 4 + len)
      this.buf = this.buf.subarray(4 + len)
      try {
        this.route(JSON.parse(body.toString('utf8')))
      } catch {
        this.emit('log', '[main] undecodable bridge frame\n')
      }
    }
  }

  private route(msg: {
    id?: number
    ok?: boolean
    result?: unknown
    error?: string
    code?: string
  }): void {
    if (typeof msg.id !== 'number') return
    const p = this.pending.get(msg.id)
    if (!p) return
    this.pending.delete(msg.id)
    clearTimeout(p.timer)
    if (msg.ok) p.resolve(msg.result)
    else p.reject(new BridgeError(msg.error ?? 'bridge error', msg.code))
  }

  send(method: string, params: Record<string, unknown>, timeoutMs = 30_000): Promise<unknown> {
    const sock = this.socket
    if (!sock || !this.ready) return Promise.reject(new BridgeError('not connected', 'down'))
    const id = ++this.seq
    const raw = Buffer.from(JSON.stringify({ id, method, params }), 'utf8')
    if (raw.length > MAX_FRAME) return Promise.reject(new BridgeError('request too large'))
    const head = Buffer.alloc(4)
    head.writeUInt32BE(raw.length, 0)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new BridgeError('timeout', 'timeout'))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      sock.write(Buffer.concat([head, raw]))
    })
  }

  private failAll(reason: string): void {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer)
      p.reject(new BridgeError(reason, 'down'))
    }
    this.pending.clear()
  }

  async stop(): Promise<void> {
    this.stopped = true
    this.failAll('stopped')
    this.socket?.destroy()
    this.socket = null
    if (this.child) {
      const child = this.child
      this.child = null
      child.kill('SIGTERM')
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => {
          child.kill('SIGKILL')
          resolve()
        }, 3_000)
        child.once('exit', () => {
          clearTimeout(t)
          resolve()
        })
      })
    }
  }

  get connected(): boolean {
    return Boolean(this.ready && this.socket)
  }

  static pythonPath(repo: string): string {
    const env = process.env.TORNADOC2_PYTHON
    if (env) return env
    for (const rel of ['client/venv/bin/python',
                       'client/.venv/bin/python']) {
      const p = join(repo, rel)
      if (existsSync(p)) return p
    }
    return process.platform === 'win32' ? 'python' : 'python3'
  }
}
