// Pure parsers for text-only agent output. They never throw: a line that
// does not fit is dropped, and callers keep the raw output as a fallback.

export type Process = { pid: number; name: string; cmd: string }
export type Conn = {
  proto: string; local: string; remote: string; state: string; pid?: number
}
export type Entry = { path: string; name: string; dir: boolean }

const MAX = 5000

function lines(text: string): string[] {
  return text.replace(/\r\n/g, '\n').split('\n').slice(0, MAX + 200)
}

export function parseProcesses(text: string): Process[] {
  const out: Process[] = []
  for (const raw of lines(text)) {
    const line = raw.trim()
    if (!line || /^pid\s+command$/i.test(line)) continue
    const parts = line.split(/\s+/)
    if (parts.length < 2) continue
    let pid = 0
    let name = ''
    let cmd = ''
    if (/^\d+$/.test(parts[0]!)) {
      pid = Number(parts[0])
      cmd = parts.slice(1).join(' ')
      name = cmd.split(/[\\/]/).pop()?.split(' ')[0] ?? cmd
    } else {
      const last = parts[parts.length - 1]
      if (!last || !/^\d+$/.test(last)) continue
      pid = Number(last)
      name = parts[0]!
      cmd = parts.slice(0, -1).join(' ')
    }
    if (!pid || !cmd) continue
    out.push({ pid, name: name.slice(0, 120), cmd: cmd.slice(0, 300) })
    if (out.length >= MAX) break
  }
  return out
}

export function parseConnections(text: string): Conn[] {
  const out: Conn[] = []
  for (const raw of lines(text)) {
    const line = raw.trim()
    if (!line || /^proto\s/i.test(line)) continue
    const parts = line.split(/\s+/)
    if (parts.length < 4) continue
    const proto = parts[0]!.toLowerCase()
    if (!/^(tcp|udp|tcp6|udp6)$/.test(proto)) continue
    const local = parts[1]!
    const remote = parts[2]!
    if (!local.includes(':') || !remote.includes(':')) continue
    const state = parts[3]!
    const tail = parts[4]
    const pid = tail && /^\d+$/.test(tail) ? Number(tail) : undefined
    out.push({
      proto, local: local.slice(0, 80), remote: remote.slice(0, 80),
      state: state.slice(0, 24), pid
    })
    if (out.length >= MAX) break
  }
  return out
}

export function parseEntries(
  dirOut: string, fileOut: string, base: string
): Entry[] {
  const root = base.replace(/\\/g, '/').replace(/\/+$/, '')
  const prefix = root.endsWith('/') ? root : `${root}/`
  const out: Entry[] = []
  const seen = new Set<string>()
  for (const [text, dir] of [[dirOut, true], [fileOut, false]] as const) {
    for (const raw of lines(text)) {
      const p = raw.trim().replace(/\\/g, '/').replace(/\/+$/, '')
      if (!p || p === root) continue
      if (!p.startsWith(prefix)) continue
      const rest = p.slice(prefix.length)
      if (!rest || rest.includes('/')) continue
      if (seen.has(rest)) continue
      seen.add(rest)
      out.push({ path: p, name: rest, dir })
      if (out.length >= MAX) break
    }
  }
  return out.sort((a, b) =>
    Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name))
}

export function humanAge(ms: number): string {
  if (ms < 1000) return 'now'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m`
  return `${Math.floor(m / 60)}h`
}

export function parentPath(path: string): string {
  const p = path.replace(/\\/g, '/').replace(/\/+$/, '')
  if (!p || p === '/') return '/'
  if (/^[A-Za-z]:$/.test(p)) return `${p}\\`
  const i = p.lastIndexOf('/')
  if (i < 0) return p
  if (i === 0) return '/'
  const up = p.slice(0, i)
  return /^[A-Za-z]:$/.test(up) ? `${up}/` : up
}

export function crumbs(path: string): Array<{ label: string; path: string }> {
  const norm = path.replace(/\\/g, '/')
  const win = /^[A-Za-z]:\//.test(norm)
  const parts = norm.split('/').filter(Boolean)
  const out: Array<{ label: string; path: string }> = []
  let acc = win ? parts[0]! : ''
  for (let i = win ? 1 : 0; i < parts.length; i++) {
    acc += `/${parts[i]}`
    out.push({ label: parts[i]!, path: win ? acc : acc })
  }
  return out
}
