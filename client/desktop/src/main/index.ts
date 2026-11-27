import { app, BrowserWindow, dialog, ipcMain, protocol, clipboard as electronClipboard } from 'electron'
import { join, normalize, resolve } from 'node:path'
import { readFile, writeFile, chmod } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { Bridge, BridgeError } from './bridge'
import { installNavigationGuards, installSessionGuards } from './security'
import { startUpdater, installUpdate } from './updater'
import { requestSchema, responseSchema, type Request } from '../shared/ipc'

const isDev = !app.isPackaged && Boolean(process.env.ELECTRON_RENDERER_URL)
const APP_ORIGIN = 'app://bundle'
const SAFE = process.argv.includes('--safe') || process.env.TORNADOC2_SAFE === '1'
const repoRoot = process.env.TORNADOC2_REPO ?? (app.isPackaged
  ? join(process.resourcesPath, 't2')
  : resolve(app.getAppPath(), '..', '..'))

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'app',
    privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false }
  }
])

let win: BrowserWindow | null = null
let bridge: Bridge | null = null
let session: { name: string; role: string; caps: string[] } | null = null
let clipboardTimer: NodeJS.Timeout | null = null

function configPath(): string {
  const idx = process.argv.indexOf('--config')
  if (idx >= 0) {
    const next = process.argv[idx + 1]
    if (next) return next
  }
  return process.env.TORNADOC2_CFG ?? ''
}

function broadcast(channel: string, data: unknown): void {
  for (const w of BrowserWindow.getAllWindows()) {
    w.webContents.send(channel, data)
  }
}

function makeChildWindow(): BrowserWindow {
  const w = new BrowserWindow({
    width: 980,
    height: 720,
    minWidth: 680,
    minHeight: 480,
    show: false,
    backgroundColor: '#04060a',
    titleBarStyle: 'hidden',
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
      spellcheck: false,
      devTools: isDev
    }
  })
  w.once('ready-to-show', () => w.show())
  const origin = isDev ? 'http://localhost' : APP_ORIGIN
  installNavigationGuards(w, origin, isDev)
  return w
}

function makeWindow(): BrowserWindow {
  const w = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1040,
    minHeight: 640,
    show: false,
    backgroundColor: '#04060a',
    titleBarStyle: 'hidden',
    trafficLightPosition: { x: 12, y: 14 },
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: false,
      spellcheck: false,
      devTools: isDev
    }
  })

  w.once('ready-to-show', () => w.show())
  installNavigationGuards(w, isDev ? 'http://localhost' : APP_ORIGIN, isDev)
  return w
}

async function serveBundle(): Promise<void> {
  const root = join(__dirname, '../renderer')
  protocol.handle('app', async (req) => {
    const url = new URL(req.url)
    let rel = decodeURIComponent(url.pathname)
    if (rel === '/' || rel === '') rel = '/index.html'
    const file = normalize(join(root, rel))
    if (!file.startsWith(root)) {
      return new Response('forbidden', { status: 403 })
    }
    try {
      const body = await readFile(file)
      const type = file.endsWith('.html')
        ? 'text/html'
        : file.endsWith('.js')
          ? 'text/javascript'
          : file.endsWith('.css')
            ? 'text/css'
            : file.endsWith('.svg')
              ? 'image/svg+xml'
              : 'application/octet-stream'
      return new Response(body, { headers: { 'Content-Type': type } })
    } catch {
      return new Response('not found', { status: 404 })
    }
  })
}

function asSession(value: unknown): { name: string; role: string; caps: string[] } | null {
  if (!value || typeof value !== 'object') return null
  const v = value as { name?: unknown; role?: unknown; caps?: unknown }
  if (typeof v.name !== 'string' || typeof v.role !== 'string') return null
  const caps = Array.isArray(v.caps)
    ? v.caps.filter((c): c is string => typeof c === 'string').slice(0, 64)
    : []
  return { name: v.name.slice(0, 80), role: v.role.slice(0, 40), caps }
}

function registerIpc(): void {
  ipcMain.handle('bridge:invoke', async (_ev, raw: unknown) => {
    const parsed = requestSchema.safeParse(raw)
    if (!parsed.success) {
      return { ok: false, error: 'bad request', code: 'bad_params' }
    }
    const req: Request = parsed.data
    if (!bridge) return { ok: false, error: 'bridge down', code: 'down' }
    try {
      const result = await bridge.send(req.method, req.params, req.timeoutMs ?? 30_000)
      if (req.method === 'connect') session = asSession(result)
      if (req.method === 'disconnect') {
        session = null
        for (const w of BrowserWindow.getAllWindows()) {
          w.webContents.send('bridge:conn', { state: 'idle' })
        }
      }
      return responseSchema.parse({ ok: true, result })
    } catch (err) {
      const e = err as BridgeError
      return responseSchema.parse({
        ok: false,
        error: e.message,
        code: e.code ?? 'error'
      })
    }
  })

  ipcMain.handle('app:status', () => ({
    connected: bridge?.connected ?? false,
    config: configPath(),
    safe: SAFE,
    platform: process.platform,
    operator: session?.name,
    role: session?.role,
    caps: session?.caps
  }))

  ipcMain.handle('window:control', (ev, action: string) => {
    const w = BrowserWindow.fromWebContents(ev.sender)
    if (!w) return false
    if (action === 'min') w.minimize()
    else if (action === 'max') {
      w.isMaximized() ? w.unmaximize() : w.maximize()
    } else if (action === 'close') w.close()
    return true
  })

  ipcMain.handle('app:pick-config', async () => {
    const r = await dialog.showOpenDialog({
      title: 'Operator config',
      properties: ['openFile'],
      filters: [{ name: 'TornadoC2 config', extensions: ['cfg', 'json'] }]
    })
    return r.canceled ? '' : (r.filePaths[0] ?? '')
  })

  ipcMain.handle('app:save-file', async (_ev, name: string, body: string) => {
    const safe = String(name).replace(/[^\w.-]/g, '_') || 'export.txt'
    const r = await dialog.showSaveDialog({ title: 'Save export', defaultPath: safe })
    if (r.canceled || !r.filePath) return ''
    await writeFile(r.filePath, body, 'utf8')
    await chmod(r.filePath, 0o600)
    return r.filePath
  })

  ipcMain.handle('app:save-binary', async (_ev, name: string, b64: string) => {
    const safe = String(name).replace(/[^\w.-]/g, '_') || 'capture.png'
    const buf = Buffer.from(String(b64), 'base64')
    if (!buf.length || buf.length > 32 << 20) return ''
    const r = await dialog.showSaveDialog({ title: 'Save capture', defaultPath: safe })
    if (r.canceled || !r.filePath) return ''
    await writeFile(r.filePath, buf, { mode: 0o600 })
    await chmod(r.filePath, 0o600)
    return r.filePath
  })

  ipcMain.handle('app:pick-path', async (_ev, name: string) => {
    const safe = String(name).replace(/[^\w.-]/g, '_') || 'output.bin'
    const r = await dialog.showSaveDialog({ title: 'Choose output', defaultPath: safe })
    return r.canceled ? '' : (r.filePath ?? '')
  })

  ipcMain.handle('app:pick-open', async () => {
    const r = await dialog.showOpenDialog({ title: 'Choose file', properties: ['openFile'] })
    return r.canceled ? '' : (r.filePaths[0] ?? '')
  })

  ipcMain.handle('app:detach', async (_ev, raw: unknown) => {
    const panel = String(raw ?? '').toLowerCase()
    if (!/^[a-z]{3,16}$/.test(panel)) return false
    const w = makeChildWindow()
    const base = isDev
      ? `${process.env.ELECTRON_RENDERER_URL}/index.html`
      : `${APP_ORIGIN}/index.html`
    await w.loadURL(`${base}#detach/${panel}`)
    return true
  })

  ipcMain.handle('app:install-update', () => installUpdate())

  ipcMain.handle('app:clipboard', async (_ev, value: string, clearMs: number) => {
    await electronClipboard.writeText(String(value))
    if (clipboardTimer) clearTimeout(clipboardTimer)
    if (clearMs > 0) {
      clipboardTimer = setTimeout(() => {
        void electronClipboard.readText().then((current) => {
          if (current === value) electronClipboard.clear()
        })
      }, clearMs)
    }
    return true
  })
}

app.whenReady().then(async () => {
  installSessionGuards()
  registerIpc()
  await serveBundle()

  const py = Bridge.pythonPath(repoRoot)
  console.log(`[main] repo=${repoRoot} python=${py}`)
  bridge = new Bridge(repoRoot, py, configPath())
  bridge.on('log', (line: string) => broadcast('bridge:log', line))
  bridge.on('conn', (data: unknown) => {
    const d = data as { state?: string; code?: number }
    console.log(`[main] bridge ${d.state ?? 'event'}${d.code !== undefined ? ` (${d.code})` : ''}`)
    broadcast('bridge:conn', data)
  })

  win = makeWindow()
  if (isDev) {
    await win.loadURL(`${process.env.ELECTRON_RENDERER_URL}/index.html`)
  } else {
    await win.loadURL(`${APP_ORIGIN}/index.html`)
  }
  app.on('browser-window-created', (_e, w) => {
    installNavigationGuards(w, isDev ? 'http://localhost' : APP_ORIGIN, isDev)
  })

  startUpdater(win)
  bridge.start().catch((err: Error) => {
    win?.webContents.send('bridge:log', `[main] bridge start failed: ${err.message}\n`)
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      win = makeWindow()
      void win.loadURL(isDev ? `${process.env.ELECTRON_RENDERER_URL}/index.html` : `${APP_ORIGIN}/index.html`)
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  void bridge?.stop()
})

// Exported for vitest without Electron bootstrapping.
export { repoRoot, configPath, pathToFileURL }
