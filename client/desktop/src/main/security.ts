import { session, shell, type BrowserWindow } from 'electron'

const CSP = [
  "default-src 'none'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'"
].join('; ')

export function installSessionGuards(): void {
  const s = session.defaultSession
  s.setPermissionRequestHandler((_wc, permission, cb) => {
    cb(permission === 'clipboard-read' || permission === 'clipboard-sanitized-write')
  })
  s.webRequest.onHeadersReceived((details, cb) => {
    cb({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [CSP],
        'X-Content-Type-Options': ['nosniff']
      }
    })
  })
}

/** Block top-level navigation and new windows outside the app. */
export function installNavigationGuards(win: BrowserWindow, appUrl: string, isDev: boolean): void {
  const allowed = (url: string): boolean =>
    url.startsWith(appUrl) || (isDev && url.startsWith('http://localhost'))

  win.webContents.on('will-navigate', (ev, url) => {
    if (!allowed(url)) ev.preventDefault()
  })
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) {
      void shell.openExternal(url)
      return { action: 'deny' }
    }
    return { action: 'deny' }
  })
}

/** Harden the packed binary at build time (see scripts/fuses.mjs). */
export const FUSE_EXPECTATIONS = {
  onlyLoadAppFromAsar: true,
  runAsNode: false,
  enableNodeCliInspectArguments: false,
  enableNodeOptionsEnvironmentVariable: false
} as const
