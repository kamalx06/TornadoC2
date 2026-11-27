import { app } from 'electron'
import type { BrowserWindow } from 'electron'

type Sender = (channel: string, data: unknown) => void

/**
 * Signed auto-update over the GitHub release feed. Disabled in dev
 * and when `TORNADOC2_NO_UPDATE=1`.
 */
export function startUpdater(win: BrowserWindow): void {
  if (!app.isPackaged || process.env.TORNADOC2_NO_UPDATE === '1') return
  const send: Sender = (channel, data) => win.webContents.send(channel, data)

  // Imported lazily: electron-updater touches app paths at load.
  void import('electron-updater').then(({ autoUpdater }) => {
    autoUpdater.autoDownload = true
    autoUpdater.autoInstallOnAppQuit = true
    autoUpdater.on('update-available', (i) => send('update', { state: 'available', version: i.version }))
    autoUpdater.on('update-downloaded', (i) => send('update', { state: 'ready', version: i.version }))
    autoUpdater.on('error', (e) => send('update', { state: 'error', message: e.message }))
    setTimeout(() => void autoUpdater.checkForUpdates().catch(() => undefined), 8_000)
  })
}

export async function installUpdate(): Promise<void> {
  if (!app.isPackaged) return
  const { autoUpdater } = await import('electron-updater')
  autoUpdater.quitAndInstall()
}
