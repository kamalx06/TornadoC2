import { contextBridge, ipcRenderer, webUtils } from 'electron'

/** Narrow surface: one invoke, two event channels, no ipcRenderer. */
const api = {
  invoke: (method: string, params: Record<string, unknown> = {}, timeoutMs?: number) =>
    ipcRenderer.invoke('bridge:invoke', { method, params, timeoutMs }),
  status: () => ipcRenderer.invoke('app:status'),
  detach: (view: string) => ipcRenderer.invoke('app:detach', view),
  pickConfig: () => ipcRenderer.invoke('app:pick-config'),
  pathForFile: (file: File) => webUtils.getPathForFile(file),
  saveFile: (name: string, body: string) => ipcRenderer.invoke('app:save-file', name, body),
  saveBinary: (name: string, b64: string) =>
    ipcRenderer.invoke('app:save-binary', name, b64),
  pickPath: (name: string) => ipcRenderer.invoke('app:pick-path', name),
  pickOpen: () => ipcRenderer.invoke('app:pick-open'),
  installUpdate: () => ipcRenderer.invoke('app:install-update'),
  windowControl: (a: 'min' | 'max' | 'close') =>
    ipcRenderer.invoke('window:control', a),
  clipboard: (value: string, clearMs = 30_000) =>
    ipcRenderer.invoke('app:clipboard', value, clearMs),
  onLog: (fn: (line: string) => void) => {
    const h = (_e: unknown, line: string): void => fn(line)
    ipcRenderer.on('bridge:log', h)
    return () => ipcRenderer.off('bridge:log', h)
  },
  onUpdate: (fn: (data: { state: string; version?: string; message?: string }) => void) => {
    const h = (_e: unknown, data: { state: string; version?: string; message?: string }): void => fn(data)
    ipcRenderer.on('update', h)
    return () => ipcRenderer.off('update', h)
  },
  onConn: (fn: (data: { state: string }) => void) => {
    const h = (_e: unknown, data: { state: string }): void => fn(data)
    ipcRenderer.on('bridge:conn', h)
    return () => ipcRenderer.off('bridge:conn', h)
  }
}

contextBridge.exposeInMainWorld('t2', api)
export type T2Api = typeof api
