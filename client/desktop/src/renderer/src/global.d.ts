export {}

declare global {
  interface Window {
    t2: {
      invoke: (
        method: string,
        params?: Record<string, unknown>,
        timeoutMs?: number
      ) => Promise<{ ok: boolean; result?: unknown; error?: string; code?: string }>
      status: () => Promise<{
        connected: boolean
        config: string
        safe?: boolean
        platform?: string
        operator?: string
        role?: string
        caps?: string[]
      }>
      pickConfig: () => Promise<string>
      pathForFile: (file: File) => string
      clipboard: (value: string, clearMs?: number) => Promise<boolean>
      saveFile: (name: string, body: string) => Promise<string>
      saveBinary: (name: string, b64: string) => Promise<string>
      pickPath: (name: string) => Promise<string>
      pickOpen: () => Promise<string>
      detach: (view: string) => Promise<boolean>
      installUpdate: () => Promise<void>
      windowControl: (a: 'min' | 'max' | 'close') => Promise<boolean>
      onLog: (fn: (line: string) => void) => () => void
      onUpdate: (fn: (d: { state: string; version?: string; message?: string }) => void) => () => void
      onConn: (fn: (data: { state: string }) => void) => () => void
    }
  }
}
