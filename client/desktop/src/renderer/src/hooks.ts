import { useCallback, useEffect, useRef, useState } from 'react'

export async function invoke<T>(method: string, params: Record<string, unknown> = {}, timeoutMs?: number): Promise<T> {
  const r = await window.t2.invoke(method, params, timeoutMs)
  if (!r.ok) throw new Error(r.error ?? r.code ?? 'request failed')
  return r.result as T
}

/** Poll a read method; `deps` restarts the loop. */
export function usePoll<T>(
  method: string,
  params: Record<string, unknown>,
  ms: number,
  enabled = true
): { data: T | null; error: string; reload: () => void } {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  const alive = useRef(true)
  const paramsRef = useRef(params)
  paramsRef.current = params

  const load = useCallback(async () => {
    try {
      const v = await invoke<T>(method, paramsRef.current)
      if (alive.current) {
        setData(v)
        setError('')
      }
    } catch (e) {
      if (alive.current) setError((e as Error).message)
    }
  }, [method])

  useEffect(() => {
    alive.current = true
    if (!enabled) return
    void load()
    const t = setInterval(() => void load(), ms)
    return () => {
      alive.current = false
      clearInterval(t)
    }
  }, [load, ms, enabled, JSON.stringify(params)])

  return { data, error, reload: () => void load() }
}
