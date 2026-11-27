import { useCallback, useEffect, useState } from 'react'
import { invoke } from '../hooks'

type Meta = {
  name: string; format?: string; description?: string
  installed?: boolean; sha256?: string
}

export default function Armory(props: {
  caps?: string[]
  onToast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [rows, setRows] = useState<Meta[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const manage = (props.caps ?? []).includes('armory.manage')

  const load = useCallback(async (refresh = false) => {
    try {
      const r = (await invoke('armory.list', { refresh })) as {
        catalogue: Meta[]
      }
      setRows(r.catalogue)
      setErr('')
    } catch (e) {
      setErr((e as Error).message)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const act = useCallback(
    async (method: string, name: string) => {
      setBusy(true)
      try {
        await invoke(method, { names: [name], replace: true })
        props.onToast(`${method.split('.')[1]} ${name}`, 'ok')
        await load()
      } catch (e) {
        props.onToast((e as Error).message, 'err')
      } finally {
        setBusy(false)
      }
    },
    [load, props]
  )

  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">ARMORY</span>
        <span className="pill">{rows.filter((r) => r.installed).length} installed</span>
        <span className="grow" />
        <button className="btn" disabled={busy} onClick={() => void load(true)}>Update index</button>
      </div>
      {err && <div className="banner err">{err}</div>}
      <div className="table-wrap">
        <div className="row head cols-a"><span>NAME</span><span>FORMAT</span><span>DESCRIPTION</span><span /></div>
        {rows.length === 0 && !err && <div className="empty">catalogue is empty</div>}
        {rows.map((r) => (
          <div key={r.name} className="row cols-a">
            <span className="mono">{r.name}</span>
            <span className="muted">{r.format}</span>
            <span className="muted ellipsis">{r.description}</span>
            <button
              className="btn"
              disabled={busy || !manage}
              onClick={() => void act(r.installed ? 'armory.uninstall' : 'armory.install', r.name)}
            >
              {r.installed ? 'Uninstall' : 'Install'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
