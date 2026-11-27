import { useEffect, useMemo, useState } from 'react'
import { invoke } from '../hooks'

type FieldSpec = {
  name: string; type: string; required: boolean
}
type Transport = {
  id: string; label: string; description: string
  platforms: string[]; exclusive: boolean; fields: string[]
}
type Options = {
  oses: string[]; arches: string[]; formats: Record<string, string[]>
  transports: Transport[]; fields: FieldSpec[]
  tls_profiles: string[]; sleep_masks: string[]; syscall_methods: string[]
  inject_methods: string[]; jump_methods: string[]; persistence: string[]
  evasion: string[]; defaults: Record<string, string | number>
  relay_fields: string[]
}
type Error = { field: string; message: string }
const PROFILES = ['default', 'stealth', 'opsec', 'paranoid']
const LABELS: Record<string, string> = {
  url: 'Callback URL', tls_profile: 'TLS fingerprint',
  c2_profile: 'C2 profile', transport_failover_after: 'Failover after',
  dns_domain: 'DNS zone', dns_resolver: 'DNS resolver',
  doh_resolver: 'DoH resolver URL', doh_host_header: 'DoH Host header',
  doh_user_agent: 'DoH User-Agent', icmp_host: 'C2 public IPv4',
  smb_pipe: 'Pipe name or UNC path', pivot_key_path: 'Pivot key (server)',
  tcp_bind_addr: 'Bind address', tcp_bind_token: 'Bind token (64 hex)',
  tcp_rev_target: 'Parent host:port', tcp_rev_token: 'Reverse token (64 hex)',
  wireguard_server_pubkey: 'Server public key',
  wireguard_server_addr: 'Server UDP address',
  wireguard_agent_privkey: 'Agent private key',
  wireguard_tunnel_ip: 'Agent tunnel IP',
  wireguard_server_tunnel_ip: 'Server tunnel IP',
  wireguard_inner_port: 'Inner port',
  smb_relay_pipe: 'SMB relay pipe', tcp_relay_target: 'TCP relay target',
  tcp_relay_token: 'TCP relay token', tcp_rev_listen: 'TCP reverse listen'
}
const HEX64 = /^[0-9a-f]{64}$/

function token(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export default function BuildDialog(props: {
  onClose: () => void
  onDone: (msg: string) => void
}): JSX.Element {
  const [opt, setOpt] = useState<Options | null>(null)
  const [f, setF] = useState<Record<string, string>>({
    target_os: 'windows', target_arch: 'amd64', output_format: 'exe',
    transport_mode: 'http', opsec_profile: 'opsec', tls_profile: 'chrome',
    kill_days: '30', url: ''
  })
  const [errors, setErrors] = useState<Error[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [adv, setAdv] = useState<Record<string, string>>({})
  const [mtls, setMtls] = useState(false)
  const [profiles, setProfiles] = useState<Array<{ name: string; description?: string }>>([])

  useEffect(() => {
    void invoke('build.options').then((r) => {
      const o = (r as { options: Options; profiles: Array<{ name: string; description?: string }> })
      setOpt(o.options)
      setProfiles(o.profiles ?? [])
    }).catch((e) => setErr((e as Error).message))
  }, [])

  const set = (k: string) => (e: { target: { value: string } }): void =>
    setF((old) => ({ ...old, [k]: e.target.value }))

  const osName = f.target_os ?? 'linux'
  const modes = (f.transport_mode ?? 'http').split(',').filter(Boolean)
  const is = (id: string): boolean => modes.includes(id)
  const child = modes.some((m) => ['smb', 'tcp', 'tcprev'].includes(m))
  const fieldsFor = useMemo(() => {
    const map = new Map<string, FieldSpec>()
    for (const t of opt?.transports ?? []) {
      if (!is(t.id)) continue
      for (const name of t.fields) {
        const spec = opt?.fields.find((x) => x.name === name)
        if (spec) map.set(name, spec)
      }
    }
    return [...map.values()]
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opt, f.transport_mode])

  const config = useMemo(() => {
    const cfg: Record<string, unknown> = {
      ...f,
      ...adv,
      kill_days: Number(f.kill_days || 30),
      transport_failover_after: Number(f.transport_failover_after || 3),
      wasm_extensions: adv.wasm_extensions === '1',
      inject: adv.inject === '1'
    }
    for (const [k, v] of Object.entries(adv)) {
      if (v === '') delete cfg[k]
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
    return cfg
  }, [f, adv, mtls])

  useEffect(() => {
    const t = setTimeout(() => {
      void invoke('build.validate', { config }).then((r) => {
        setErrors((r as { errors: Error[] }).errors ?? [])
      }).catch(() => undefined)
    }, 180)
    return () => clearTimeout(t)
  }, [config])

  const errFor = (name: string): string =>
    errors.find((e) => e.field === name)?.message ?? ''

  const pickTransport = (id: string): void => {
    const t = opt?.transports.find((x) => x.id === id)
    if (!t) return
    let next: string[]
    if (t.exclusive) next = [id]
    else if (is(id)) next = modes.filter((m) => m !== id)
    else if (modes.some((m) => {
      const cur = opt?.transports.find((x) => x.id === m)
      return cur?.exclusive
    })) next = [...modes.filter((m) => !opt?.transports.find(
      (x) => x.id === m)?.exclusive), id]
    else next = [...modes, id]
    if (!next.length) next = ['http']
    setF((old) => ({ ...old, transport_mode: next.join(',') }))
  }

  const go = async (): Promise<void> => {
    if (errors.length) return
    setBusy(true)
    setErr('')
    try {
      const out = await window.t2.pickPath(
        `${f.target_os}-${f.target_arch}.${f.output_format}`)
      if (!out) return
      await invoke('build.start', { config, out })
      props.onDone(`build queued → ${out}`)
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const input = (name: string): JSX.Element => (
    <label key={name}>{LABELS[name] ?? name}
      <input className="field" value={f[name] ?? ''}
        aria-invalid={Boolean(errFor(name))} onChange={set(name)}
        placeholder={name.endsWith('_token') ? '64 hex characters' : ''} />
      {name.endsWith('_token') && (
        <button type="button" className="btn"
          onClick={() => setF((old) => ({ ...old, [name]: token() }))}>
          Generate
        </button>
      )}
      {errFor(name) && <span className="small errc">{errFor(name)}</span>}
    </label>
  )

  const formats = opt?.formats?.[osName] ?? ['exe']

  return (
    <div className="modal" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <form className="modal-card" role="dialog" aria-modal="true" aria-label="Build agent"
        onSubmit={(e) => { e.preventDefault(); void go() }}>
        <h2>Build agent</h2>
        <div className="modal-body grid2">
          <label>OS
            <select value={f.target_os} onChange={(e) => {
              const os = e.target.value
              setF((old) => {
                const allowed = (opt?.transports ?? [])
                  .filter((t) => t.platforms.includes(os))
                  .map((t) => t.id)
                const kept = (old.transport_mode ?? '')
                  .split(',').filter((m) => allowed.includes(m))
                return {
                  ...old, target_os: os,
                  transport_mode: kept.length ? kept.join(',')
                    : (allowed.includes('http') ? 'http' : allowed[0] ?? 'http'),
                  output_format: opt?.formats?.[os]?.[0] ?? old.output_format ?? 'elf'
                }
              })
            }}>
              {(opt?.oses ?? ['windows', 'linux']).map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>Arch
            <select value={f.target_arch} onChange={set('target_arch')}>
              {(opt?.arches ?? ['amd64', 'arm64']).map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>Format
            <select value={f.output_format} onChange={set('output_format')}>
              {formats.map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <label>OPSEC profile
            <select value={f.opsec_profile} onChange={set('opsec_profile')}>
              {PROFILES.map((x) => <option key={x}>{x}</option>)}
            </select>
          </label>
          <div className="span2">
            <span className="small muted">Transport chain</span>
            <div className="chips">
              {(opt?.transports ?? []).filter((t) =>
                t.platforms.includes(osName)).map((t) => (
                <label key={t.id} className="chip" title={t.description}>
                  <input type="checkbox" checked={is(t.id)}
                    onChange={() => pickTransport(t.id)} />
                  {t.label}
                </label>
              ))}
            </div>
            {errFor('transport_mode') && (
              <span className="small errc">{errFor('transport_mode')}</span>
            )}
          </div>

          {fieldsFor.map((spec) => {
            if (spec.name === 'tls_profile') {
              return (
                <label key={spec.name}>TLS fingerprint
                  <select value={f.tls_profile} onChange={set('tls_profile')}>
                    {(opt?.tls_profiles ?? ['go', 'chrome', 'firefox', 'safari'])
                      .map((x) => <option key={x}>{x}</option>)}
                  </select>
                </label>
              )
            }
            if (spec.name === 'c2_profile') {
              return (
                <label key={spec.name}>C2 profile
                  <select value={adv.c2_profile ?? ''}
                    onChange={(e) => setAdv({ ...adv, c2_profile: e.target.value })}>
                    <option value="">—</option>
                    {profiles.map((p) => (
                      <option key={p.name} value={p.name}>{p.name}</option>
                    ))}
                  </select>
                </label>
              )
            }
            return input(spec.name)
          })}

          {!child && (
            <>
              {input('smb_relay_pipe')}
              {input('tcp_relay_target')}
              {input('tcp_relay_token')}
              {input('tcp_rev_listen')}
              {input('tcp_rev_token')}
            </>
          )}
          {input('pivot_key_path')}

          <label>Kill days
            <input className="field" type="number" value={f.kill_days} onChange={set('kill_days')} />
          </label>
          <label>Extra tags
            <input className="field" value={adv.tags ?? ''}
              onChange={(e) => setAdv({ ...adv, tags: e.target.value })}
              placeholder="ev_unhook, update" />
          </label>
          <label>Jump methods
            <input className="field" value={adv.jump_methods ?? ''}
              onChange={(e) => setAdv({ ...adv, jump_methods: e.target.value })}
              placeholder="psexec,winrm" />
          </label>
          <label>Persistence
            <input className="field" value={adv.persistence ?? ''}
              onChange={(e) => setAdv({ ...adv, persistence: e.target.value })}
              placeholder="registry,task" />
          </label>
        </div>

        <details className="advanced">
          <summary>Advanced</summary>
          <div className="modal-body grid2">
            <label>Identity role
              <input className="field" value={adv.identity_role ?? ''}
                onChange={(e) => setAdv({ ...adv, identity_role: e.target.value })} />
            </label>
            <label>Sleep mask
              <select value={adv.sleep_mask ?? 'none'}
                onChange={(e) => setAdv({ ...adv, sleep_mask: e.target.value })}>
                {(opt?.sleep_masks ?? ['none']).map((x) =>
                  <option key={x} value={x}>{x || 'default'}</option>)}
              </select>
            </label>
            <label>Syscall method
              <select value={adv.syscall_method ?? 'direct'}
                onChange={(e) => setAdv({ ...adv, syscall_method: e.target.value })}>
                {(opt?.syscall_methods ?? ['direct', 'indirect']).map((x) =>
                  <option key={x}>{x}</option>)}
              </select>
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
            <label className="check">
              <input type="checkbox" checked={adv.wasm_extensions === '1'}
                onChange={(e) => setAdv({ ...adv, wasm_extensions: e.target.checked ? '1' : '' })} />
              Link the WASM host
            </label>
            <label className="check">
              <input type="checkbox" checked={adv.inject === '1'}
                onChange={(e) => setAdv({ ...adv, inject: e.target.checked ? '1' : '' })} />
              Embed injector for migrate
            </label>
          </div>
        </details>

        {errors.length > 0 && (
          <div className="err-line" role="status">
            {errors.length} validation {errors.length === 1 ? 'issue' : 'issues'}
          </div>
        )}
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
            } catch (e) { setErr((e as Error).message) }
          }}>Load config…</button>
          <button type="button" className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !opt || errors.length > 0}>
            {busy ? 'starting…' : 'Build'}
          </button>
        </div>
      </form>
    </div>
  )
}
