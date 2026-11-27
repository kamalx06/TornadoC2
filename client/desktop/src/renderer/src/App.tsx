import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { flushSync } from 'react-dom'
import type { Beacon, HealthRow } from '../../shared/ipc'
import { invoke } from './hooks'
import Dialog from './ui/Dialog'
import { EmptyState, Field, IconButton, KeyHint, MenuButton, StatusPill } from './ui'
import { Confirm } from './ui/Prompt'
import Dock, { type DockHandle } from './workspace/Dock'
import { PANELS, PANEL_IDS, canUse, type PanelId } from './workspace/panels'
import { GROUPS, GROUP_IDS, groupOf } from './workspace/groups'
import { parseDetached } from './workspace/model'
import { pushBridge } from './lib/events'
import { PROFILES, profileModel, type ProfileId } from './workspace/profiles'
import pkg from '../../../package.json'
import Targets from './features/Targets'
const Listeners = lazy(() => import('./features/Listeners'))
const Engagement = lazy(() => import('./features/Engagement'))
const GraphView = lazy(() => import('./features/Graph'))
const Audit = lazy(() => import('./features/Audit'))
const Chat = lazy(() => import('./features/Chat'))
const Armory = lazy(() => import('./features/Armory'))
const Settings = lazy(() => import('./features/Settings'))
const TargetActions = lazy(() => import('./features/TargetActions'))
const Jump = lazy(() => import('./features/Jump'))
const Ai = lazy(() => import('./features/Ai'))
const Jobs = lazy(() => import('./features/Jobs'))
const Creds = lazy(() => import('./features/Creds'))
const BuildDialog = lazy(() => import('./features/BuildDialog'))
const EventLog = lazy(() => import('./features/EventLog'))
const TerminalPane = lazy(() => import('./features/Terminal'))
const ScreenPane = lazy(() => import('./features/Screen'))
const Processes = lazy(() => import('./features/Processes'))
const FilesPane = lazy(() => import('./features/Files'))
const Network = lazy(() => import('./features/Network'))

type Conn = 'idle' | 'connecting' | 'ok' | 'down'
type Toast = { id: number; text: string; kind: 'ok' | 'err' | 'info' }
type Density = 'cozy' | 'compact' | 'dense'

const DETACHED = parseDetached(location.hash)

function loadProfile(): ProfileId {
  if (DETACHED) return 'custom'
  const p = localStorage.getItem('t2.dock.profile')
  return p === 'custom' || (p && Object.hasOwn(PROFILES, p))
    ? (p as ProfileId)
    : 'engagement'
}

function loadRecents(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem('t2:recent-cfg') ?? '[]')
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, 3) : []
  } catch {
    return []
  }
}

function score(label: string, term: string, recents: string[]): number {
  const hay = label.toLowerCase()
  let s = -1
  if (!term) s = 0
  else if (hay.startsWith(term)) s = 0
  else {
    const i = hay.indexOf(term)
    s = i >= 0 ? 2 : 0
    if (i < 0) {
      let p = 0
      for (const ch of term) {
        p = hay.indexOf(ch, p)
        if (p < 0) return -1
        p += 1
      }
      s = 3
    }
  }
  return recents.includes(label) ? s - 1 : s
}

export default function App(): JSX.Element {
  const [conn, setConn] = useState<Conn>('idle')
  const [safe, setSafe] = useState(false)
  const [platform, setPlatform] = useState('linux')
  const [active, setActive] = useState<PanelId>('targets')
  const [prefill, setPrefill] = useState<{ text: string; n: number } | null>(null)
  const prefillSeq = useRef(0)
  const [profile, setProfile] = useState<ProfileId>(loadProfile)
  const [clock, setClock] = useState(() => new Date())
  const [recentCfgs, setRecentCfgs] = useState<string[]>(loadRecents)
  const [bridge, setBridge] = useState<'checking' | 'ready' | 'down'>('checking')
  const [drag, setDrag] = useState(false)
  const cfgRef = useRef<HTMLInputElement>(null)
  const passRef = useRef<HTMLInputElement>(null)
  const [lastSession, setLastSession] = useState<{ operator?: string; role?: string; at?: number } | null>(() => {
    try { return JSON.parse(localStorage.getItem('t2:last-session') ?? 'null') } catch { return null }
  })
  const [cfg, setCfg] = useState('')
  const [password, setPassword] = useState('')
  const [ident, setIdent] = useState<{ name: string; role: string } | null>(null)
  const [caps, setCaps] = useState<string[]>([])
  const [beacons, setBeacons] = useState<Beacon[]>([])
  const [q, setQ] = useState('')
  const [sel, setSel] = useState<Set<number>>(new Set())
  const [primary, setPrimary] = useState<number | null>(null)
  const [err, setErr] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])
  const [palette, setPalette] = useState(false)
  const [palQ, setPalQ] = useState('')
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('t2:theme') === 'light' ? 'light' : 'dark'))
  const [density, setDensity] = useState<Density>(() => {
    const d = localStorage.getItem('t2:density')
    return d === 'cozy' || d === 'dense' ? d : 'compact'
  })
  const [jumpOpen, setJumpOpen] = useState(false)
  const [buildOpen, setBuildOpen] = useState(false)
  const [listeners, setListeners] = useState<HealthRow[]>([])
  const [update, setUpdate] = useState<{ state: string; version?: string; message?: string } | null>(null)
  const [paletteKey, setPaletteKey] = useState(
    localStorage.getItem('t2:paletteKey') || 'k')
  const [dialog, setDialog] = useState<'task' | 'tag' | null>(null)
  const [confirmKill, setConfirmKill] = useState(false)
  const [taskLine, setTaskLine] = useState('')
  const [tag, setTag] = useState('')
  const toastId = useRef(1)
  const dockRef = useRef<DockHandle>(null)

  const toast = useCallback((text: string, kind: Toast['kind'] = 'info') => {
    const id = toastId.current++
    setToasts((t) => [...t.slice(-3), { id, text, kind }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000)
  }, [])

  const logline = useCallback((line: string) => { pushBridge(line) }, [])

  useEffect(() => {
    document.documentElement.dataset.platform = platform
  }, [platform])

  useEffect(() => {
    if (!ident) cfgRef.current?.focus()
  }, [ident])

  useEffect(() => {
    if (ident) return
    let live = true
    const probe = (): void => {
      void invoke('ping').then(
        () => { if (live) setBridge('ready') },
        () => {
          if (!live) return
          setBridge((b) => (b === 'ready' ? 'down' : 'down'))
        })
    }
    probe()
    const timer = setInterval(probe, 3000)
    return () => { live = false; clearInterval(timer) }
  }, [ident])

  useEffect(() => {
    if (!err) return
    ;(cfg
      ? passRef.current ?? document.querySelector<HTMLInputElement>('input[type=password]')
      : cfgRef.current)?.focus()
  }, [err, cfg])

  useEffect(() => {
    document.title = DETACHED
      ? `${PANELS[DETACHED].title} — TornadoC2`
      : 'TornadoC2'
  }, [])

  useEffect(() => {
    if (conn !== 'ok') return
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [conn])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.dataset.density = density
    localStorage.setItem('t2:theme', theme)
    localStorage.setItem('t2:density', density)
  }, [theme, density])

  useEffect(() => {
    const offLog = window.t2.onLog(logline)
    const offUpd = window.t2.onUpdate((d) => setUpdate(d))
    const offConn = window.t2.onConn((d) => {
      if (d.state === 'ok') setConn('ok')
      if (d.state === 'lost') {
        setConn('down')
        toast('bridge lost — reconnecting', 'err')
      }
      if (d.state === 'idle') {
        setConn('idle')
        setIdent(null)
        setCaps([])
        setSel(new Set())
        setPrimary(null)
      }
    })
    void window.t2.status().then((s) => {
      setCfg(s.config)
      setSafe(Boolean(s.safe))
      if (s.platform) setPlatform(s.platform)
      if (s.connected) {
        setConn('ok')
        if (s.operator && s.role) {
          setIdent({ name: s.operator, role: s.role })
          setCaps(s.caps ?? [])
        }
      }
    })
    return () => {
      offLog()
      offUpd()
      offConn()
    }
  }, [logline, toast])

  const syncCaps = useCallback(async () => {
    for (let i = 0; i < 5; i++) {
      try {
        const r = await invoke<{ caps?: string[] }>('capabilities')
        if (r.caps?.length) { setCaps(r.caps); return }
      } catch { /* banner may not be ready yet */ }
      await new Promise((r) => setTimeout(r, 400))
    }
  }, [])

  const connect = useCallback(async () => {
    setErr('')
    setConn('connecting')
    try {
      const res = (await invoke('connect', { config: cfg, password })) as {
        name: string
        role: string
        caps: string[]
      }
      setIdent(res)
      setCaps(res.caps ?? [])
      if (!res.caps?.length) void syncCaps()
      setPassword('')
      try {
        const last = { operator: res.name, role: res.role, at: Date.now() }
        localStorage.setItem('t2:last-session', JSON.stringify(last))
        setLastSession(last)
      } catch { /* ignore */ }
      setConn('ok')
      setRecentCfgs((prev) => {
        const next = [cfg, ...prev.filter((x) => x !== cfg)].slice(0, 3)
        try {
          localStorage.setItem('t2:recent-cfg', JSON.stringify(next))
        } catch {
          /* ignore */
        }
        return next
      })
      toast(`connected as ${res.name}`, 'ok')
    } catch (e) {
      const msg = (e as Error).message
      const text = msg.includes('not connected') || msg.includes('down') ||
        msg.includes('missing Python')
        ? 'the Python bridge is not running — check the Events pane and ' +
          'run install-deps-client.sh (or set TORNADOC2_PYTHON)'
        : msg
      flushSync(() => {
        setConn('down')
        setErr(text)
      })
      ;(cfg
        ? passRef.current ?? document.querySelector<HTMLInputElement>('input[type=password]')
        : cfgRef.current)?.focus()
    }
  }, [cfg, password, toast, syncCaps])

  const disconnect = useCallback(async () => {
    await invoke('disconnect').catch(() => undefined)
    setIdent(null)
    setConn('idle')
    setSel(new Set())
    setPrimary(null)
  }, [])

  const refresh = useCallback(async () => {
    if (conn !== 'ok') return
    try {
      setBeacons((await invoke('beacons')) as Beacon[])
    } catch (e) {
      toast((e as Error).message, 'err')
    }
  }, [conn, toast])

  useEffect(() => {
    if (conn !== 'ok') return
    void refresh()
    const t = setInterval(() => void refresh(), 4000)
    return () => clearInterval(t)
  }, [conn, refresh])

  useEffect(() => {
    if (conn !== 'ok') return
    const load = (): void => {
      void invoke<{ listeners: HealthRow[] }>('listeners.health')
        .then((r) => setListeners(r.listeners))
        .catch(() => undefined)
    }
    load()
    const t = setInterval(load, 15_000)
    return () => clearInterval(t)
  }, [conn])

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return beacons
    return beacons.filter((b) =>
      [b.id, b.display_name, b.alias, b.os]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(needle)
    )
  }, [beacons, q])

  const selected = beacons.find((b) => b.id === primary) ?? null
  const ids = useMemo(() => [...sel], [sel])
  const live = useMemo(() => beacons.filter((b) => b.alive).length, [beacons])
  const health = useMemo(() => ({
    ok: listeners.filter((l) => l.health === 'ok').length,
    degraded: listeners.filter((l) => l.health === 'degraded').length,
    down: listeners.filter((l) => l.health === 'down').length
  }), [listeners])

  const can = useCallback((cap: string) => caps.includes(cap), [caps])

  const openPanel = useCallback((id: PanelId) => {
    if (!canUse(PANELS[id], caps)) {
      toast(`${PANELS[id].title} needs ${PANELS[id].cap}`, 'err')
      return
    }
    if (dockRef.current?.open(id)) setActive(id)
    else toast('workspace not ready', 'err')
  }, [caps, toast])

  const applyProfile = useCallback((id: Exclude<ProfileId, 'custom'>) => {
    dockRef.current?.apply(profileModel(id))
    setProfile(id)
    localStorage.setItem('t2.dock.profile', id)
    toast(`${PROFILES[id].label} profile`, 'ok')
  }, [toast])

  const markCustom = useCallback(() => {
    setProfile((p) => {
      if (p === 'custom') return p
      localStorage.setItem('t2.dock.profile', 'custom')
      return 'custom'
    })
  }, [])

  const select = useCallback((next: number[], focus: number | null) => {
    setSel(new Set(next))
    setPrimary(focus)
  }, [])

  const setAlias = useCallback(async (id: number, alias: string) => {
    try {
      await invoke('beacon.alias', { id, alias })
      await refresh()
      toast(alias ? `alias set for #${id}` : `alias cleared for #${id}`, 'ok')
    } catch (e) {
      toast((e as Error).message, 'err')
    }
  }, [refresh, toast])

  const attach = useCallback(async () => {
    if (!selected) return
    await window.t2.clipboard(String(selected.id), 0)
    openPanel('inspector')
    toast(`target #${selected.id} selected`, 'ok')
  }, [selected, openPanel, toast])

  const openConsole = useCallback((command = '') => {
    setPrefill({ text: command, n: ++prefillSeq.current })
    openPanel('terminal')
  }, [openPanel])

  const bulk = useCallback(
    async (action: 'task' | 'tag' | 'kill', payload: Record<string, unknown>) => {
      try {
        const r = (await invoke('bulk', {
          action, ids, ...payload
        })) as { results: Array<{ id: number; error?: string }> }
        const bad = r.results.filter((x) => x.error).length
        toast(
          bad ? `${r.results.length - bad}/${r.results.length} ok, ${bad} failed`
            : `${r.results.length} beacon(s) ${action}ed`,
          bad ? 'err' : 'ok'
        )
        setSel(new Set())
        setPrimary(null)
        await refresh()
      } catch (e) {
        toast((e as Error).message, 'err')
      }
    },
    [ids, refresh, toast]
  )

  const exportAs = useCallback(
    async (kind: 'ioc' | 'stix' | 'report') => {
      try {
        const body = await window.t2.invoke(
          kind === 'report' ? 'report' : `export.${kind}`, {})
        if (!body.ok) throw new Error(body.error ?? 'export failed')
        const data = body.result as { csv?: string; bundle?: unknown; markdown?: string }
        const text =
          kind === 'ioc' ? (data.csv ?? '')
            : kind === 'stix' ? JSON.stringify(data.bundle, null, 2)
              : (data.markdown ?? '')
        const name =
          kind === 'ioc' ? 'iocs.csv' : kind === 'stix' ? 'stix.json' : 'report.md'
        const saved = await window.t2.saveFile(name, text)
        if (saved) toast(`saved ${saved}`, 'ok')
      } catch (e) {
        toast((e as Error).message, 'err')
      }
    },
    [toast]
  )

  const allowed = useMemo(
    () => PANEL_IDS.filter((id) => canUse(PANELS[id], caps)), [caps])

  const commands = useMemo(
    () => [
      { id: 'attach', label: 'Attach to selection', run: () => void attach() },
      { id: 'task', label: 'Run task on selection…', run: () => setDialog('task') },
      { id: 'tag', label: 'Tag selection…', run: () => setDialog('tag') },
      { id: 'kill', label: 'Kill selection', run: () => setConfirmKill(true) },
      { id: 'jump', label: 'Jump to host…', run: () => setJumpOpen(true) },
      { id: 'build', label: 'Build agent…', run: () => setBuildOpen(true) },
      { id: 'ioc', label: 'Export IOCs', run: () => void exportAs('ioc') },
      { id: 'stix', label: 'Export STIX', run: () => void exportAs('stix') },
      { id: 'report', label: 'Export report', run: () => void exportAs('report') },
      { id: 'refresh', label: 'Refresh targets', run: () => void refresh() },
      { id: 'layout', label: 'Reset layout', run: () => dockRef.current?.reset() },
      ...(DETACHED ? [] : (Object.keys(PROFILES) as Array<keyof typeof PROFILES>).map((id) => ({
        id: `profile:${id}`, label: `Profile: ${PROFILES[id].label}`,
        run: () => applyProfile(id)
      }))),
      { id: 'copy', label: 'Copy selected id', run: async () => {
        if (primary) { await window.t2.clipboard(String(primary)); toast('id copied', 'ok') }
      } },
      ...allowed.map((id) => ({
        id: `view:${id}`, label: `Open ${PANELS[id].title}`,
        run: () => openPanel(id)
      }))
    ],
    [attach, exportAs, primary, refresh, toast, allowed, openPanel, applyProfile]
  )

  const recents = useMemo(() => {
    try {
      return JSON.parse(localStorage.getItem('t2:recent') ?? '[]') as string[]
    } catch {
      return []
    }
  }, [palette])

  const palItems = useMemo(() => {
    const term = palQ.trim().toLowerCase()
    return commands
      .map((c) => ({ c, s: score(c.label, term, recents) }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => a.s - b.s)
      .map((x) => x.c)
  }, [commands, palQ, recents])

  const remember = (label: string): void => {
    const next = [label, ...recents.filter((x) => x !== label)].slice(0, 8)
    localStorage.setItem('t2:recent', JSON.stringify(next))
  }

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === paletteKey) {
        e.preventDefault()
        setPalette((p) => !p)
      }
      if (e.key === 'Escape') {
        setPalette(false)
        setDialog(null)
        setJumpOpen(false)
      }
      const typing = e.target instanceof HTMLElement &&
        ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName)
      if (e.key === 'Enter' && !typing && !palette && !dialog && selected) {
        void attach()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [palette, dialog, selected, attach, paletteKey])

  const renderPanel = useCallback((id: PanelId): JSX.Element => {
    switch (id) {
      case 'targets':
        return <Targets rows={rows} total={beacons.length} query={q}
          onQuery={setQ} onRefresh={() => void refresh()} sel={sel}
          primary={primary} density={density} onSelect={select}
          onAlias={setAlias}
          onAttach={() => void attach()} onTask={() => setDialog('task')}
          onTag={() => setDialog('tag')} onKill={() => setConfirmKill(true)} />
      case 'inspector':
        return selected
          ? <TargetActions beacon={selected} caps={caps} onToast={toast}
              onChanged={() => void refresh()} onConsole={openConsole} />
          : <EmptyState glyph="❯" title="No target selected"
              hint="pick a beacon in Targets to inspect it" />
      case 'terminal':
        return <TerminalPane beacon={selected} onToast={toast}
          prefill={prefill} onPrefillUsed={() => setPrefill(null)} />
      case 'screen':
        return <ScreenPane beacon={selected} onToast={toast} />
      case 'processes':
        return <Processes beacon={selected} caps={caps} onToast={toast} />
      case 'files':
        return <FilesPane beacon={selected} caps={caps} onToast={toast} />
      case 'network':
        return <Network beacon={selected} caps={caps} onToast={toast} />
      case 'listeners':
        return <Listeners enabled={!safe} caps={caps} onToast={toast} />
      case 'engagement':
        return <Engagement enabled={!safe} caps={caps} onExport={exportAs} toast={toast} />
      case 'graph':
        return <GraphView enabled={!safe} selectedId={primary}
          onSelect={(id) => { select([id], id); openPanel('inspector') }} />
      case 'audit':
        return <Audit enabled={!safe} caps={caps} />
      case 'chat':
        return <Chat enabled={!safe} me={ident?.name ?? ''} />
      case 'armory':
        return <Armory onToast={toast} caps={caps} />
      case 'ai':
        return <Ai onToast={toast} />
      case 'jobs':
        return <Jobs onToast={toast} />
      case 'creds':
        return <Creds onToast={toast} />
      case 'events':
        return <EventLog enabled={!safe} onToast={toast} />
      case 'settings':
        return <Settings config={cfg} theme={theme} density={density}
          paletteKey={paletteKey}
          onPaletteKey={(k) => {
            if (!k) return
            setPaletteKey(k.toLowerCase())
            localStorage.setItem('t2:paletteKey', k.toLowerCase())
          }}
          onTheme={setTheme} onDensity={setDensity} />
    }
  }, [rows, beacons.length, q, sel, primary, density, caps, selected, toast, openPanel, select, ident?.name,
    refresh, attach, exportAs, safe, cfg, theme, paletteKey, setAlias, prefill, openConsole])

  if (conn !== 'ok' || !ident) {
    const step = cfg ? (password ? 3 : 2) : 1
    const ready = bridge === 'ready'
    return (
      <div className={`gate${drag ? ' drag' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={(e) => {
          if (e.currentTarget === e.target) setDrag(false)
        }}
        onDrop={(e) => {
          e.preventDefault()
          setDrag(false)
          const file = e.dataTransfer?.files?.[0]
          if (!file) return
          const path = window.t2.pathForFile(file)
          if (!/\.(cfg|json)$/i.test(path)) {
            setErr('choose an operator .cfg (or .json) file')
            return
          }
          setCfg(path)
          setErr('')
        }}>
        <header className="gate-top">
          <div className="brand">Tornado<span>C2</span></div>
          <span className="gate-top-label mono">operator session</span>
          <span className={`gate-bridge ${bridge}`}>
            <i aria-hidden="true" />bridge {bridge === 'checking' ? '…' : bridge}
          </span>
        </header>

        <aside className="gate-brand" aria-label="About TornadoC2">
          <div className="gate-lockup">
            <span className="gate-kicker">TornadoC2 // Operator</span>
            <h1 className="brand big">Tornado<span>C2</span></h1>
            <p className="gate-lead">
              A console over a local Python bridge. Certificates, HTTP and
              RBAC never enter the renderer.
            </p>
          </div>

          <ul className="gate-ready" aria-label="Launch readiness">
            <li data-state={bridge}>
              <i aria-hidden="true" />
              <span>Bridge</span>
              <b>{bridge === 'ready' ? 'live' : bridge === 'down' ? 'offline' : 'checking'}</b>
            </li>
            <li data-state={cfg ? 'ok' : 'idle'}>
              <i aria-hidden="true" />
              <span>Config</span>
              <b>{cfg ? 'selected' : 'required'}</b>
            </li>
            <li data-state={cfg ? 'ok' : 'idle'}>
              <i aria-hidden="true" />
              <span>Transport</span>
              <b>mTLS + HMAC</b>
            </li>
            <li data-state="ok">
              <i aria-hidden="true" />
              <span>State</span>
              <b>local only</b>
            </li>
          </ul>

          {lastSession?.operator && (
            <div className="gate-last">
              <span className="gate-last-label">last session</span>
              <b>{lastSession.operator}</b>
              <span className="muted">@{lastSession.role}</span>
              {lastSession.at && (
                <span className="mono muted">
                  {new Date(lastSession.at).toLocaleString()}
                </span>
              )}
            </div>
          )}

          <dl className="gate-meta">
            <dt>build</dt><dd className="mono">{pkg.version}</dd>
            <dt>platform</dt><dd className="mono">{platform}</dd>
          </dl>
        </aside>

        <main className="gate-main">
          <form className="gate-card" aria-labelledby="gate-title"
            onSubmit={(e) => { e.preventDefault(); void connect() }}>
            <header>
              <span className="gate-kicker">Session launch</span>
              <h2 id="gate-title">Start a session</h2>
              <p>Use the operator config issued by the team server.</p>
            </header>

            <ol className="gate-steps" aria-label="Connection steps">
              <li data-done={Boolean(cfg)} aria-current={step === 1 ? 'step' : undefined}>
                <span>1</span> Config
              </li>
              <li data-done={Boolean(cfg && password)}
                aria-current={step === 2 ? 'step' : undefined}>
                <span>2</span> Credentials
              </li>
              <li aria-current={step === 3 ? 'step' : undefined}>
                <span>3</span> Connect
              </li>
            </ol>

            <div className={`gate-drop${cfg ? ' has-file' : ''}`}>
              <span className="gate-drop-glyph" aria-hidden="true">⇩</span>
              {cfg ? (
                <div className="gate-file">
                  <b className="mono">{cfg.split('/').pop()}</b>
                  <span className="mono muted" title={cfg}>{cfg}</span>
                </div>
              ) : (
                <p>Drop the operator <b>.cfg</b> here</p>
              )}
              <button type="button" className="btn"
                onClick={async () => {
                  const p = await window.t2.pickConfig()
                  if (p) { setCfg(p); setErr('') }
                }}>Browse…</button>
            </div>

            <Field label="Operator config path" ref={cfgRef}
              placeholder="/path/operator.cfg" value={cfg}
              onChange={(e) => setCfg(e.target.value)} />

            {recentCfgs.length > 0 && (
              <div className="gate-recents" aria-label="Recent configs">
                <span className="gate-recents-label">recent</span>
                {recentCfgs.map((path) => (
                  <button key={path} type="button" className="link"
                    title={path} onClick={() => { setCfg(path); setErr('') }}>
                    {path.split('/').pop()}
                  </button>
                ))}
              </div>
            )}

            <Field label="Operator password" type="password" ref={passRef}
              placeholder="if required" hint="kept in memory for this session"
              value={password} onChange={(e) => setPassword(e.target.value)} />

            {err && (
              <div className="gate-error" role="alert">
                <b>Could not start</b>
                <span>{err}</span>
              </div>
            )}

            <button className="btn primary gate-go"
              disabled={conn === 'connecting' || !cfg || bridge === 'down'}>
              {conn === 'connecting'
                ? <><span className="spinner" aria-hidden="true" /> Connecting…</>
                : ready ? 'Connect' : bridge === 'down' ? 'Bridge offline' : 'Connect'}
            </button>
            <p className="gate-foot mono">
              {cfg ? 'ready when you are' : 'select a config to continue'} ·
              local session · no telemetry
            </p>
          </form>
        </main>

        <div className="gate-mobile-brand">
          <span className="brand">Tornado<span>C2</span></span>
          <span className="mono muted">{platform}</span>
        </div>

        {platform !== 'darwin' && (
          <div className="gate-wctl wctl">
            <button aria-label="Minimise" onClick={() => void window.t2.windowControl('min')}>–</button>
            <button aria-label="Maximise" onClick={() => void window.t2.windowControl('max')}>□</button>
            <button aria-label="Close" onClick={() => void window.t2.windowControl('close')}>×</button>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <header className="titlebar"
        onDoubleClick={(e) => {
          if ((e.target as HTMLElement).closest('button')) return
          void window.t2.windowControl('max')
        }}>
        <div className={`brand${DETACHED ? ' small' : ''}`}>
          {DETACHED
            ? <>{PANELS[DETACHED].glyph} {PANELS[DETACHED].title}<span className="brand-tail"> · TornadoC2</span></>
            : <>Tornado<span>C2</span></>}
        </div>

        {!DETACHED && (
          <nav className="profiles" role="tablist" aria-label="Workspace profile"
            onKeyDown={(e) => {
              if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return
              const ids = Object.keys(PROFILES)
              const at = ids.indexOf(profile)
              const next = ids[(at + (e.key === 'ArrowRight' ? 1 : -1) + ids.length) % ids.length]
              if (next) {
                e.preventDefault()
                applyProfile(next as keyof typeof PROFILES)
              }
            }}>
            {(Object.keys(PROFILES) as Array<keyof typeof PROFILES>).map((id) => (
              <button key={id} role="tab" aria-selected={profile === id}
                title={PROFILES[id].hint}
                onClick={() => applyProfile(id)}>
                <span aria-hidden="true">{PROFILES[id].glyph}</span>
                <span className="profile-label">{PROFILES[id].label}</span>
              </button>
            ))}
            {profile === 'custom' && (
              <span className="profile-custom" title="Modified arrangement">custom</span>
            )}
          </nav>
        )}

        <span className="grow" />

        <div className="quick" aria-label="Quick actions">
          {can('beacon.build') && (
            <IconButton label="Build agent" onClick={() => setBuildOpen(true)}>⚒</IconButton>
          )}
          <MenuButton label="Panels" glyph="▦" items={[
            { kind: 'heading', id: 'h', label: 'Open panel' },
            ...allowed.map((id) => ({
              kind: 'item' as const, id, label: PANELS[id].title,
              onSelect: () => openPanel(id)
            })),
            { kind: 'sep', id: 's1' },
            { kind: 'item', id: 'reset', label: 'Reset layout',
              onSelect: () => dockRef.current?.reset() }
          ]} />
          {can('beacon.use') && (
            <IconButton label="Jump to host" onClick={() => setJumpOpen(true)}>⇥</IconButton>
          )}
          <MenuButton label="Export" glyph="⤓" items={[
            { kind: 'item', id: 'ioc', label: 'IOCs (CSV)', onSelect: () => void exportAs('ioc') },
            { kind: 'item', id: 'stix', label: 'STIX 2.1', onSelect: () => void exportAs('stix') },
            { kind: 'sep', id: 's' },
            { kind: 'item', id: 'report', label: 'Engagement report', onSelect: () => void exportAs('report') }
          ]} />
          <IconButton label="Command palette (Ctrl+K)" onClick={() => setPalette(true)}>⌘</IconButton>
          <IconButton label="Settings" on={active === 'settings'}
            onClick={() => openPanel('settings')}>⚙</IconButton>
        </div>

        <div className="conn" aria-live="polite">
          <span className={`dot ${conn === 'ok' ? 'ok' : 'err'}`} aria-hidden="true" />
          <span className="mono conn-who" title={`${ident.name}@${ident.role}`}>
            {ident.name}<span className="muted">@{ident.role}</span>
          </span>
          {!DETACHED && (
            <IconButton label="Detach active panel"
              onClick={() => void window.t2.detach(active)}>⧉</IconButton>
          )}
          <IconButton label="Disconnect" onClick={() => void disconnect()}>⏻</IconButton>
          {platform !== 'darwin' && (
            <div className="wctl">
              <button aria-label="Minimise" onClick={() => void window.t2.windowControl('min')}>–</button>
              <button aria-label="Maximise" onClick={() => void window.t2.windowControl('max')}>□</button>
              <button aria-label="Close" onClick={() => void window.t2.windowControl('close')}>×</button>
            </div>
          )}
        </div>
      </header>

      <div className="body">
        {!DETACHED && (
          <nav className="rail" aria-label="Panel groups">
            {GROUP_IDS.map((gid) => {
              const leaves = GROUPS[gid].panels.filter((id) => canUse(PANELS[id], caps))
              if (!leaves.length) return null
              const bad = gid === 'assets'
                ? listeners.filter((l) => l.health === 'down' || l.health === 'degraded').length
                : 0
              return (
                <MenuButton key={gid} placement="right" label={GROUPS[gid].label}
                  glyph={GROUPS[gid].glyph} badge={bad}
                  on={groupOf(active) === gid}
                  items={[
                    { kind: 'heading', id: `h:${gid}`, label: GROUPS[gid].hint },
                    ...leaves.map((id) => ({
                      kind: 'item' as const, id, label: PANELS[id].title,
                      onSelect: () => openPanel(id)
                    }))
                  ]} />
              )
            })}
          </nav>
        )}

        <main className="main" id="main" tabIndex={-1}>
          {update && (
            <div className="banner update" role="status">
              {update.state === 'available' && `update ${update.version} downloading…`}
              {update.state === 'ready' && (
                <>
                  update {update.version} ready
                  <button className="btn" onClick={() => void window.t2.installUpdate()}>
                    Restart & install
                  </button>
                </>
              )}
              {update.state === 'error' && `update failed: ${update.message ?? ''}`}
            </div>
          )}
          <Dock ref={dockRef}
            renderPanel={(id) => (
              <Suspense fallback={
                <div className="pane-loading" role="status">loading pane…</div>
              }>
                {renderPanel(id)}
              </Suspense>
            )}
            single={DETACHED ?? undefined}
            storageKey={DETACHED ? `t2.dock.detach.${DETACHED}` : undefined}
            onCustom={markCustom}
            onActive={(id) => { if (id) setActive(id) }} onNotice={toast} />
        </main>
      </div>

      <footer className="status">
        <StatusPill tone={conn === 'ok' ? 'ok' : 'err'}>
          {conn === 'ok' ? 'connected' : 'bridge down'}
        </StatusPill>
        <span className="mono ellipsis status-cfg" title={cfg}>
          {cfg.split('/').pop() || 'no config'}
        </span>
        <span className="stat"><b>{live}</b> live</span>
        <span className="stat dead">{beacons.length - live} dead</span>
        {listeners.length > 0 && (
          <StatusPill tone={health.down ? 'err' : health.degraded ? 'warn' : 'idle'}
            title={`${health.ok} healthy, ${health.degraded} degraded, ${health.down} down`}>
            ◈ {health.ok}/{listeners.length}
          </StatusPill>
        )}
        <span className="grow" />
        {safe && <StatusPill tone="warn">safe mode</StatusPill>}
        <span className="stat">{ids.length || 0} selected</span>
        <button className="btn quiet" onClick={() => dockRef.current?.reset()}>
          Reset layout
        </button>
        <span className="muted status-hint">
          alt+1–4 · <KeyHint keys="⌘K" label="Command palette" />
        </span>
        <time className="mono clock" dateTime={clock.toISOString()}>
          {clock.toISOString().slice(11, 19)}Z
        </time>
      </footer>

      {palette && (
        <div className="palette" role="dialog" aria-label="Command palette">
          <input autoFocus placeholder="run a command…" value={palQ}
            onChange={(e) => setPalQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && palItems[0]) {
                remember(palItems[0].label)
                setPalette(false); setPalQ(''); void palItems[0].run()
              }
            }} />
          <ul>
            {palItems.map((c) => (
              <li key={c.id} aria-selected={palItems[0] === c}
                onClick={() => {
                  remember(c.label)
                  setPalette(false); setPalQ(''); void c.run()
                }}>
                {c.label}
              </li>
            ))}
          </ul>
          <div className="hint">Enter runs · Esc closes</div>
        </div>
      )}

      {dialog === 'task' && (
        <Dialog title={`Run on ${ids.length} beacon(s)`} onClose={() => setDialog(null)}
          footer={<>
            <button className="btn" onClick={() => setDialog(null)}>Cancel</button>
            <button className="btn primary" disabled={!taskLine.trim()} onClick={() => {
              const [verb, ...args] = taskLine.trim().split(/\s+/)
              setDialog(null)
              if (verb) void bulk('task', { verb, args })
              setTaskLine('')
            }}>Queue</button>
          </>}>
          <input className="field" autoFocus placeholder="verb args (e.g. whoami)"
            value={taskLine} onChange={(e) => setTaskLine(e.target.value)} />
          <p className="muted small">Runs on every selected beacon; each call is audited.</p>
        </Dialog>
      )}

      {dialog === 'tag' && (
        <Dialog title={`Tag ${ids.length} beacon(s)`} onClose={() => setDialog(null)}
          footer={<>
            <button className="btn" onClick={() => setDialog(null)}>Cancel</button>
            <button className="btn primary" disabled={!tag.trim()} onClick={() => {
              setDialog(null)
              void bulk('tag', { tag: tag.trim() })
              setTag('')
            }}>Apply</button>
          </>}>
          <input className="field" autoFocus placeholder="tag" value={tag}
            onChange={(e) => setTag(e.target.value)} />
        </Dialog>
      )}

      {confirmKill && (
        <Confirm title="Kill beacons" yes="Kill"
          body={`Queue self-destruct on ${ids.length} beacon(s)?`}
          onClose={() => setConfirmKill(false)}
          onYes={() => { setConfirmKill(false); void bulk('kill', {}) }} />
      )}

      {buildOpen && (
        <Suspense fallback={null}>
          <BuildDialog onClose={() => setBuildOpen(false)}
            onDone={(m) => { setBuildOpen(false); toast(m, 'ok'); openPanel('jobs') }} />
        </Suspense>
      )}

      {jumpOpen && (
        <Suspense fallback={null}>
          <Jump beacons={beacons} listeners={listeners}
            onClose={() => setJumpOpen(false)} onToast={toast} />
        </Suspense>
      )}

      <div className="toasts" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.text}</div>)}
      </div>
    </div>
  )
}
