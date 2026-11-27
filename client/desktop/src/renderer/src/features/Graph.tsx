import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation,
  forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum
} from 'd3-force'
import type { Graph } from '../../../shared/ipc'
import { usePoll } from '../hooks'
import {
  EDGE_COLORS, EDGE_LABELS, buildView, nodeSummary,
  type VizLink, type VizNode
} from '../lib/graph'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

const cssVar = (name: string): string =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim()

type SimNode = VizNode & SimulationNodeDatum
type SimLink = SimulationLinkDatum<SimNode> & VizLink

export default function GraphView(props: {
  enabled?: boolean
  selectedId?: number | null
  onSelect?: (id: number) => void
}): JSX.Element {
  const { data, error, reload } = usePoll<Graph>('graph', { mode: 'json' }, 6_000,
    props.enabled ?? true)
  const [focus, setFocus] = useState<string | null>(null)
  const [cluster, setCluster] = useState(true)
  const [hover, setHover] = useState<{ x: number; y: number; text: string } | null>(null)
  const [size, setSize] = useState({ w: 900, h: 520 })
  const wrap = useRef<HTMLDivElement>(null)
  const canvas = useRef<HTMLCanvasElement>(null)
  const mini = useRef<HTMLCanvasElement>(null)
  const view = useRef({ k: 1, x: 450, y: 260 })
  const nodes = useRef<SimNode[]>([])
  const links = useRef<SimLink[]>([])
  const selected = useRef<number | null>(null)
  const hovered = useRef<SimNode | null>(null)
  const drag = useRef<{ node?: SimNode; x: number; y: number; vx: number; vy: number } | null>(null)
  const sim = useRef<ReturnType<typeof forceSimulation<SimNode>> | null>(null)

  const viz = useMemo(
    () => buildView(data, focus, cluster), [data, focus, cluster])

  useEffect(() => {
    const el = wrap.current
    if (!el) return
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect()
      setSize({ w: Math.max(200, r.width), h: Math.max(160, r.height) })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const world = useCallback((cx: number, cy: number): { x: number; y: number } => {
    const r = canvas.current?.getBoundingClientRect()
    const v = view.current
    return {
      x: ((cx - (r?.left ?? 0)) - v.x) / v.k,
      y: ((cy - (r?.top ?? 0)) - v.y) / v.k
    }
  }, [])

  const nearest = useCallback((x: number, y: number): SimNode | null => {
    let best: SimNode | null = null
    let dist = 18 / view.current.k
    for (const n of nodes.current) {
      const d = Math.hypot((n.x ?? 0) - x, (n.y ?? 0) - y)
      if (d < Math.max(dist, n.radius + 4)) { best = n; dist = d }
    }
    return best
  }, [])

  const draw = useCallback(() => {
    const cv = canvas.current
    const ctx = cv?.getContext('2d')
    if (!cv || !ctx) return
    const dpr = Math.min(2, window.devicePixelRatio || 1)
    const { w, h } = size
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr)
      cv.height = Math.round(h * dpr)
    }
    const colours = {
      cyan: cssVar('--cyan'), green: cssVar('--green'),
      violet: cssVar('--violet'), amber: cssVar('--amber'),
      red: cssVar('--red'), 'text-3': cssVar('--text-3'),
      'text-2': cssVar('--text-2'), text: cssVar('--text'), bg: cssVar('--bg'),
      'bg-sunken': cssVar('--bg-sunken')
    }
    const col = (value: string): string =>
      value.startsWith('var(')
        ? colours[value.slice(4, -1) as keyof typeof colours] ?? ''
        : value
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, w, h)
    ctx.fillStyle = colours['bg-sunken'] || 'rgb(2 4 6)'
    ctx.fillRect(0, 0, w, h)

    const v = view.current
    ctx.save()
    ctx.translate(v.x, v.y)
    ctx.scale(v.k, v.k)
    ctx.lineWidth = 1 / v.k
    for (const l of links.current) {
      const a = l.source as SimNode
      const b = l.target as SimNode
      ctx.strokeStyle = col(EDGE_COLORS[l.kind])
      ctx.globalAlpha = l.kind === 'cluster' ? 0.18 : 0.38
      ctx.beginPath()
      ctx.moveTo(a.x ?? 0, a.y ?? 0)
      ctx.lineTo(b.x ?? 0, b.y ?? 0)
      ctx.stroke()
    }
    ctx.globalAlpha = 1

    for (const n of nodes.current) {
      const isSel = n.kind === 'node' && Number(n.id) === selected.current
      if (isSel || n === hovered.current) {
        ctx.strokeStyle = colours.cyan
        ctx.lineWidth = 2 / v.k
        ctx.beginPath()
        ctx.arc(n.x ?? 0, n.y ?? 0, n.radius + 3, 0, Math.PI * 2)
        ctx.stroke()
      }
      ctx.fillStyle = col(n.color)
      ctx.beginPath()
      ctx.arc(n.x ?? 0, n.y ?? 0, n.radius, 0, Math.PI * 2)
      ctx.fill()
      if (n.elevated) {
        ctx.strokeStyle = colours.text
        ctx.lineWidth = 1.2 / v.k
        ctx.stroke()
      }
      if (n.kind === 'cluster') {
        ctx.fillStyle = colours.bg
        ctx.font = `600 ${Math.max(8, n.radius / 1.6)}px ui-monospace`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText(String(n.count), n.x ?? 0, (n.y ?? 0) + 0.5)
      }
      if (v.k > 0.75 || isSel || n === hovered.current) {
        ctx.fillStyle = colours['text-2']
        ctx.font = `${10 / Math.max(0.8, v.k)}px ui-monospace`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillText(n.label.slice(0, 24), n.x ?? 0, (n.y ?? 0) + n.radius + 3)
      }
    }
    ctx.restore()

    const mc = mini.current
    const mctx = mc?.getContext('2d')
    if (mc && mctx && nodes.current.length) {
      mctx.clearRect(0, 0, mc.width, mc.height)
      mctx.fillStyle = colours['bg-sunken'] || 'rgb(2 4 6)'
      mctx.fillRect(0, 0, mc.width, mc.height)
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
      for (const n of nodes.current) {
        minX = Math.min(minX, n.x ?? 0); maxX = Math.max(maxX, n.x ?? 0)
        minY = Math.min(minY, n.y ?? 0); maxY = Math.max(maxY, n.y ?? 0)
      }
      const pad = 12
      const sx = (mc.width - pad * 2) / Math.max(1, maxX - minX)
      const sy = (mc.height - pad * 2) / Math.max(1, maxY - minY)
      const s = Math.min(sx, sy)
      for (const n of nodes.current) {
        mctx.fillStyle = colours['text-3']
        mctx.fillRect(
          pad + ((n.x ?? 0) - minX) * s,
          pad + ((n.y ?? 0) - minY) * s, 1.6, 1.6)
      }
      mctx.strokeStyle = colours.cyan
      mctx.strokeRect(
        pad + (-v.x / v.k - minX) * s,
        pad + (-v.y / v.k - minY) * s,
        (size.w / v.k) * s, (size.h / v.k) * s)
    }
  }, [size])

  useEffect(() => {
    sim.current?.stop()
    if (!viz.nodes.length) { nodes.current = []; links.current = []; draw(); return }
    const ns: SimNode[] = viz.nodes.map((n, i) => ({
      ...n,
      x: Math.cos((i / viz.nodes.length) * Math.PI * 2) * 180,
      y: Math.sin((i / viz.nodes.length) * Math.PI * 2) * 180
    }))
    const ls: SimLink[] = viz.links.map((l) => ({ ...l }))
    nodes.current = ns
    links.current = ls
    const s = forceSimulation(ns)
      .force('link', forceLink<SimNode, SimLink>(ls).id((d) => d.id)
        .distance((l) => (l.kind === 'cluster' ? 90 : 55))
        .strength(0.25))
      .force('charge', forceManyBody().strength((d) =>
        (d as SimNode).kind === 'cluster' ? -220 : -70))
      .force('collide', forceCollide<SimNode>().radius((d) => d.radius + 4))
      .force('center', forceCenter(0, 0))
      .force('x', forceX(0).strength(0.02))
      .force('y', forceY(0).strength(0.02))
      .alpha(1)
      .on('tick', draw)
    sim.current = s
    return () => { s.stop() }
  }, [viz, draw])

  useEffect(() => { draw() }, [draw, size])

  useEffect(() => {
    selected.current = props.selectedId ?? null
    draw()
  }, [props.selectedId, draw])


  const onPointerDown = (e: React.PointerEvent<HTMLCanvasElement>): void => {
    const p = world(e.clientX, e.clientY)
    const n = nearest(p.x, p.y)
    ;(e.target as HTMLElement).setPointerCapture?.(e.pointerId)
    drag.current = {
      node: n ?? undefined, x: e.clientX, y: e.clientY,
      vx: view.current.x, vy: view.current.y
    }
    if (n) {
      n.fx = p.x; n.fy = p.y
      sim.current?.alphaTarget(0.2).restart()
    }
  }

  const onPointerMove = (e: React.PointerEvent<HTMLCanvasElement>): void => {
    const d = drag.current
    if (d) {
      if (d.node) {
        const p = world(e.clientX, e.clientY)
        d.node.fx = p.x; d.node.fy = p.y
      } else {
        view.current.x = d.vx + e.clientX - d.x
        view.current.y = d.vy + e.clientY - d.y
      }
      draw()
      return
    }
    const p = world(e.clientX, e.clientY)
    const n = nearest(p.x, p.y)
    hovered.current = n
    const r = canvas.current?.getBoundingClientRect()
    setHover(n && r
      ? { x: e.clientX - r.left + 10, y: e.clientY - r.top + 10, text: nodeSummary(n) }
      : null)
    draw()
  }

  const onPointerUp = (): void => {
    const n = drag.current?.node
    if (n) { n.fx = null; n.fy = null }
    drag.current = null
    sim.current?.alphaTarget(0)
  }

  const click = (e: React.PointerEvent<HTMLCanvasElement>): void => {
    const p = world(e.clientX, e.clientY)
    const n = nearest(p.x, p.y)
    if (n?.kind === 'node') props.onSelect?.(Number(n.id))
    if (!n) { hovered.current = null; setHover(null) }
    draw()
  }

  const zoomAt = (factor: number, cx: number, cy: number): void => {
    const r = canvas.current?.getBoundingClientRect()
    const v = view.current
    const nx = cx - (r?.left ?? 0)
    const ny = cy - (r?.top ?? 0)
    const k = Math.min(4, Math.max(0.2, v.k * factor))
    v.x = nx - ((nx - v.x) / v.k) * k
    v.y = ny - ((ny - v.y) / v.k) * k
    v.k = k
    draw()
  }

  const total = viz.total
  return (
    <div className="view graph">
      <Toolbar label="Graph">
        <ToolbarTitle>Graph</ToolbarTitle>
        <span className="pill">{total}</span>
        {focus && <button className="btn tiny" onClick={() => setFocus(null)}>
          All clusters
        </button>}
        <ToolbarSpacer />
        <span className="muted small graph-focus">
          {viz.clustered ? 'clustered' : `${viz.nodes.length} drawn`}
        </span>
        <IconButton label="Toggle clustering" on={cluster}
          onClick={() => { setCluster((c) => !c); setFocus(null) }}>⊞</IconButton>
        <IconButton label="Reset view" onClick={() => {
          view.current = { k: 1, x: size.w / 2, y: size.h / 2 }
          draw()
        }}>◎</IconButton>
        <IconButton label="Refresh graph" onClick={reload}>↻</IconButton>
      </Toolbar>

      {error && <div className="banner err" role="alert">{error}</div>}
      {total > 2000 && (
        <div className="banner">
          {total.toLocaleString()} sessions — clustered view; double-click a
          cluster to expand it.
        </div>
      )}

      <div className="graph-stage" ref={wrap}
        style={{ position: 'relative', flex: 1, minHeight: 0 }}>
        <canvas ref={canvas} className="graph-canvas"
          style={{ width: '100%', height: '100%', display: 'block' }}
          role="img"
          aria-label={`Session graph, ${viz.nodes.length} drawn of ${total}`}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
          onClick={click}
          onDoubleClick={(e) => {
            const p = world(e.clientX, e.clientY)
            const n = nearest(p.x, p.y)
            if (n?.kind === 'cluster' && n.clusterKey) {
              setFocus(n.clusterKey)
              view.current = { k: 1, x: size.w / 2, y: size.h / 2 }
            } else if (n?.kind === 'node') props.onSelect?.(Number(n.id))
          }}
          onWheel={(e) => {
            e.preventDefault()
            zoomAt(e.deltaY < 0 ? 1.12 : 0.89, e.clientX, e.clientY)
          }} />
        {!viz.nodes.length && (
          <EmptyState glyph="⌁" title="No sessions"
            hint="the graph fills as beacons check in" />
        )}
        {hover && (
          <div className="graph-tip mono" style={{ left: hover.x, top: hover.y }}>
            {hover.text}
          </div>
        )}
        <div className="graph-legend">
          {EDGE_LABELS.map(([kind, label]) => (
            <span key={kind} className={`edge-key ${kind}`}>
              <i style={{ background: EDGE_COLORS[kind] }} />{label}
            </span>
          ))}
        </div>
        <canvas ref={mini} className="graph-mini" width={148} height={92}
          aria-hidden="true"
          onPointerDown={(e) => {
            const r = mini.current?.getBoundingClientRect()
            if (!r) return
            const n = nodes.current
            if (!n.length) return
            const minX = Math.min(...n.map((x) => x.x ?? 0))
            const maxX = Math.max(...n.map((x) => x.x ?? 0))
            const minY = Math.min(...n.map((x) => x.y ?? 0))
            const maxY = Math.max(...n.map((x) => x.y ?? 0))
            const s = Math.min((r.width - 24) / Math.max(1, maxX - minX),
              (r.height - 24) / Math.max(1, maxY - minY))
            const wx = (e.clientX - r.left - 12) / s + minX
            const wy = (e.clientY - r.top - 12) / s + minY
            view.current.x = size.w / 2 - wx * view.current.k
            view.current.y = size.h / 2 - wy * view.current.k
            draw()
          }} />
      </div>
    </div>
  )
}
