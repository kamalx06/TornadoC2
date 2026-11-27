import type { Graph } from '../../../shared/ipc'

export type EdgeKind = 'relay' | 'process' | 'identity' | 'domain' | 'subnet' | 'cluster'

export const EDGE_COLORS: Record<EdgeKind, string> = {
  relay: 'var(--cyan)',
  process: 'var(--green)',
  identity: 'var(--violet)',
  domain: 'var(--amber)',
  subnet: 'var(--red)',
  cluster: 'var(--text-3)'
}

export const EDGE_LABELS: Array<[EdgeKind, string]> = [
  ['relay', 'relay parent'],
  ['process', 'process parent'],
  ['identity', 'shared identity'],
  ['domain', 'shared domain'],
  ['subnet', 'shared subnet']
]

export type VizNode = {
  id: string
  label: string
  kind: 'node' | 'cluster'
  radius: number
  color: string
  count: number
  clusterKey?: string
  privilege?: string
  elevated?: boolean
  alive?: boolean
  user?: string
  host?: string
  subnet?: string
  domain?: string
  ports?: string[]
}

export type VizLink = { source: string; target: string; kind: EdgeKind; count: number }

export type Viz = { nodes: VizNode[]; links: VizLink[]; total: number; clustered: boolean }

const MAX_NODES = 2500
const MAX_LINKS = 6000

export function classify(shared: string[] | undefined): EdgeKind {
  const s = shared ?? []
  if (s.includes('relay-parent')) return 'relay'
  if (s.includes('process-parent')) return 'process'
  if (s.some((x) => x.startsWith('user='))) return 'identity'
  if (s.some((x) => x.startsWith('domain='))) return 'domain'
  if (s.some((x) => x.startsWith('subnet='))) return 'subnet'
  return 'identity'
}

export function clusterKey(n: Graph['nodes'][number]): string {
  if (n.subnet) return `subnet ${n.subnet}`
  if (n.domain) return `domain ${n.domain}`
  return `${(n.privilege ?? 'user').toLowerCase()} sessions`
}

function color(n: Graph['nodes'][number]): string {
  if (!n.alive) return 'var(--text-3)'
  return `var(--${(n.privilege ?? 'user').toLowerCase() === 'system'
    ? 'red' : (n.privilege ?? '').toLowerCase() === 'root'
      ? 'amber' : n.elevated ? 'violet' : 'cyan'})`
}

function nodeViz(n: Graph['nodes'][number]): VizNode {
  return {
    id: String(n.id), label: n.hostname ?? n.user ?? `#${n.id}`,
    kind: 'node', radius: n.elevated ? 8 : 5.5, color: color(n), count: 1,
    privilege: n.privilege, elevated: n.elevated, alive: n.alive,
    user: n.user, host: n.hostname, subnet: n.subnet, domain: n.domain,
    ports: n.ports
  }
}

export function buildView(
  data: Graph | null,
  focus: string | null,
  allowCluster: boolean,
  threshold = 500
): Viz {
  const all = data?.nodes ?? []
  if (!all.length) return { nodes: [], links: [], total: 0, clustered: false }
  const clustered = allowCluster && all.length > threshold && !focus
  const visible = new Map<string, VizNode>()
  const clusterOf = new Map<string, string>()

  if (clustered) {
    for (const n of all) {
      const key = clusterKey(n)
      clusterOf.set(String(n.id), key)
      const id = `c:${key}`
      const existing = visible.get(id)
      if (existing) {
        existing.count++
        existing.radius = Math.min(24, 9 + Math.sqrt(existing.count) * 1.6)
      } else {
        visible.set(id, {
          id, label: key, kind: 'cluster', radius: 10, color: 'var(--text-2)',
          count: 1, clusterKey: key
        })
      }
    }
  } else {
    const subset = focus
      ? all.filter((n) => clusterKey(n) === focus)
      : all.slice(0, MAX_NODES)
    for (const n of subset) visible.set(String(n.id), nodeViz(n))
  }

  const links: VizLink[] = []
  const seen = new Map<string, VizLink>()
  for (const e of data?.edges ?? []) {
    let from = String(e.from)
    let to = String(e.to)
    if (clustered) {
      from = `c:${clusterOf.get(from) ?? ''}`
      to = `c:${clusterOf.get(to) ?? ''}`
    }
    if (!visible.has(from) || !visible.has(to) || from === to) continue
    const id = `${from}|${to}`
    const existing = seen.get(id)
    if (existing) { existing.count++; continue }
    const link: VizLink = {
      source: from, target: to,
      kind: clustered ? 'cluster' : classify(e.shared), count: 1
    }
    seen.set(id, link)
    if (links.length < MAX_LINKS) links.push(link)
  }
  return { nodes: [...visible.values()], links, total: all.length, clustered }
}

export function nodeSummary(n: VizNode): string {
  if (n.kind === 'cluster') return `${n.count} session(s) · ${n.label}`
  return [
    n.host, n.user && `@${n.user}`, `· ${n.privilege ?? 'user'}`,
    n.elevated && 'elevated', n.ports?.length && `ports ${n.ports.join(',')}`
  ].filter(Boolean).join(' ')
}
