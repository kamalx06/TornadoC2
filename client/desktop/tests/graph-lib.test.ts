import { describe, expect, it } from 'vitest'
import type { Graph } from '../src/shared/ipc'
import { buildView, classify, clusterKey, nodeSummary } from '../src/renderer/src/lib/graph'

const n = (id: number, over: Partial<Graph['nodes'][number]> = {}) =>
  ({ id, hostname: `h${id}`, privilege: 'user', alive: true, ...over })
const g = (count: number): Graph => ({
  nodes: Array.from({ length: count }, (_, i) => n(i + 1)),
  edges: [{ from: 1, to: 2, shared: ['subnet=10.0.0.0/24'] }]
})

describe('edge classification', () => {
  it('prioritises relay then process then identity', () => {
    expect(classify(['user=a', 'relay-parent'])).toBe('relay')
    expect(classify(['process-parent', 'user=a'])).toBe('process')
    expect(classify(['user=a', 'subnet=x'])).toBe('identity')
    expect(classify(['domain=x'])).toBe('domain')
    expect(classify(['subnet=x'])).toBe('subnet')
    expect(classify([])).toBe('identity')
  })
})

describe('graph view', () => {
  it('renders individual nodes under the threshold', () => {
    const v = buildView(g(10), null, true)
    expect(v.clustered).toBe(false)
    expect(v.nodes).toHaveLength(10)
    expect(v.links[0]).toMatchObject({ kind: 'subnet', count: 1 })
  })

  it('clusters large graphs and aggregates links', () => {
    const data: Graph = {
      nodes: [n(1, { subnet: 'a' }), n(2, { subnet: 'a' }), n(3, { subnet: 'b' })],
      edges: [
        { from: 1, to: 2, shared: ['user=x'] },
        { from: 2, to: 3, shared: ['domain=d'] }
      ]
    }
    const v = buildView(data, null, true, 2)
    expect(v.clustered).toBe(true)
    expect(v.nodes.map((x) => x.kind)).toEqual(['cluster', 'cluster'])
    expect(v.nodes[0]?.count).toBe(2)
    expect(v.links).toHaveLength(1)
    expect(v.links[0]?.kind).toBe('cluster')
  })

  it('expands one cluster when focused', () => {
    const data: Graph = {
      nodes: [n(1, { subnet: 'a' }), n(2, { subnet: 'a' }), n(3, { subnet: 'b' })],
      edges: [{ from: 1, to: 2, shared: ['user=x'] }]
    }
    const v = buildView(data, clusterKey(data.nodes[0]!), true)
    expect(v.clustered).toBe(false)
    expect(v.nodes).toHaveLength(2)
    expect(v.links[0]?.kind).toBe('identity')
  })

  it('caps individual rendering and handles empty input', () => {
   expect(buildView(g(3000), null, false).nodes.length).toBe(2500)
    expect(buildView(null, null, true).nodes).toEqual([])
  })

  it('summarises hover text', () => {
    expect(nodeSummary({
      id: '1', label: 'h', kind: 'node', radius: 5, color: 'x', count: 1,
      host: 'h1', user: 'alice', privilege: 'system', elevated: true
    })).toContain('alice')
  })
})
