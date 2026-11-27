// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import axe from 'axe-core'
import type { Graph } from '../src/shared/ipc'
import GraphView from '../src/renderer/src/features/Graph'

let payload: Graph = { nodes: [], edges: [] }

vi.mock('../src/renderer/src/hooks', () => ({
  usePoll: () => ({ data: payload, error: '', reload: () => undefined })
}))

const ctx = {
  setTransform: vi.fn(), clearRect: vi.fn(), fillRect: vi.fn(),
  save: vi.fn(), restore: vi.fn(), translate: vi.fn(), scale: vi.fn(),
  beginPath: vi.fn(), moveTo: vi.fn(), lineTo: vi.fn(), stroke: vi.fn(),
  arc: vi.fn(), fill: vi.fn(), fillText: vi.fn(), strokeRect: vi.fn(),
  globalAlpha: 1, lineWidth: 1, font: '', textAlign: '', textBaseline: '',
  fillStyle: '', strokeStyle: ''
}

beforeAll(() => {
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext')
    .mockReturnValue(ctx as unknown as CanvasRenderingContext2D)
})

afterEach(cleanup)

const nodes = (n: number): Graph => ({
  nodes: Array.from({ length: n }, (_, i) => ({
    id: i + 1, hostname: `h${i}`, user: 'alice', privilege: 'user',
    alive: true, subnet: '10.0.0.0/24'
  })),
  edges: [{ from: 1, to: 2, shared: ['subnet=10.0.0.0/24'] }]
})

describe('graph', () => {
  it('shows the empty state', () => {
    payload = { nodes: [], edges: [] }
    render(<GraphView />)
    expect(screen.getByText('No sessions')).toBeTruthy()
    expect(screen.getByRole('img', { name: /Session graph, 0 drawn of 0/ })).toBeTruthy()
  })

  it('draws individual nodes and the legend', async () => {
    payload = nodes(10)
    render(<GraphView />)
    await waitFor(() => expect(
      screen.getByRole('img', { name: /10 drawn of 10/ })).toBeTruthy())
    expect(screen.getByText('shared subnet')).toBeTruthy()
    expect(screen.getByText('relay parent')).toBeTruthy()
    expect(screen.getByText('10 drawn')).toBeTruthy()
  })

  it('clusters beyond 2000 and warns', async () => {
    payload = nodes(2100)
    render(<GraphView />)
    await waitFor(() => expect(
      screen.getByRole('img', { name: /1 drawn of 2100/ })).toBeTruthy())
    expect(screen.getByText(/2,100 sessions/)).toBeTruthy()
    expect(screen.getByText('clustered')).toBeTruthy()
  })

  it('has no axe violations', async () => {
    payload = nodes(12)
    const { container } = render(<GraphView />)
    await waitFor(() => expect(screen.getByText('12 drawn')).toBeTruthy())
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})
