// @vitest-environment jsdom
import type { ComponentProps } from 'react'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import DataGrid, { type Column } from '../src/renderer/src/ui/DataGrid'

type Row = { id: number; name: string; path: string; pid: number }

const columns: Array<Column<Row>> = [
  { key: 'name', label: 'Name', width: '1fr', group: 'Identity',
    render: (r) => r.name },
  { key: 'path', label: 'Path', width: '2fr', group: 'Identity',
    render: (r) => r.path },
  { key: 'pid', label: 'PID', width: '80px', group: 'Process',
    render: (r) => String(r.pid) }
]

beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
    configurable: true, get: () => 300
  })
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 800, height: 300, top: 0, left: 0, bottom: 300, right: 800,
    x: 0, y: 0, toJSON: () => ({})
  } as DOMRect)
})

afterEach(cleanup)

function grid(props: Partial<ComponentProps<typeof DataGrid<Row>>> = {}) {
  return <DataGrid label="Rows" rows={[{ id: 1, name: 'a', path: '/a', pid: 10 }]}
    columns={columns} getKey={(r) => r.id} rowText={(r) => r.name}
    onRefresh={() => undefined} emptyTitle="empty" emptyHint="nothing"
    {...props} />
}

describe('data grid groups', () => {
  it('renders group headers and can hide a group', async () => {
    render(grid())
    expect(screen.getAllByRole('columnheader')[0]?.textContent).toBe('Identity')
    fireEvent.click(screen.getByRole('button', { name: 'Columns' }))
    fireEvent.click(await screen.findByRole('menuitemcheckbox', { name: /Process/ }))
    expect(screen.queryByRole('columnheader', { name: 'PID' })).toBeNull()
  })
})

describe('data grid tree', () => {
  it('renders depth and a twisty and toggles', () => {
    const toggle = vi.fn()
    render(<DataGrid label="Tree" rows={[
      { id: 1, name: 'parent', path: '/', pid: 1 },
      { id: 2, name: 'child', path: '/x', pid: 2 }
    ]} columns={columns} getKey={(r) => r.id} rowText={(r) => r.name}
      onRefresh={() => undefined} emptyTitle="empty" emptyHint="nothing"
      tree={{
        depth: (r) => r.id === 2 ? 1 : 0,
        hasChildren: (r) => r.id === 1,
        expanded: () => true,
        onToggle: toggle
      }} />)
    expect(screen.getByRole('row', { name: /child/ }).getAttribute('aria-level'))
      .toBe('2')
    fireEvent.click(screen.getByRole('button', { name: 'Collapse' }))
    expect(toggle).toHaveBeenCalled()
  })
})

describe('data grid states', () => {
  it('shows an error preset with retry', () => {
    const retry = vi.fn()
    render(grid({ rows: [], error: 'offline', onRefresh: retry }))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalled()
  })

  it('shows a filter-specific empty state', () => {
    render(grid({ rows: [] }))
    fireEvent.change(screen.getByLabelText('Filter Rows'), { target: { value: 'zzz' } })
    expect(screen.getByText(/zzz/)).toBeTruthy()
  })
})
