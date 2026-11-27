import { useMemo, useRef, useState, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import EmptyState from './EmptyState'
import IconButton from './IconButton'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from './Toolbar'

export type Column<T> = {
  key: string
  label: string
  width: string
  sort?: (a: T, b: T) => number
  render: (row: T) => ReactNode
  mono?: boolean
}

export type GridAction<T> = {
  id: string
  label: string
  onSelect: (row: T) => void
  disabled?: (row: T) => boolean
}

export default function DataGrid<T>(props: {
  label: string
  rows: T[]
  columns: Array<Column<T>>
  getKey: (row: T) => string | number
  actions?: Array<GridAction<T>>
  rowText: (row: T) => string
  onRefresh: () => void
  busy?: boolean
  error?: string
  raw?: string
  rawMode?: boolean
  onRaw?: () => void
  auto?: boolean
  onAuto?: () => void
  emptyTitle: string
  emptyHint: string
  onActivate?: (row: T) => void
  rowClass?: (row: T) => string
  hint?: string
  headerAction?: ReactNode
}): JSX.Element {
  const [filter, setFilter] = useState('')
  const [sortKey, setSortKey] = useState<string>('')
  const [dir, setDir] = useState<'asc' | 'desc'>('asc')
  const scroll = useRef<HTMLDivElement>(null)
  const needle = filter.trim().toLowerCase()

  const rows = useMemo(() => {
    const col = props.columns.find((c) => c.key === sortKey)
    const base = needle
      ? props.rows.filter((r) => props.rowText(r).toLowerCase().includes(needle))
      : props.rows.slice()
    if (col?.sort) {
      base.sort((a, b) => col.sort!(a, b) * (dir === 'asc' ? 1 : -1))
    }
    return base
  }, [props.rows, props.columns, props.rowText, needle, sortKey, dir])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroll.current,
    estimateSize: () => 25,
    overscan: 16
  })

  const grid = useMemo(
    () => [...props.columns.map((c) => c.width), props.actions?.length ? '118px' : '']
      .filter(Boolean).join(' '),
    [props.columns, props.actions?.length])

  const sort = (key: string): void => {
    if (sortKey === key) setDir(dir === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setDir('asc') }
    virt.scrollToOffset(0)
  }

  return (
    <div className="view datagrid">
      <Toolbar label={props.label}>
        <ToolbarTitle>{props.label}</ToolbarTitle>
        <span className="pill">{rows.length}</span>
        {props.headerAction}
        <ToolbarSpacer />
        <input className="ui-input dock-filter" value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter" aria-label={`Filter ${props.label}`} />
        <IconButton label="Refresh" disabled={props.busy} onClick={props.onRefresh}>↻</IconButton>
        <IconButton label={props.auto ? 'Stop auto refresh' : 'Auto refresh every 10s'}
          on={props.auto} onClick={props.onAuto}>⟳</IconButton>
        <IconButton label={props.rawMode ? 'Show grid' : 'Show raw output'}
          on={props.rawMode} onClick={props.onRaw}>◫</IconButton>
      </Toolbar>

      {props.error && <div className="banner err" role="alert">{props.error}</div>}
      {props.hint && <div className="foot-note">{props.hint}</div>}

      {props.rawMode ? (
        <pre className="dg-raw" tabIndex={0}>{props.raw || 'no output yet'}</pre>
      ) : (
        <div className="table-wrap dg-wrap" ref={scroll} role="table"
          aria-label={props.label} aria-rowcount={rows.length + 1}>
          <div className="row head sticky dg-row" role="row"
            style={{ gridTemplateColumns: grid }}>
            {props.columns.map((c) => (
              <div key={c.key} role="columnheader"
                aria-sort={sortKey === c.key
                  ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
                {c.sort
                  ? <button className="sort" onClick={() => sort(c.key)}>{c.label}</button>
                  : c.label}
              </div>
            ))}
            {props.actions?.length ? <span role="columnheader">ACTIONS</span> : null}
          </div>

          {rows.length === 0 && (
            <div role="rowgroup">
              <div role="row"><div role="cell">
                <EmptyState glyph="▤"
                  title={props.busy ? 'Collecting…' : props.emptyTitle}
                  hint={props.emptyHint} />
              </div></div>
            </div>
          )}

          <div role="rowgroup" style={{ height: virt.getTotalSize(), position: 'relative' }}>
            {virt.getVirtualItems().map((v) => {
              const row = rows[v.index]
              if (!row) return null
              return (
                <div key={props.getKey(row)} role="row"
                  tabIndex={0}
                  className={`row dg-row ${props.rowClass?.(row) ?? ''}`}
                  style={{
                    gridTemplateColumns: grid,
                    position: 'absolute', left: 0, right: 0,
                    transform: `translateY(${v.start}px)`
                  }}
                  onDoubleClick={() => props.onActivate?.(row)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') props.onActivate?.(row)
                  }}>
                  {props.columns.map((c) => (
                    <span key={c.key} role="cell" className={c.mono ? 'mono ellipsis' : 'ellipsis'}>
                      {c.render(row)}
                    </span>
                  ))}
                  {props.actions?.length ? (
                    <span role="cell" className="dg-actions">
                      {props.actions.map((a) => (
                        <button key={a.id} className="btn tiny"
                          disabled={a.disabled?.(row) || props.busy}
                          onClick={() => a.onSelect(row)}>{a.label}</button>
                      ))}
                    </span>
                  ) : null}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
