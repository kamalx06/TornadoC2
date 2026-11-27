import { useMemo, useRef, useState, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import IconButton from './IconButton'
import MenuButton from './MenuButton'
import { EmptyPreset, ErrorPreset, NoResultsPreset } from './StatePresets'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from './Toolbar'

export type Column<T> = {
  key: string
  label: string
  width: string
  group?: string
  defaultHidden?: boolean
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

export type TreeSpec<T> = {
  depth: (row: T) => number
  hasChildren: (row: T) => boolean
  expanded: (row: T) => boolean
  onToggle: (row: T) => void
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
  tree?: TreeSpec<T>
}): JSX.Element {
  const [filter, setFilter] = useState('')
  const [sortKey, setSortKey] = useState<string>('')
  const [dir, setDir] = useState<'asc' | 'desc'>('asc')
  const [hidden, setHidden] = useState<Set<string>>(() => new Set(
    props.columns.filter((c) => c.defaultHidden)
      .map((c) => c.group ?? c.key)))
  const scroll = useRef<HTMLDivElement>(null)
  const needle = filter.trim().toLowerCase()

  const groups = useMemo(() => {
    const out: Array<{ id: string; label: string }> = []
    const seen = new Set<string>()
    for (const col of props.columns) {
      if (!col.group || seen.has(col.group)) continue
      seen.add(col.group)
      out.push({ id: col.group, label: col.group })
    }
    return out
  }, [props.columns])

  const columns = useMemo(
    () => props.columns.filter((c) => !hidden.has(c.group ?? c.key)),
    [props.columns, hidden])

  const rows = useMemo(() => {
    const col = columns.find((c) => c.key === sortKey)
    const base = needle
      ? props.rows.filter((r) => props.rowText(r).toLowerCase().includes(needle))
      : props.rows.slice()
    if (col?.sort) {
      base.sort((a, b) => col.sort!(a, b) * (dir === 'asc' ? 1 : -1))
    }
    return base
  }, [props.rows, columns, props.rowText, needle, sortKey, dir])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroll.current,
    estimateSize: () => 25,
    overscan: 16
  })

  const grid = useMemo(
    () => [...columns.map((c) => c.width), props.actions?.length ? '118px' : '']
      .filter(Boolean).join(' '),
    [columns, props.actions?.length])

  // Contiguous group spans for the header row.
  const spans = useMemo(() => {
    const out: Array<{ key: string; label: string; span: number }> = []
    for (const col of columns) {
      const label = col.group ?? ''
      const last = out.at(-1)
      if (last && last.label === label) last.span += 1
      else out.push({ key: `${col.key}:${out.length}`, label, span: 1 })
    }
    return out
  }, [columns])

  const sort = (key: string): void => {
    if (sortKey === key) setDir(dir === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setDir('asc') }
    virt.scrollToOffset(0)
  }

  const toggleGroup = (id: string): void => {
    setHidden((old) => {
      const next = new Set(old)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const showGroups = columns.some((c) => c.group) && spans.some((s) => s.label)

  return (
    <div className="view datagrid">
      <Toolbar label={props.label}>
        <ToolbarTitle>{props.label}</ToolbarTitle>
        <span className="pill">{rows.length}</span>
        {props.headerAction}
        <ToolbarSpacer />
        {groups.length > 0 && (
          <MenuButton label="Columns" glyph="▥" items={[
            { kind: 'heading', id: 'g', label: 'Column groups' },
            ...groups.map((g) => ({
              kind: 'item' as const, id: g.id, label: g.label,
              checked: !hidden.has(g.id),
              onSelect: () => toggleGroup(g.id)
            }))
          ]} />
        )}
        <input className="ui-input dock-filter" value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter" aria-label={`Filter ${props.label}`} />
        <IconButton label="Refresh" disabled={props.busy} onClick={props.onRefresh}>↻</IconButton>
        <IconButton label={props.auto ? 'Stop auto refresh' : 'Auto refresh every 10s'}
          on={props.auto} onClick={props.onAuto}>⟳</IconButton>
        <IconButton label={props.rawMode ? 'Show grid' : 'Show raw output'}
          on={props.rawMode} onClick={props.onRaw}>◫</IconButton>
      </Toolbar>

      {props.error && rows.length > 0 && (
        <div className="banner err" role="alert">{props.error}</div>
      )}
      {props.hint && <div className="foot-note">{props.hint}</div>}

      {props.rawMode ? (
        <pre className="dg-raw" tabIndex={0}>{props.raw || 'no output yet'}</pre>
      ) : (
        <div className="table-wrap dg-wrap" ref={scroll} role="table"
          aria-label={props.label} aria-rowcount={rows.length + 1}
          aria-colcount={columns.length + (props.actions?.length ? 1 : 0)}>
          {showGroups && (
            <div className="row head dg-group-row" role="row"
              style={{ gridTemplateColumns: grid }}>
              {spans.map((span) => (
                <span key={span.key} role="columnheader"
                  aria-colspan={span.span}
                  style={{ gridColumn: `span ${span.span}` }}
                  className="dg-group">
                  {span.label || '—'}
                </span>
              ))}
              {props.actions?.length ? <span role="columnheader" /> : null}
            </div>
          )}
          <div className="row head sticky dg-row" role="row"
            style={{ gridTemplateColumns: grid }}>
            {columns.map((c) => (
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
                {props.error
                  ? <ErrorPreset detail={props.error} onRetry={props.onRefresh} />
                  : needle
                    ? <NoResultsPreset filter={filter} />
                    : <EmptyPreset title={props.busy ? 'Collecting…' : props.emptyTitle}
                      hint={props.emptyHint} />}
              </div></div>
            </div>
          )}

          <div role="rowgroup" style={{ height: virt.getTotalSize(), position: 'relative' }}>
            {virt.getVirtualItems().map((v) => {
              const row = rows[v.index]
              if (!row) return null
              const depth = props.tree?.depth(row) ?? 0
              return (
                <div key={props.getKey(row)} role="row"
                  tabIndex={0}
                  aria-level={props.tree ? depth + 1 : undefined}
                  aria-expanded={props.tree?.hasChildren(row)
                    ? props.tree.expanded(row) : undefined}
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
                  {columns.map((c, i) => (
                    <span key={c.key} role="cell" className={c.mono ? 'mono ellipsis' : 'ellipsis'}>
                      {i === 0 && props.tree && (
                        <>
                          <span className="tree-indent"
                            style={{ width: `${depth * 14}px` }} />
                          {props.tree.hasChildren(row) ? (
                            <button type="button" className="tree-twisty"
                              aria-label={props.tree.expanded(row)
                                ? 'Collapse' : 'Expand'}
                              onClick={() => props.tree!.onToggle(row)}>
                              {props.tree.expanded(row) ? '▾' : '▸'}
                            </button>
                          ) : <span className="tree-twisty" />}
                        </>
                      )}
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
