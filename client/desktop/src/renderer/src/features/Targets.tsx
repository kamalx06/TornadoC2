import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { Beacon } from '../../../shared/ipc'
import {
  nextIndex, rangeSelection, severity, severityLabel, sortRows,
  type SortDir, type SortKey
} from '../lib/targets'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import { Toolbar, ToolbarGroup, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

export default function Targets(props: {
  rows: Beacon[]
  total: number
  query: string
  onQuery: (q: string) => void
  onRefresh: () => void
  sel: Set<number>
  primary: number | null
  density: 'cozy' | 'compact' | 'dense'
  busy?: boolean
  onSelect: (ids: number[], primary: number | null) => void
  onAlias: (id: number, alias: string) => Promise<void>
  onAttach: () => void
  onTask: () => void
  onTag: () => void
  onKill: () => void
}): JSX.Element {
  const [sortKey, setSortKey] = useState<SortKey>('last')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [edit, setEdit] = useState<{ id: number; value: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const savingRef = useRef(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  const compact = props.density !== 'cozy'

  const rows = useMemo(
    () => sortRows(props.rows, sortKey, sortDir), [props.rows, sortKey, sortDir])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (compact ? 24 : 30),
    overscan: 14
  })

  const focusRow = useCallback((id: number | null) => {
    if (id === null) return
    requestAnimationFrame(() => {
      bodyRef.current
        ?.querySelector<HTMLElement>(`[data-row-id="${id}"]`)?.focus()
    })
  }, [])

  const selectOne = useCallback((b: Beacon) => {
    props.onSelect([b.id], b.id)
  }, [props])

  const pick = (b: Beacon, e: React.MouseEvent): void => {
    if (e.shiftKey && props.primary !== null) {
      const next = rangeSelection(rows, props.primary, b.id)
      props.onSelect([...next], b.id)
      return
    }
    if (e.ctrlKey || e.metaKey) {
      const next = new Set(props.sel)
      if (next.has(b.id)) next.delete(b.id)
      else next.add(b.id)
      props.onSelect([...next], b.id)
      return
    }
    selectOne(b)
  }

  const move = (delta: number, extend: boolean): void => {
    const at = rows.findIndex((r) => r.id === props.primary)
    const idx = nextIndex(rows.length, at, delta)
    const b = rows[idx]
    if (!b) return
    virt.scrollToIndex(idx, { align: 'auto' })
    if (extend && props.primary !== null) {
      const next = rangeSelection(rows, props.primary, b.id)
      props.onSelect([...next], b.id)
    } else {
      props.onSelect([b.id], b.id)
    }
    focusRow(b.id)
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>): void => {
    if (edit) return
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); move(1, e.shiftKey); break
      case 'ArrowUp': e.preventDefault(); move(-1, e.shiftKey); break
      case 'Home': e.preventDefault(); move(-rows.length, e.shiftKey); break
      case 'End': e.preventDefault(); move(rows.length, e.shiftKey); break
      case ' ':
        if (!props.primary) break
        e.preventDefault()
        if (props.sel.has(props.primary)) {
          const next = new Set(props.sel)
          next.delete(props.primary)
          props.onSelect([...next], props.primary)
        } else {
          props.onSelect([...props.sel, props.primary], props.primary)
        }
        break
      case 'a':
        if (!e.ctrlKey && !e.metaKey) break
        e.preventDefault()
        props.onSelect(rows.map((r) => r.id), props.primary)
        break
      case 'Escape':
        if (props.sel.size) {
          e.preventDefault()
          props.onSelect([], null)
        }
        break
      case 'F2': {
        if (props.primary === null) break
        const b = rows.find((r) => r.id === props.primary)
        if (!b) break
        e.preventDefault()
        setEdit({ id: b.id, value: b.alias ?? '' })
        break
      }
    }
  }

  useEffect(() => {
    if (edit) {
      const el = bodyRef.current?.querySelector<HTMLInputElement>(
        `[data-alias-input="${edit.id}"]`)
      el?.focus()
      el?.select()
    }
  }, [edit])

  const commit = async (): Promise<void> => {
    if (!edit || savingRef.current) return
    const id = edit.id
    const b = rows.find((r) => r.id === id)
    if (!b) { setEdit(null); return }
    const value = edit.value.trim()
    if (value === (b.alias ?? '')) { setEdit(null); return }
    savingRef.current = true
    setSaving(true)
    try {
      await props.onAlias(id, value)
      setEdit(null)
      focusRow(id)
    } finally {
      savingRef.current = false
      setSaving(false)
    }
  }

  const sort = (key: SortKey): void => {
    if (sortKey === key) setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir(key === 'last' ? 'asc' : 'desc') }
    virt.scrollToOffset(0)
  }

  const ariaSort = (key: SortKey): 'ascending' | 'descending' | 'none' =>
    sortKey === key ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'

  const all = rows.length > 0 && rows.every((r) => props.sel.has(r.id))

  return (
    <div className="view targets">
      <Toolbar label="Targets">
        <ToolbarTitle>Targets</ToolbarTitle>
        <span className="pill">{rows.length}</span>
        {props.sel.size > 0 && (
          <span className="pill">{props.sel.size} sel</span>
        )}
        <ToolbarSpacer />
        <input type="search" className="ui-input dock-filter" value={props.query}
          onChange={(e) => props.onQuery(e.target.value)}
          placeholder="filter id, host, user" aria-label="Filter targets" />
        <IconButton label="Refresh targets" onClick={props.onRefresh}>↻</IconButton>
      </Toolbar>

      <div className="bulkbar" aria-live="polite">
        <ToolbarGroup label="Selection">
          <button className="btn tiny" disabled={rows.length === 0}
            onClick={() => props.onSelect(all ? [] : rows.map((r) => r.id),
              all ? null : props.primary)}>
            {all ? 'None' : `All ${rows.length}`}
          </button>
          <button className="btn tiny" disabled={rows.length === 0}
            onClick={() => props.onSelect(
              rows.filter((r) => !props.sel.has(r.id)).map((r) => r.id),
              props.primary)}>Invert</button>
        </ToolbarGroup>
        {props.sel.size > 0 && (
          <ToolbarGroup label="Bulk actions">
            <button className="btn tiny" onClick={props.onTask}>Task…</button>
            <button className="btn tiny" onClick={props.onTag}>Tag…</button>
            <button className="btn tiny" onClick={props.onKill}>Kill…</button>
            <button className="btn tiny" onClick={() => props.onSelect([], null)}>
              Clear
            </button>
          </ToolbarGroup>
        )}
        <span className="grow" />
        <span className="muted small target-hint">
          ↑↓ move · space select · shift range · F2 alias
        </span>
      </div>

      <div className="table-wrap" ref={scrollRef} role="table"
        aria-label="Targets" aria-rowcount={rows.length + 1}
        onKeyDown={onKeyDown}>
        <div className="row head sticky" role="row">
          <div role="columnheader" aria-sort={ariaSort('id')}>
            <button className="sort" onClick={() => sort('id')}>BEACON</button>
          </div>
          <div role="columnheader" aria-sort={ariaSort('host')}>
            <button className="sort" onClick={() => sort('host')}>IDENTITY</button>
          </div>
          <div role="columnheader" aria-sort={ariaSort('pri')}>
            <button className="sort" onClick={() => sort('pri')}>PRI</button>
          </div>
          <span role="columnheader">OS</span>
          <div role="columnheader" aria-sort={ariaSort('last')}>
            <button className="sort" onClick={() => sort('last')}>LAST</button>
          </div>
          <span role="columnheader">VIEW</span>
        </div>
        {rows.length === 0 && (
          <div role="rowgroup">
            <div role="row">
              <div role="cell">
                <EmptyState glyph="◉"
                  title={props.total === 0 ? 'No targets' : 'No match'}
                  hint={props.total === 0
                    ? 'they appear on their first check-in'
                    : 'clear the filter to see every target'} />
              </div>
            </div>
          </div>
        )}
        <div role="rowgroup" ref={bodyRef}
          style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const b = rows[v.index]
            if (!b) return null
            const sev = severity(b)
            const editing = edit?.id === b.id
            return (
              <div key={b.id} role="row" data-row-id={b.id}
                tabIndex={props.primary === b.id || (!props.primary && v.index === 0) ? 0 : -1}
                aria-selected={props.sel.has(b.id)}
                className={`row target-row${props.primary === b.id ? ' sel' : ''}`}
                data-sev={sev}
                style={{
                  position: 'absolute', top: 0, left: 0, right: 0,
                  transform: `translateY(${v.start}px)`
                }}
                onClick={(e) => pick(b, e)}
                onDoubleClick={() => {
                  if (props.primary !== b.id) props.onSelect([b.id], b.id)
                  props.onAttach()
                }}>
                <span className="id" role="cell">
                  <span className={b.alive ? 'live' : 'dead'} aria-hidden="true">●</span>{' '}
                  {b.id}
                </span>
                <span className="host identity" role="cell">
                  {b.display_name || '?'}
                  {editing ? (
                    <input className="alias-input" data-alias-input={b.id}
                      value={edit.value} disabled={saving}
                      aria-label={`Alias for ${b.id}`}
                      onChange={(e) => setEdit({ id: b.id, value: e.target.value })}
                      onBlur={() => void commit()}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') { e.preventDefault(); void commit() }
                        if (e.key === 'Escape') {
                          e.preventDefault()
                          setEdit(null)
                          focusRow(b.id)
                        }
                        e.stopPropagation()
                      }} />
                  ) : (
                    <button type="button" className="alias" tabIndex={-1}
                      title="Double-click or F2 to set an alias"
                      onDoubleClick={(e) => {
                        e.stopPropagation()
                        setEdit({ id: b.id, value: b.alias ?? '' })
                      }}>
                      {b.alias ? `«${b.alias}»` : '—'}
                    </button>
                  )}
                </span>
                <span role="cell" className="pri">
                  <span className={`sev ${sev}`}>{severityLabel(sev)}</span>
                  <span className="muted priv">{b.privilege || 'user'}</span>
                </span>
                <span className="muted" role="cell">{b.os?.slice(0, 3)}/{b.arch}</span>
                <span className="muted mono" role="cell">{b.last_seen_age ?? 0}s</span>
                <span className="muted" role="cell">
                  {b.viewers?.length ? `+${b.viewers.length}` : '—'}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
