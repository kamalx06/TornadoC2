import { useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { AuditRow } from '../../../shared/ipc'
import { usePoll } from '../hooks'
import { useEvents } from '../lib/useEvents'
import {
  clear, exportText, pushAudit, type Event, type Level, type Source
} from '../lib/events'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

const LEVELS: Array<[Level | 'all', string]> = [
  ['all', 'all levels'], ['err', 'errors'], ['warn', 'warnings'],
  ['task', 'tasks'], ['info', 'info']
]
const SOURCES: Array<[Source | 'all', string]> = [
  ['all', 'all sources'], ['bridge', 'bridge'], ['task', 'task'],
  ['audit', 'audit'], ['operator', 'operator'], ['system', 'system']
]

function glyph(level: Level): string {
  if (level === 'err') return '■'
  if (level === 'warn') return '▲'
  if (level === 'task') return '›'
  return '·'
}

export default function EventLog(props: {
  enabled?: boolean
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const events = useEvents()
  const [level, setLevel] = useState<Level | 'all'>('all')
  const [source, setSource] = useState<Source | 'all'>('all')
  const [needle, setNeedle] = useState('')
  const [paused, setPaused] = useState(false)
  const [frozen, setFrozen] = useState<Event[]>([])
  const [follow, setFollow] = useState(true)
  const scroller = useRef<HTMLDivElement>(null)

  const audit = usePoll<AuditRow[]>('audit', { limit: 50 }, 15_000,
    props.enabled ?? true)
  useEffect(() => {
    if (audit.data?.length) pushAudit(audit.data)
  }, [audit.data])

  const all = paused ? frozen : events
  const rows = useMemo(() => {
    const q = needle.trim().toLowerCase()
    return all.filter((e) =>
      (level === 'all' || e.level === level) &&
      (source === 'all' || e.source === source) &&
      (!q || e.text.toLowerCase().includes(q) || e.source.includes(q)))
  }, [all, level, source, needle])

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 22,
    getItemKey: (i) => rows[i]?.id ?? i,
    overscan: 24
  })

  useEffect(() => {
    if (follow && rows.length) {
      virt.scrollToIndex(rows.length - 1, { align: 'end' })
    }
  }, [rows.length, follow]) // eslint-disable-line react-hooks/exhaustive-deps

  const pause = (): void => {
    if (!paused) setFrozen(events)
    setPaused((p) => !p)
  }

  const save = async (): Promise<void> => {
    try {
      const p = await window.t2.saveFile('events.log', exportText(rows))
      if (p) props.onToast(`saved ${p}`, 'ok')
    } catch (e) { props.onToast((e as Error).message, 'err') }
  }

  return (
    <div className="view events">
      <Toolbar label="Event log">
        <ToolbarTitle>Events</ToolbarTitle>
        <span className="pill">{rows.length}</span>
        {paused && <span className="paused-tag">paused</span>}
        <ToolbarSpacer />
        <select className="ui-input compact-select" value={level}
          aria-label="Level filter"
          onChange={(e) => setLevel(e.target.value as Level | 'all')}>
          {LEVELS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select className="ui-input compact-select" value={source}
          aria-label="Source filter"
          onChange={(e) => setSource(e.target.value as Source | 'all')}>
          {SOURCES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <input className="ui-input dock-filter" value={needle}
          onChange={(e) => setNeedle(e.target.value)} placeholder="search"
          aria-label="Search events" />
        <IconButton label={paused ? 'Resume events' : 'Pause events'}
          on={paused} onClick={pause}>{paused ? '▶' : '❚❚'}</IconButton>
        <IconButton label={follow ? 'Pause follow' : 'Follow output'}
          on={follow} onClick={() => setFollow((f) => !f)}>⇣</IconButton>
        <IconButton label="Save visible events" onClick={() => void save()}>⤓</IconButton>
        <IconButton label="Clear events" onClick={() => { clear(); setFrozen([]) }}>⌫</IconButton>
      </Toolbar>

      {audit.error && (
        <div className="banner">audit stream: {audit.error}</div>
      )}

      <div className="log event-scroll" ref={scroller} role="log"
        aria-live={paused ? 'off' : 'polite'} aria-label="Merged event log">
        {rows.length === 0 && (
          <EmptyState title={needle ? 'No matching events' : 'No events yet'}
            hint={needle ? 'clear the filters' : 'bridge, task and audit output appears here'} />
        )}
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const e = rows[v.index]
            if (!e) return null
            return (
              <div key={e.id} className={`event-line ${e.level}`}
                data-index={v.index}
                style={{
                  position: 'absolute', left: 0, right: 0,
                  transform: `translateY(${v.start}px)`
                }}>
                <span className="event-mark" aria-hidden="true">{glyph(e.level)}</span>
                <time className="mono event-time" dateTime={new Date(e.ts).toISOString()}>
                  {new Date(e.ts).toLocaleTimeString([], { hour12: false })}
                </time>
                <span className={`event-source ${e.source}`}>{e.source}</span>
                <span className="event-text">{e.text}</span>
              </div>
            )
          })}
        </div>
      </div>
      <div className="foot-note">
        ring {events.length}/2000 · audit merged · pause freezes the view, not collection
      </div>
    </div>
  )
}
