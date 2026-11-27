import type { PanelId } from './panels'

export type GroupId =
  | 'session' | 'host' | 'topology' | 'assets' | 'activity' | 'system'

export interface GroupMeta {
  label: string
  glyph: string
  hint: string
  panels: PanelId[]
}

/** Fixed taxonomy. Every registered leaf belongs to exactly one group. */
export const GROUPS: Record<GroupId, GroupMeta> = {
  session: {
    label: 'Session', glyph: '◉', hint: 'Target inventory',
    panels: ['targets']
  },
  host: {
    label: 'Host', glyph: '❯', hint: 'Inspect, console and host data',
    panels: ['inspector', 'terminal', 'screen', 'processes', 'files', 'network']
  },
  topology: {
    label: 'Topology', glyph: '⌁', hint: 'Graph and engagement model',
    panels: ['graph', 'engagement']
  },
  assets: {
    label: 'Assets', glyph: '◈', hint: 'Listeners, armory, credentials and AI',
    panels: ['listeners', 'armory', 'creds', 'ai']
  },
  activity: {
    label: 'Activity', glyph: '▒', hint: 'Events, audit, jobs and chat',
    panels: ['events', 'audit', 'jobs', 'chat']
  },
  system: {
    label: 'System', glyph: '⚙', hint: 'Console settings',
    panels: ['settings']
  }
}

export const GROUP_IDS = Object.keys(GROUPS) as GroupId[]

export function groupOf(panel: PanelId): GroupId {
  const hit = GROUP_IDS.find((id) => GROUPS[id].panels.includes(panel))
  return hit ?? 'session'
}
