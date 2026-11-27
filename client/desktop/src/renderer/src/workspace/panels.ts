// Panel registry. The dock only knows ids; App owns rendering and caps.

export type PanelId =
  | 'targets' | 'inspector' | 'listeners' | 'engagement' | 'graph'
  | 'audit' | 'chat' | 'armory' | 'ai' | 'jobs' | 'creds' | 'events'
  | 'settings' | 'terminal' | 'screen' | 'processes' | 'files' | 'network'

export type SlotId = 'left' | 'center' | 'right' | 'bottom'

export interface PanelMeta {
  title: string
  glyph: string
  slot: SlotId
  cap?: string
  minWidth?: string
  minHeight?: string
}

export const PANELS: Record<PanelId, PanelMeta> = {
  targets: { title: 'Targets', glyph: '◉', slot: 'left', cap: 'beacon.list', minWidth: '190px' },
  listeners: { title: 'Listeners', glyph: '◈', slot: 'left', cap: 'listener.view' },
  engagement: { title: 'Engagement', glyph: '◇', slot: 'center', cap: 'beacon.list' },
  graph: { title: 'Graph', glyph: '⌁', slot: 'center', cap: 'beacon.list' },
  terminal: { title: 'Terminal', glyph: '⌨', slot: 'center', cap: 'beacon.list' },
  screen: { title: 'Screen', glyph: '▣', slot: 'center', cap: 'beacon.list' },
  processes: { title: 'Processes', glyph: '≣', slot: 'center', cap: 'beacon.list' },
  files: { title: 'Files', glyph: '▤', slot: 'center', cap: 'beacon.list' },
  network: { title: 'Network', glyph: '⇄', slot: 'center', cap: 'beacon.list' },
  audit: { title: 'Audit', glyph: '▤', slot: 'center', cap: 'audit.read.own' },
  inspector: { title: 'Inspector', glyph: '❯', slot: 'right', cap: 'beacon.list', minWidth: '240px' },
  armory: { title: 'Armory', glyph: '⛨', slot: 'right', cap: 'armory.view' },
  ai: { title: 'AI', glyph: '✧', slot: 'right', cap: 'beacon.list' },
  jobs: { title: 'Jobs', glyph: '⇅', slot: 'bottom' },
  creds: { title: 'Credentials', glyph: '⚿', slot: 'right' },
  events: { title: 'Events', glyph: '▒', slot: 'bottom' },
  chat: { title: 'Chat', glyph: '✦', slot: 'bottom', cap: 'chat.use' },
  settings: { title: 'Settings', glyph: '⚙', slot: 'bottom' }
}

export const PANEL_IDS = Object.keys(PANELS) as PanelId[]

export function isPanelId(value: unknown): value is PanelId {
  return typeof value === 'string' && Object.hasOwn(PANELS, value)
}

export function canUse(meta: PanelMeta, caps: string[]): boolean {
  return !meta.cap || caps.includes(meta.cap)
}
