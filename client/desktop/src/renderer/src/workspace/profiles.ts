import type { DockModel } from './model'
import { makeTab, type DockTab } from './model'
import type { SlotId } from './panels'
import type { PanelId } from './panels'

export type ProfileId = 'engagement' | 'investigation' | 'listeners' | 'admin' | 'custom'

export interface Profile {
  label: string
  glyph: string
  hint: string
}

export const PROFILES: Record<Exclude<ProfileId, 'custom'>, Profile> = {
  engagement: { label: 'Engagement', glyph: '◎', hint: 'Targets, topology and chat' },
  investigation: { label: 'Investigation', glyph: '⌕', hint: 'Audit, graph and credentials' },
  listeners: { label: 'Listeners', glyph: '◈', hint: 'Listener control and armory' },
  admin: { label: 'Admin', glyph: '⚙', hint: 'Audit, settings and AI' }
}

const SIZES: Record<SlotId, number> = { left: 24, center: 52, right: 24, bottom: 28 }

function ts(slot: SlotId, panels: PanelId[], selected: PanelId) {
  return {
    type: 'tabset' as const,
    id: `dock-${slot}`,
    size: SIZES[slot],
    data: { slot },
    selectedId: selected,
    collapsible: true,
    minWidth: slot === 'center' ? '320px' : slot === 'left' ? '200px' : '240px',
    minHeight: slot === 'bottom' ? '140px' : undefined,
    tabs: panels.map((p): DockTab => makeTab(p))
  }
}

function model(
  left: [PanelId[], PanelId],
  center: [PanelId[], PanelId],
  right: [PanelId[], PanelId],
  bottom: [PanelId[], PanelId]
): DockModel {
  return {
    version: 1,
    root: {
      type: 'split',
      id: 'dock-root',
      orientation: 'vertical',
      children: [
        {
          type: 'split',
          id: 'dock-main',
          orientation: 'horizontal',
          size: '72%',
          children: [
            ts('left', ...left),
            ts('center', ...center),
            ts('right', ...right)
          ]
        },
        ts('bottom', ...bottom)
      ]
    }
  }
}

/** Curated starter sets; other leaves stay reachable through group menus. */
export function profileModel(id: Exclude<ProfileId, 'custom'>): DockModel {
  switch (id) {
    case 'engagement':
      return model(
        [['targets'], 'targets'],
        [['terminal', 'graph'], 'terminal'],
        [['inspector', 'listeners'], 'inspector'],
        [['events', 'chat'], 'events'])
    case 'investigation':
      return model(
        [['targets'], 'targets'],
        [['audit', 'terminal', 'files', 'graph'], 'audit'],
        [['inspector', 'creds'], 'inspector'],
        [['events', 'jobs'], 'events'])
    case 'listeners':
      return model(
        [['listeners', 'targets'], 'listeners'],
        [['graph', 'terminal'], 'graph'],
        [['armory', 'creds'], 'armory'],
        [['events'], 'events'])
    case 'admin':
      return model(
        [['targets'], 'targets'],
        [['audit', 'terminal'], 'audit'],
        [['settings', 'ai'], 'settings'],
        [['events', 'jobs'], 'events'])
  }
}
