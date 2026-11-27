import type { DockModel, DockTab } from './model'
import { DOCK_KEY, makeTab, parseStoredModel } from './model'
import type { PanelId, SlotId } from './panels'

export type WorkspaceId = 'w1' | 'w2' | 'w3' | 'w4'

export const WORKSPACE_VERSION = 1 as const
export const WORKSPACE_KEY_PREFIX = 't2.workspace.v1.'
export const WORKSPACE_ACTIVE_KEY = 't2.workspace.active'
export const WORKSPACE_MIGRATED_KEY = 't2.workspace.v1.migrated'
export const LEGACY_BACKUP_KEY = 't2.dock.v1.pre-workspaces'

export const WORKSPACES: Record<WorkspaceId, { label: string; hint: string }> = {
  w1: { label: 'Workspace 1', hint: 'Target operations' },
  w2: { label: 'Workspace 2', hint: 'Infrastructure & assets' },
  w3: { label: 'Workspace 3', hint: 'Comms & telemetry' },
  w4: { label: 'Workspace 4', hint: 'Intel & reporting' }
}
export const WORKSPACE_IDS = Object.keys(WORKSPACES) as WorkspaceId[]

export function workspaceKey(id: WorkspaceId): string {
  return WORKSPACE_KEY_PREFIX + id
}

export function loadActiveWorkspace(): WorkspaceId {
  const v = localStorage.getItem(WORKSPACE_ACTIVE_KEY)
  return v && Object.hasOwn(WORKSPACES, v) ? v as WorkspaceId : 'w1'
}

function tabset(slot: SlotId, size: number, panels: PanelId[], selected: PanelId) {
  return {
    type: 'tabset' as const,
    id: `ws-${slot}`,
    size,
    data: { slot },
    selectedId: selected,
    collapsible: true,
    minWidth: slot === 'center' ? '320px' : '180px',
    minHeight: slot === 'bottom' ? '140px' : undefined,
    tabs: panels.map((p): DockTab => makeTab(p))
  }
}

function grid(top: PanelId[], topSel: PanelId, bottom: PanelId[],
  bottomSel: PanelId): DockModel {
  return {
    version: 1,
    root: {
      type: 'split', id: 'ws-root', orientation: 'vertical',
      children: [
        { type: 'split', id: 'ws-top', orientation: 'horizontal',
          size: '56%', children: [
            tabset('left', 56, top, topSel),
            tabset('center', 44, ['terminal'], 'terminal')
          ] },
        { type: 'split', id: 'ws-bottom', orientation: 'horizontal',
          size: '44%', children: [
            tabset('right', 56, bottom, bottomSel),
            tabset('bottom', 44, ['targets', 'inspector'], 'targets')
          ] }
      ]
    }
  }
}

export function defaultModelFor(id: WorkspaceId): DockModel {
  switch (id) {
    case 'w1':
      return grid(['screen', 'graph'], 'screen',
        ['processes', 'files', 'network'], 'processes')
    case 'w2':
      return {
        version: 1,
        root: tabset('center', 100,
          ['listeners', 'armory', 'creds', 'settings'], 'listeners')
      }
    case 'w3':
      return {
        version: 1,
        root: tabset('center', 100,
          ['events', 'chat', 'audit', 'jobs', 'ai'], 'events')
      }
    case 'w4':
      return {
        version: 1,
        root: {
          type: 'split', id: 'ws-root', orientation: 'horizontal',
          children: [
            tabset('left', 55, ['targets-intel'], 'targets-intel'),
            tabset('center', 45, ['engagement'], 'engagement')
          ]
        }
      }
  }
}

/** Copy the pre-workspace model into w1 once, keeping a verbatim backup. */
export function ensureMigrated(): void {
  try {
    if (localStorage.getItem(WORKSPACE_MIGRATED_KEY)) return
    const legacy = localStorage.getItem(DOCK_KEY)
    if (legacy) {
      try { localStorage.setItem(LEGACY_BACKUP_KEY, legacy) } catch { /* ignore */ }
      if (!localStorage.getItem(workspaceKey('w1'))) {
        const parsed = parseStoredModel(legacy)
        if (parsed) localStorage.setItem(workspaceKey('w1'), JSON.stringify(parsed))
      }
    }
    if (!localStorage.getItem(WORKSPACE_ACTIVE_KEY)) {
      localStorage.setItem(WORKSPACE_ACTIVE_KEY, 'w1')
    }
    localStorage.setItem(WORKSPACE_MIGRATED_KEY, '1')
  } catch {
    /* storage unavailable: defaults still work */
  }
}
