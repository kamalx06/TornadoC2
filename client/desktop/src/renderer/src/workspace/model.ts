import {
  normalizeWorkspaceModel,
  type TabNode,
  type TabsetNode,
  type WorkspaceModel,
  type WorkspaceNode
} from 'react-resizable-panels'
import { PANELS, PANEL_IDS, isPanelId, type PanelId, type SlotId } from './panels'

export const DOCK_KEY = 't2.dock.v1'
export const DOCK_VERSION = 1 as const
export const GROUPED_KEY = 't2.dock.grouped'
export const DOCK_BACKUP = 't2.dock.v1.pre-groups'

export type PanelData = { panel: PanelId }
export type TabsetData = { slot: SlotId }

export type DockTab = TabNode<PanelData>
export type DockTabset = TabsetNode<PanelData, TabsetData>
export type DockModel = WorkspaceModel<PanelData, TabsetData>

export const SLOT_ORDER: SlotId[] = ['left', 'center', 'right', 'bottom']

export function makeTab(panel: PanelId): DockTab {
  return {
    id: panel,
    title: PANELS[panel].title,
    data: { panel },
    disableClose: false
  }
}

function tabset(slot: SlotId, size: number, panels: PanelId[], selected: PanelId): DockTabset {
  return {
    type: 'tabset',
    id: `dock-${slot}`,
    size,
    data: { slot },
    selectedId: selected,
    tabs: panels.map(makeTab),
    collapsible: true,
    minWidth: slot === 'center' ? '320px' : slot === 'left' ? '200px' : '240px',
    minHeight: slot === 'bottom' ? '140px' : undefined
  }
}

export function singleModel(panel: PanelId): DockModel {
  return {
    version: DOCK_VERSION,
    root: {
      type: 'tabset',
      id: 'dock-single',
      keepWhenEmpty: true,
      selectedId: panel,
      tabs: [makeTab(panel)]
    }
  }
}

export function defaultModel(): DockModel {
  const root: WorkspaceNode<PanelData, TabsetData> = {
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
          tabset('left', 22, ['targets'], 'targets'),
          tabset('center', 52, ['terminal', 'graph'], 'terminal'),
          tabset('right', 26, ['inspector', 'listeners'], 'inspector')
        ]
      },
      tabset('bottom', 28, ['events', 'chat'], 'events')
    ]
  }
  return { version: DOCK_VERSION, root }
}

export function countTabs(node: WorkspaceNode<PanelData, TabsetData>): number {
  if (node.type === 'tabset') return node.tabs.length
  return node.children.reduce((n, child) => n + countTabs(child), 0)
}

export function walkTabsets(
  node: WorkspaceNode<PanelData, TabsetData>, out: DockTabset[] = []
): DockTabset[] {
  if (node.type === 'tabset') {
    out.push(node)
    return out
  }
  for (const child of node.children) walkTabsets(child, out)
  return out
}

export function tabsetBySlot(model: DockModel, slot: SlotId): DockTabset | undefined {
  return walkTabsets(model.root).find((t) => t.data?.slot === slot)
}

export function findTab(model: DockModel, id: PanelId): DockTabset | undefined {
  return walkTabsets(model.root).find((t) => t.tabs.some((tab) => tab.id === id))
}

function asModel(value: unknown): DockModel | null {
  if (!value || typeof value !== 'object') return null
  const raw = value as { version?: unknown; hidden?: unknown }
  if (raw.version !== DOCK_VERSION) return null
  const hidden = new Set(
    Array.isArray(raw.hidden)
      ? raw.hidden.filter((id): id is PanelId => isPanelId(id))
      : [])
  const model = normalizeWorkspaceModel<PanelData, TabsetData>(value, {
    mapTab: (tab) => {
      if (!isPanelId(tab.id)) return null
      return { ...tab, title: PANELS[tab.id].title, data: { panel: tab.id } }
    }
  })
  if (!model || countTabs(model.root) === 0) return null
  const seen = new Set<string>()
  for (const ts of walkTabsets(model.root)) {
    ts.tabs = ts.tabs.filter((tab) => {
      if (!isPanelId(tab.id) || seen.has(tab.id)) return false
      seen.add(tab.id)
      return true
    })
    if (!ts.tabs.some((tab) => tab.id === ts.selectedId)) {
      ts.selectedId = ts.tabs[0]?.id
    }
    if (ts.tabs.length === 0) ts.keepWhenEmpty = true
  }
  const missing = PANEL_IDS.filter((id) => !seen.has(id) && !hidden.has(id))
  if (missing.length) {
    const tabsets = walkTabsets(model.root)
    for (const id of missing) {
      const target = tabsets.find((ts) => ts.data?.slot === PANELS[id].slot) ??
        tabsets[0]
      if (!target) break
      target.tabs.push(makeTab(id))
    }
  }
  return model
}

export function parseStoredModel(raw: string): DockModel | null {
  try {
    return asModel(JSON.parse(raw))
  } catch {
    return null
  }
}

export function loadModel(
  key = DOCK_KEY,
  fallback: () => DockModel = defaultModel
): { model: DockModel; recovered: boolean; migrated?: boolean } {
  let raw: string | null = null
  try {
    raw = localStorage.getItem(key)
    if (key === DOCK_KEY && !localStorage.getItem(GROUPED_KEY)) {
      if (!raw) {
        localStorage.setItem(GROUPED_KEY, '1')
      } else {
        try {
          const candidate = JSON.parse(raw) as { version?: unknown }
          if (candidate.version === DOCK_VERSION) {
            try { localStorage.setItem(DOCK_BACKUP, raw) } catch { /* ignore */ }
            localStorage.setItem(GROUPED_KEY, '1')
            return { model: fallback(), recovered: false, migrated: true }
          }
        } catch { /* corrupt: handled below */ }
      }
    }
  } catch {
    return { model: fallback(), recovered: false }
  }
  if (!raw) return { model: fallback(), recovered: false }
  try {
    const model = asModel(JSON.parse(raw))
    if (model) return { model, recovered: false }
  } catch {
    /* corrupt JSON falls through */
  }
  return { model: fallback(), recovered: true }
}

export function saveModel(model: DockModel, key = DOCK_KEY): boolean {
  if (countTabs(model.root) === 0) return true
  const present = new Set<string>()
  for (const ts of walkTabsets(model.root)) {
    for (const tab of ts.tabs) present.add(tab.id)
  }
  const hidden = PANEL_IDS.filter((id) => !present.has(id))
  try {
    localStorage.setItem(key, JSON.stringify({ ...model, hidden }))
    return true
  } catch {
    return false
  }
}

export function parseDetached(hash: string): PanelId | null {
  if (!hash.startsWith('#detach/')) return null
  const id = hash.slice('#detach/'.length)
  return isPanelId(id) ? id : null
}

export function tabsetOrder(model: DockModel): DockTabset[] {
  const bySlot = new Map<SlotId, DockTabset>()
  for (const ts of walkTabsets(model.root)) {
    if (ts.data?.slot) bySlot.set(ts.data.slot, ts)
  }
  return SLOT_ORDER.map((s) => bySlot.get(s)).filter((x): x is DockTabset => Boolean(x))
}
