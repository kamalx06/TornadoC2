import {
  forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState,
  type ReactNode
} from 'react'
import {
  TabsetCollapseButton, TabsetMaximizeButton, Workspace,
  useWorkspaceRef, type TabRenderProps, type TabsetNode,
  type WorkspaceChangedMeta
} from 'react-resizable-panels'
import EmptyState from '../ui/EmptyState'
import {
  defaultModel, findTab, loadModel, makeTab, saveModel, singleModel, tabsetBySlot,
  tabsetOrder, walkTabsets, type DockModel, type PanelData, type TabsetData
} from './model'
import { PANELS, isPanelId, type PanelId } from './panels'

export interface DockHandle {
  open: (id: PanelId) => boolean
  reset: () => void
  active: () => PanelId | null
  apply: (model: DockModel) => void
}

type Notice = (text: string, kind?: 'ok' | 'err' | 'info') => void

const Dock = forwardRef<DockHandle, {
  renderPanel: (id: PanelId) => ReactNode
  onActive: (id: PanelId | null) => void
  onNotice: Notice
  single?: PanelId
  storageKey?: string
  onCustom?: () => void
}>(function Dock(props, ref) {
  const key = props.storageKey ?? 't2.dock.v1'
  const fallback = useCallback(
    () => (props.single ? singleModel(props.single) : defaultModel()),
    [props.single])
  const [initial] = useState(() => loadModel(key, fallback))
  const workspace = useWorkspaceRef<PanelData, TabsetData>()
  const activeTab = useRef<PanelId | null>('targets')
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const focusTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const announced = useRef(false)
  const pendingFocus = useRef<PanelId | null>(null)
  const pendingActive = useRef<PanelId | null>(null)
  const activeLock = useRef(0)

  useEffect(() => {
    if (!initial.recovered || announced.current) return
    announced.current = true
    try {
      localStorage.removeItem(key)
    } catch {
      /* ignore */
    }
    props.onNotice('saved layout was corrupt — restored the default', 'err')
  }, [initial.recovered, props])

  useEffect(() => () => {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    if (focusTimer.current) clearTimeout(focusTimer.current)
  }, [])

  const focusTab = useCallback((id: PanelId) => {
    const apply = (): void => {
      document.querySelector<HTMLElement>(`[data-tab-id="${id}"]`)?.focus()
    }
    setTimeout(apply, 50)
    requestAnimationFrame(apply)
  }, [])

  const persist = useCallback((model: DockModel) => {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    saveTimer.current = setTimeout(() => {
      if (!saveModel(model, key)) props.onNotice('layout could not be saved', 'err')
    }, 150)
  }, [props, key])

  const onModelChanged = useCallback((model: DockModel, meta: WorkspaceChangedMeta) => {
    persist(model)
    if (meta.isUserInteraction && meta.reason !== 'select' &&
        meta.reason !== 'set-model') props.onCustom?.()
    const ws = workspace.current
    const active = ws?.getActiveTabsetId()
    const ts = active
      ? walkTabsets(model.root).find((t) => t.id === active)
      : undefined
    const focusedTab = (document.activeElement as HTMLElement | null)
      ?.closest<HTMLElement>('[data-tab-id]')?.getAttribute('data-tab-id')
    let id: string | undefined
    if (Date.now() < activeLock.current && pendingActive.current) {
      id = pendingActive.current
    } else if (pendingFocus.current && findTab(model, pendingFocus.current)) {
      id = pendingFocus.current
    } else if (focusedTab && isPanelId(focusedTab) && findTab(model, focusedTab)) {
      id = focusedTab
    } else if (activeTab.current && findTab(model, activeTab.current)) {
      id = activeTab.current
    } else {
      id = ts?.selectedId ??
        walkTabsets(model.root).find((t) => t.selectedId)?.selectedId
      if (pendingActive.current && findTab(model, pendingActive.current)) {
        id = pendingActive.current
      }
      pendingActive.current = null
    }
    if (meta.reason === 'close' && pendingFocus.current) {
      const target = pendingFocus.current
      pendingFocus.current = null
      if (focusTimer.current) clearTimeout(focusTimer.current)
      // Workspace settles its own removal focus first; land ours after it.
      focusTimer.current = setTimeout(() => focusTab(target), 140)
    }
    if (id && isPanelId(id)) {
      activeTab.current = id
      props.onActive(id)
      if (meta.reason === 'move' || meta.reason === 'restore') focusTab(id)
    } else if (!findTab(model, activeTab.current ?? 'targets')) {
      activeTab.current = null
      props.onActive(null)
    }
  }, [persist, props, workspace, focusTab])

  const close = useCallback((id: PanelId) => {
    const ws = workspace.current
    if (!ws) return
    const ts = findTab(ws.getModel(), id)
    if (!ts) return
    const at = ts.tabs.findIndex((tab) => tab.id === id)
    let next = ts.tabs[at + 1]?.id ?? ts.tabs[at - 1]?.id
    if (!next) {
      const order = tabsetOrder(ws.getModel())
      const here = order.findIndex((t) => t.id === ts.id)
      for (let i = 1; i <= order.length && !next; i++) {
        next = order[here + i]?.tabs[0]?.id ?? order[here - i]?.tabs.at(-1)?.id
      }
    }
    pendingFocus.current = next && isPanelId(next) ? next : null
    ws.closeTab(id)
  }, [workspace])

  const closeActive = useCallback(() => {
    if (activeTab.current) close(activeTab.current)
  }, [close])

  const open = useCallback((id: PanelId): boolean => {
    const ws = workspace.current
    if (!ws) return false
    const model = ws.getModel()
    const found = findTab(model, id)
    activeLock.current = Date.now() + 600
    if (found) {
      pendingActive.current = id
      ws.selectTab(id)
      if (found.collapsed) ws.expandTabset(found.id)
      activeTab.current = id
      props.onActive(id)
      focusTab(id)
      return true
    }
    const target = tabsetBySlot(model, PANELS[id].slot) ??
      tabsetBySlot(model, 'center') ?? walkTabsets(model.root)[0]
    pendingActive.current = id
    ws.addTab(makeTab(id),
      target ? { target: { region: 'center', tabsetId: target.id } } : undefined)
    if (target?.collapsed) ws.expandTabset(target.id)
    activeTab.current = id
    props.onActive(id)
    focusTab(id)
    return true
  }, [focusTab, props, workspace])

  const reset = useCallback(() => {
    try {
      localStorage.removeItem(key)
    } catch {
      /* ignore */
    }
    const next = fallback()
    workspace.current?.setModel(next)
    const first = walkTabsets(next.root)[0]?.tabs[0]?.id
    if (first && isPanelId(first)) {
      activeTab.current = first
      props.onActive(first)
      focusTab(first)
    }
    props.onNotice('layout reset', 'ok')
  }, [fallback, focusTab, props, workspace, key])

  const apply = useCallback((model: DockModel) => {
    workspace.current?.setModel(model)
    const first = walkTabsets(model.root)[0]?.tabs[0]?.id
    if (first && isPanelId(first)) {
      activeTab.current = first
      props.onActive(first)
      focusTab(first)
    }
  }, [focusTab, props, workspace])

  useImperativeHandle(ref, () => ({
    open,
    reset,
    active: () => activeTab.current,
    apply
  }), [open, reset, apply])

  const moveActive = useCallback((to: 'prev' | 'next' | number) => {
    const ws = workspace.current
    if (!ws) return
    const id = activeTab.current
    if (!id) return
    const model = ws.getModel()
    const current = findTab(model, id)
    if (!current) return
    const order = tabsetOrder(model)
    const at = order.findIndex((t) => t.id === current.id)
    const dest = typeof to === 'number' ? order[to]
      : order[at + (to === 'next' ? 1 : -1)]
    if (!dest || dest.id === current.id) return
    ws.moveTab(id, { region: 'center', tabsetId: dest.id })
    if (dest.collapsed) ws.expandTabset(dest.id)
    activeTab.current = id
    focusTab(id)
  }, [focusTab, workspace])

  const onKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    const typing = e.target instanceof HTMLElement &&
      ['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName)
    if (!e.altKey && e.key === 'Delete' && !typing) {
      e.preventDefault()
      closeActive()
      return
    }
    if (!e.altKey || e.ctrlKey || e.metaKey) return
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault()
      moveActive(e.key === 'ArrowRight' ? 'next' : 'prev')
      return
    }
    const digit = Number(e.key)
    if (digit >= 1 && digit <= 4) {
      e.preventDefault()
      moveActive(digit - 1)
      return
    }
    if (e.key.toLowerCase() === 'm' && e.shiftKey) {
      e.preventDefault()
      const ws = workspace.current
      const model = ws?.getModel()
      if (!ws || !model) return
      if (model.maximizedTabsetId) ws.restoreTabset()
      else {
        const ts = walkTabsets(model.root).find((t) =>
          t.tabs.some((tab) => tab.id === activeTab.current))
        if (ts) ws.maximizeTabset(ts.id)
      }
    }
  }, [moveActive, workspace, closeActive])

  const renderTab = useCallback((tab: { id: string; title?: string }, p: TabRenderProps) => {
    const panel = isPanelId(tab.id) ? tab.id : null
    return (
      <div
        {...p}
        className={`dock-tab${p.className ? ` ${p.className}` : ''}`}
        onClick={(e) => {
          p.onClick?.(e)
          if (panel) {
            activeTab.current = panel
            props.onActive(panel)
          }
        }}
        onFocus={() => {
          if (panel) {
            activeTab.current = panel
            props.onActive(panel)
          }
        }}
      >
        <span className="dock-glyph" aria-hidden="true">
          {panel ? PANELS[panel].glyph : '·'}
        </span>
        <span className="dock-tab-title">{tab.title ?? tab.id}</span>
      </div>
    )
  }, [props])

  const renderToolbar = useCallback((ts: TabsetNode<PanelData, TabsetData>) => (
    <>
      <span className="dock-slot" aria-hidden="true">{ts.data?.slot}</span>
      <TabsetMaximizeButton className="dock-tool"
        title="Maximise pane (Alt+Shift+M)" />
      <TabsetCollapseButton className="dock-tool" title="Collapse pane" />
      <button type="button" className="dock-tool" aria-label="Close tab"
        title="Close tab (Delete)"
        onClick={() => {
          const id = ts.selectedId
          if (id && isPanelId(id)) close(id)
        }}>×</button>
    </>
  ), [close])

  return (
    <div className="dock" onKeyDownCapture={onKeyDown}>
      <Workspace
        id="dock"
        aria-label="Operator workspace"
        defaultModel={initial.model}
        workspaceRef={workspace}
        onModelChanged={onModelChanged}
        renderTab={renderTab}
        renderTabContent={(tab) =>
          isPanelId(tab.id) ? props.renderPanel(tab.id) : null}
        renderTabsetToolbar={renderToolbar}
        renderEmptyTabset={() => (
          <EmptyState glyph="▢" title="Empty pane"
            hint="drag a tab here, or open one from the rail" />
        )}
        hiddenTabBehavior="keep-mounted"
        lazyTabContent
        tabsetMinWidth="170px"
        tabsetMinHeight="120px"
        classNames={{
          tabset: 'dock-tabset',
          header: 'dock-header',
          tabList: 'dock-tabs',
          tab: 'dock-tab',
          tabPanels: 'dock-panels',
          tabContent: 'dock-content',
          toolbar: 'dock-toolbar',
          split: 'dock-split',
          dropIndicator: 'dock-drop',
          dragPreview: 'dock-drag'
        }}
      />
    </div>
  )
})

export default Dock
