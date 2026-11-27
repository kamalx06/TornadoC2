// @vitest-environment jsdom
import { createRef } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import Dock, { type DockHandle } from '../src/renderer/src/workspace/Dock'
import {
  DOCK_BACKUP, GROUPED_KEY, defaultModel, loadModel, parseDetached, saveModel,
  tabsetBySlot,
  walkTabsets
} from '../src/renderer/src/workspace/model'
import { PROFILES, profileModel } from '../src/renderer/src/workspace/profiles'
import { PANEL_IDS } from '../src/renderer/src/workspace/panels'
import { GROUPS } from '../src/renderer/src/workspace/groups'

function setup(notice = vi.fn()) {
  return {
    notice,
    ...render(
      <Dock renderPanel={(id) => <p>panel {id}</p>}
        onActive={() => undefined} onNotice={notice} />
    )
  }
}

beforeEach(() => localStorage.clear())
afterEach(cleanup)

describe('layout model', () => {
  it('round-trips a saved layout', () => {
    const model = defaultModel()
    expect(saveModel(model)).toBe(true)
    expect(loadModel().recovered).toBe(false)
    expect(loadModel().model.root.type).toBe('split')
  })

  it('recovers from corrupt storage with a notice', () => {
    localStorage.setItem(GROUPED_KEY, '1')
    localStorage.setItem('t2.dock.v1', '{not json')
    const loaded = loadModel()
    expect(loaded.recovered).toBe(true)
    expect(tabsetBySlot(loaded.model, 'left')).toBeTruthy()
  })

  it('drops unknown panels and restores defaults when empty', () => {
    localStorage.setItem(GROUPED_KEY, '1')
    localStorage.setItem('t2.dock.v1', JSON.stringify({
      version: 1,
      root: { type: 'tabset', id: 'r', tabs: [{ id: 'nope', data: {} }] }
    }))
    const loaded = loadModel()
    expect(loaded.recovered).toBe(true)
    expect(tabsetBySlot(loaded.model, 'bottom')).toBeTruthy()
  })

  it('drops duplicate tabs from a tampered model', () => {
    localStorage.setItem(GROUPED_KEY, '1')
    localStorage.setItem('t2.dock.v1', JSON.stringify({
      version: 1,
      root: { type: 'tabset', id: 'r', tabs: [
        { id: 'targets', data: {} }, { id: 'targets', data: {} },
        { id: 'chat', data: {} }
      ] }
    }))
    const loaded = loadModel()
    expect(loaded.recovered).toBe(false)
    expect(JSON.stringify(loaded.model).match(/"targets"/g)).toHaveLength(3)
    expect(JSON.stringify(loaded.model).match(/"chat"/g)).toHaveLength(2)
  })

  it('covers every panel across profiles and keeps each profile small', () => {
    const grouped = Object.values(GROUPS).flatMap((g) => g.panels).sort()
    expect(grouped).toEqual([...PANEL_IDS].sort())
    for (const id of Object.keys(PROFILES) as Array<keyof typeof PROFILES>) {
      const ids = walkTabsets(profileModel(id).root)
        .flatMap((ts) => ts.tabs.map((tab) => tab.id))
      expect(ids.length).toBeLessThanOrEqual(9)
      expect(new Set(ids).size).toBe(ids.length)
      for (const x of ids) expect(PANEL_IDS).toContain(x)
    }
  })

  it('migrates an old flat layout once and keeps a backup', () => {
    const old = defaultModel()
    localStorage.setItem('t2.dock.v1', JSON.stringify(old))
    const first = loadModel()
    expect(first.migrated).toBe(true)
    expect(localStorage.getItem(GROUPED_KEY)).toBe('1')
    expect(localStorage.getItem(DOCK_BACKUP)).toBe(JSON.stringify(old))
    const second = loadModel()
    expect(second.migrated).toBeFalsy()
  })

  it('adds panels missing from an older saved model', () => {
    localStorage.setItem(GROUPED_KEY, '1')
    localStorage.setItem('t2.dock.v1', JSON.stringify({
      version: 1,
      root: { type: 'tabset', id: 'r', tabs: [{ id: 'targets', data: {} }] }
    }))
    const loaded = loadModel()
    expect(walkTabsets(loaded.model.root)
      .flatMap((ts) => ts.tabs.map((tab) => tab.id)).sort())
      .toEqual([...PANEL_IDS].sort())
  })

  it('parses only known detached panels', () => {
    expect(parseDetached('#detach/graph')).toBe('graph')
    expect(parseDetached('#detach/nope')).toBeNull()
    expect(parseDetached('#other/graph')).toBeNull()
  })
})

describe('dock', () => {
  it('renders every default panel exactly once', () => {
    setup()
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(7)
    expect(new Set(tabs.map((t) => t.getAttribute('data-tab-id'))).size).toBe(7)
  })

  it('reports a corrupt layout', async () => {
    localStorage.setItem(GROUPED_KEY, '1')
    localStorage.setItem('t2.dock.v1', 'garbage')
    const { notice } = setup()
    await waitFor(() => expect(notice).toHaveBeenCalled())
    expect(notice.mock.calls[0][0]).toMatch(/corrupt/)
    expect(screen.getAllByRole('tab').length).toBeGreaterThan(0)
    expect(localStorage.getItem('t2.dock.v1')).toBeNull()
  })

  it('moves a tab between panes with alt+arrow', () => {
    const { container } = setup()
    fireEvent.click(screen.getByRole('tab', { name: /Targets/ }))
    fireEvent.keyDown(screen.getByRole('tab', { name: /Targets/ }), {
      key: 'ArrowRight', altKey: true
    })
    expect(container.querySelector('[data-tabset-id="dock-left"]')).toBeNull()
    expect(container.querySelector('[data-tabset-id="dock-center"]')?.textContent)
      .toContain('Targets')
  })

  it('opens a closed panel through the handle and focuses it', async () => {
    const ref = createRef<DockHandle>()
    render(<Dock ref={ref} renderPanel={(id) => <p>panel {id}</p>}
      onActive={() => undefined} onNotice={() => undefined} />)
    expect(ref.current?.open('chat')).toBe(true)
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="chat"]')
        ?.getAttribute('data-tab-selected')).toBe('true'))
    await waitFor(() => expect(
      document.activeElement?.getAttribute('data-tab-id')).toBe('chat'))
  })

  it('restores focus to the next tab after closing', async () => {
    setup()
    fireEvent.click(screen.getByRole('tab', { name: /Targets/ }))
    const left = document.querySelector('[data-tabset-id="dock-left"]') as HTMLElement
    fireEvent.click(within(left).getByLabelText('Close tab'))
    await waitFor(() => expect(document.activeElement?.textContent)
      .toContain('Listeners'))
  })

  it('reopens a panel after every tab is closed', async () => {
    const ref = createRef<DockHandle>()
    const { container } = render(
      <Dock ref={ref} renderPanel={(id) => <p>panel {id}</p>}
        onActive={() => undefined} onNotice={() => undefined} />
    )
    for (let i = 0; i < 20 && screen.queryAllByRole('tab').length; i++) {
      fireEvent.click(screen.getAllByRole('tab')[0])
      fireEvent.keyDown(container.querySelector('.dock')!, { key: 'Delete' })
    }
    await waitFor(() => expect(screen.queryAllByRole('tab')).toHaveLength(0))
    expect(ref.current?.open('targets')).toBe(true)
    await waitFor(() =>
      expect(document.querySelector('[data-tab-id="targets"]')).toBeTruthy())
  })

  it('has no axe violations', async () => {
    const { container } = setup()
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false } }
    })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('moves with alt+digit and keeps focus on the tab', () => {
    setup()
    const targets = screen.getByRole('tab', { name: /Targets/ })
    fireEvent.click(targets)
    fireEvent.keyDown(targets, { key: '3', altKey: true })
    const right = document.querySelector('[data-tabset-id="dock-right"]')
    expect(right?.textContent).toContain('Targets')
  })

  it('maximises from the pane and restores from the keyboard', async () => {
    setup()
    const max = within(
      document.querySelector('[data-tabset-id="dock-left"]') as HTMLElement
    ).getByRole('button', { name: /maximize tabset/i })
    fireEvent.click(max)
    await waitFor(() => expect(
      document.querySelector('[data-tabset-id="dock-left"]')
        ?.getAttribute('data-tabset-maximized')).toBe('true'))
    fireEvent.keyDown(screen.getByRole('tab', { name: /Targets/ }), {
      key: 'M', altKey: true, shiftKey: true
    })
    await waitFor(() => expect(
      document.querySelector('[data-tabset-id="dock-left"]')
        ?.getAttribute('data-tabset-maximized')).toBeNull())
  })

  it('persists an arrangement for the next launch', async () => {
    const first = setup()
    fireEvent.click(screen.getByRole('tab', { name: /Chat/ }))
    await waitFor(() => {
      expect(localStorage.getItem('t2.dock.v1') ?? '').toContain('"chat"')
    })
    first.unmount()
    setup()
    const bottom = document.querySelector('[data-tabset-id="dock-bottom"]')
    expect(bottom?.textContent).toContain('Chat')
  })

  it('closes with Delete and resets through the handle', async () => {
    const ref = createRef<DockHandle>()
    const { container } = render(
      <Dock ref={ref} renderPanel={(id) => <p>panel {id}</p>}
        onActive={() => undefined} onNotice={() => undefined} />
    )
    const targets = screen.getByRole('tab', { name: /Targets/ })
    fireEvent.click(targets)
    fireEvent.keyDown(container.querySelector('.dock')!, { key: 'Delete' })
    expect(document.querySelector('[data-tab-id="targets"]')).toBeNull()
    ref.current?.reset()
    await waitFor(() => expect(
      document.querySelector('[data-tab-id="targets"]')).toBeTruthy())
    const left = document.querySelector('[data-tabset-id="dock-left"]')
    expect(left?.textContent).toContain('Targets')
    await waitFor(() =>
      expect(localStorage.getItem('t2.dock.v1') ?? '').toContain('targets'))
  })
})
