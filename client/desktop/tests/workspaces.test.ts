import { beforeEach, describe, expect, it } from 'vitest'
import {
  LEGACY_BACKUP_KEY, WORKSPACE_ACTIVE_KEY, WORKSPACE_MIGRATED_KEY,
  WORKSPACE_KEY_PREFIX, defaultModelFor, ensureMigrated, loadActiveWorkspace,
  workspaceKey
} from '../src/renderer/src/workspace/workspaces'
import { loadModel, saveModel, walkTabsets } from '../src/renderer/src/workspace/model'
import { PANEL_IDS } from '../src/renderer/src/workspace/panels'

beforeEach(() => localStorage.clear())

const tabs = (id: Parameters<typeof defaultModelFor>[0]) =>
  walkTabsets(defaultModelFor(id).root).flatMap((t) => t.tabs.map((x) => x.id))

describe('workspaces', () => {
  it('builds four distinct defaults with every W1 panel accounted for', () => {
    expect(new Set(tabs('w1')).size).toBe(tabs('w1').length)
    expect(tabs('w1')).toEqual(expect.arrayContaining([
      'screen', 'graph', 'terminal', 'processes', 'files', 'network',
      'targets', 'inspector'
    ]))
    expect(tabs('w2')).toEqual(['listeners', 'armory', 'creds', 'settings'])
    expect(tabs('w3')).toEqual(['events', 'chat', 'audit', 'jobs', 'ai'])
    expect(tabs('w4')).toEqual(['targets-intel', 'engagement'])
  })

  it('W1 is a 2x2 split', () => {
    const root = defaultModelFor('w1').root
    expect(root.type).toBe('split')
    if (root.type !== 'split') return
    expect(root.orientation).toBe('vertical')
    expect(root.children.every((c) => c.type === 'split')).toBe(true)
  })

  it('uses a distinct storage key per workspace', () => {
    expect(workspaceKey('w1')).toBe(WORKSPACE_KEY_PREFIX + 'w1')
    expect(workspaceKey('w3')).not.toBe(workspaceKey('w4'))
  })

  it('persists workspace models independently', () => {
    const w1 = defaultModelFor('w1')
    const w3 = defaultModelFor('w3')
    expect(saveModel(w1, workspaceKey('w1'))).toBe(true)
    expect(saveModel(w3, workspaceKey('w3'))).toBe(true)
    expect(loadModel(workspaceKey('w1'), () => defaultModelFor('w1')).model)
      .not.toEqual(loadModel(workspaceKey('w3'), () => defaultModelFor('w3')).model)
  })

  it('keeps closed tabs closed through a reload', () => {
    const model = defaultModelFor('w3')
    const set = walkTabsets(model.root)[0]!
    set.tabs = set.tabs.filter((t) => t.id !== 'chat')
    saveModel(model, workspaceKey('w3'))
    const loaded = loadModel(workspaceKey('w3'), () => defaultModelFor('w3'))
    expect(walkTabsets(loaded.model.root)[0]!.tabs.map((t) => t.id))
      .not.toContain('chat')
  })

  it('re-adds missing panels when no hidden list exists', () => {
    const model = defaultModelFor('w3') as unknown as Record<string, unknown>
    const set = walkTabsets(defaultModelFor('w3').root)[0]!
    set.tabs = set.tabs.filter((t) => t.id !== 'chat')
    localStorage.setItem(workspaceKey('w3'), JSON.stringify({
      version: 1, root: model.root
    }))
    const loaded = loadModel(workspaceKey('w3'), () => defaultModelFor('w3'))
    expect(walkTabsets(loaded.model.root)[0]!.tabs.map((t) => t.id))
      .toContain('chat')
  })

  it('recovers a corrupt model to the default', () => {
    localStorage.setItem(workspaceKey('w1'), '{bad')
    const loaded = loadModel(workspaceKey('w1'), () => defaultModelFor('w1'))
    expect(loaded.recovered).toBe(true)
    expect(walkTabsets(loaded.model.root).flatMap((t) => t.tabs).length)
      .toBeGreaterThan(3)
  })

  it('migrates the legacy model once, with a backup', () => {
    const legacy = defaultModelFor('w4')
    localStorage.setItem('t2.dock.v1', JSON.stringify(legacy))
    ensureMigrated()
    expect(localStorage.getItem(LEGACY_BACKUP_KEY)).toBeTruthy()
    expect(localStorage.getItem(WORKSPACE_MIGRATED_KEY)).toBe('1')
    expect(localStorage.getItem(WORKSPACE_ACTIVE_KEY)).toBe('w1')
    const w1 = loadModel(workspaceKey('w1'), () => defaultModelFor('w1'))
    const ids = walkTabsets(w1.model.root).flatMap((t) => t.tabs.map((x) => x.id))
    expect(ids).toEqual(expect.arrayContaining(['targets-intel', 'engagement']))
  })

  it('does not overwrite a newer w1 on migration', () => {
    localStorage.setItem('t2.dock.v1', JSON.stringify(defaultModelFor('w4')))
    saveModel(defaultModelFor('w1'), workspaceKey('w1'))
    ensureMigrated()
    const w1 = loadModel(workspaceKey('w1'), () => defaultModelFor('w1'))
    expect(walkTabsets(w1.model.root).flatMap((t) => t.tabs.map((x) => x.id)))
      .toEqual(expect.arrayContaining(['screen', 'processes']))
  })

  it('loads a valid active workspace only', () => {
    expect(loadActiveWorkspace()).toBe('w1')
    localStorage.setItem(WORKSPACE_ACTIVE_KEY, 'w4')
    expect(loadActiveWorkspace()).toBe('w4')
    localStorage.setItem(WORKSPACE_ACTIVE_KEY, 'w9')
    expect(loadActiveWorkspace()).toBe('w1')
  })

  it('has no unknown panel in defaults', () => {
    for (const id of ['w1', 'w2', 'w3', 'w4'] as const) {
      for (const tab of tabs(id)) expect(PANEL_IDS).toContain(tab)
    }
  })
})
