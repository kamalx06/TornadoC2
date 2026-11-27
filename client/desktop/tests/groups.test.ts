import { describe, expect, it } from 'vitest'
import { GROUPS, GROUP_IDS, groupOf } from '../src/renderer/src/workspace/groups'
import { PANEL_IDS } from '../src/renderer/src/workspace/panels'

describe('panel groups', () => {
  it('places every leaf in exactly one group', () => {
    const seen = new Map<string, string>()
    for (const id of GROUP_IDS) {
      for (const panel of GROUPS[id].panels) {
        expect(seen.has(panel), `${panel} duplicated`).toBe(false)
        seen.set(panel, id)
      }
    }
    expect([...seen.keys()].sort()).toEqual([...PANEL_IDS].sort())
  })

  it('resolves the owning group', () => {
    expect(groupOf('terminal')).toBe('host')
    expect(groupOf('settings')).toBe('system')
  })
})
