// The panel inventory is the no-loss contract. It must cover every
// registered panel exactly once, with the same capability. New panels
// are allowed in the inventory before they exist in code, but must be
// marked `new` so a future registry move cannot silently pass.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { PANELS, PANEL_IDS } from '../src/renderer/src/workspace/panels'

type Row = {
  id: string
  cap: string | null
  preserve: boolean
  new?: boolean
  workspace: number
  component: string
}

const path = join(
  process.cwd(), '../../docs/design/panel-inventory.json')
const doc = JSON.parse(readFileSync(path, 'utf8')) as {
  version: number
  rule: string
  panels: Row[]
}

describe('panel inventory', () => {
  it('is versioned and carries the preserve rule', () => {
    expect(doc.version).toBe(1)
    expect(doc.rule).toContain('remain reachable')
  })

  it('has unique ids and preserve=true', () => {
    const seen = new Set<string>()
    for (const row of doc.panels) {
      expect(seen.has(row.id), row.id).toBe(false)
      seen.add(row.id)
      expect(row.preserve, row.id).toBe(true)
      expect([1, 2, 3, 4]).toContain(row.workspace)
      expect(row.component.endsWith('.tsx'), row.id).toBe(true)
    }
  })

  it('covers every registered panel with the same capability', () => {
    const byId = new Map(doc.panels.map((r) => [r.id, r]))
    for (const id of PANEL_IDS) {
      const row = byId.get(id)
      expect(row, `${id} missing from inventory`).toBeDefined()
      expect(row!.cap, id).toBe(PANELS[id].cap ?? null)
    }
  })

  it('marks unregistered inventory rows as new', () => {
    for (const row of doc.panels) {
      if (!PANEL_IDS.includes(row.id as (typeof PANEL_IDS)[number])) {
        expect(row.new, `${row.id} is not registered but not marked new`)
          .toBe(true)
      }
    }
  })
})
