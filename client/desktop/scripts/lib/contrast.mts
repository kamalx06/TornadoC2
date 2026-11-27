// Pure WCAG contrast helpers used by the audit script and unit tests.

export type Pairs = 'dark' | 'light'

export interface Check {
  fg: string
  bg: string
  min: number
  why: string
}

export const CHECKS: Check[] = [
  { fg: 'text', bg: 'bg', min: 7, why: 'body copy on canvas' },
  { fg: 'text', bg: 'bg-panel', min: 7, why: 'body copy on pane' },
  { fg: 'text', bg: 'bg-raised', min: 4.5, why: 'body copy on raised row' },
  { fg: 'text', bg: 'bg-hover', min: 4.5, why: 'body copy on hover' },
  { fg: 'text-2', bg: 'bg-panel', min: 4.5, why: 'metadata' },
  { fg: 'text-3', bg: 'bg-panel', min: 4.5, why: 'hints' },
  { fg: 'text-3', bg: 'bg-sunken', min: 4.5, why: 'hints on terminal' },
  { fg: 'cyan', bg: 'bg-panel', min: 4.5, why: 'active accent' },
  { fg: 'green', bg: 'bg-panel', min: 4.5, why: 'live state' },
  { fg: 'red', bg: 'bg-panel', min: 4.5, why: 'danger state' },
  { fg: 'amber', bg: 'bg-panel', min: 4.5, why: 'warning state' },
  { fg: 'violet', bg: 'bg-panel', min: 4.5, why: 'elevated marker' },
  { fg: 'on-accent', bg: 'cyan', min: 4.5, why: 'primary button' },
  { fg: 'on-accent', bg: 'green', min: 4.5, why: 'success button' },
  { fg: 'on-accent', bg: 'red', min: 4.5, why: 'danger button' },
  { fg: 'cyan', bg: 'cyan-soft', min: 4.5, why: 'selected row' },
  { fg: 'green', bg: 'green-soft', min: 4.5, why: 'ok pill' },
  { fg: 'red', bg: 'red-soft', min: 4.5, why: 'error banner' },
  { fg: 'amber', bg: 'amber-soft', min: 4.5, why: 'warning banner' },
  { fg: 'violet', bg: 'violet-soft', min: 4.5, why: 'elevated pill' }
]

export function parseTheme(css: string, selector: string): Record<string, string> {
  const start = css.indexOf(selector)
  if (start < 0) throw new Error(`selector not found: ${selector}`)
  const open = css.indexOf('{', start)
  const close = css.indexOf('}', open)
  const out: Record<string, string> = {}
  for (const m of css.slice(open + 1, close).matchAll(/--([\w-]+)\s*:\s*(#[0-9a-f]{6})\b/gi)) {
    out[m[1]] = m[2].toLowerCase()
  }
  return out
}

export function channels(hex: string): [number, number, number] {
  if (!/^#[0-9a-f]{6}$/i.test(hex)) throw new Error(`bad hex: ${hex}`)
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number]
}

function linear(channel: number): number {
  const c = channel / 255
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

export function luminance(hex: string): number {
  const [r, g, b] = channels(hex).map(linear)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

export function ratio(fg: string, bg: string): number {
  const a = luminance(fg)
  const b = luminance(bg)
  const [hi, lo] = a >= b ? [a, b] : [b, a]
  return (hi + 0.05) / (lo + 0.05)
}

export interface Result extends Check {
  ratio: number
  pass: boolean
  fgHex?: string
  bgHex?: string
}

export function auditTheme(tokens: Record<string, string>): Result[] {
  return CHECKS.map((check) => {
    const fgHex = tokens[check.fg]
    const bgHex = tokens[check.bg]
    if (!fgHex || !bgHex) {
      return { ...check, ratio: 0, pass: false, fgHex, bgHex }
    }
    const value = ratio(fgHex, bgHex)
    return { ...check, ratio: value, pass: value >= check.min, fgHex, bgHex }
  })
}

export function format(result: Result): string {
  const state = result.pass ? 'PASS' : 'FAIL'
  return `${state} ${result.ratio.toFixed(2).padStart(6)} (min ${result.min}) ${result.fg} on ${result.bg} — ${result.why}`
}
