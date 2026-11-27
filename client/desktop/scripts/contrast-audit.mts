#!/usr/bin/env node
// Fails when a text token drops below WCAG AA on its surface, or when a
// renderer file hard-codes a colour instead of using a token.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { auditTheme, format, luminance, parseTheme } from './lib/contrast.mts'

const root = fileURLToPath(new URL('..', import.meta.url))
const tokensFile = join(root, 'src/renderer/src/styles/tokens.css')
const renderer = join(root, 'src/renderer/src')
const css = readFileSync(tokensFile, 'utf8')

let failed = 0
for (const [theme, selector] of [
  ['dark', ':root'],
  ["light", "html[data-theme='light']"]
] as const) {
  const tokens = parseTheme(css, selector)
  const results = auditTheme(tokens)
  console.log(`\n${theme}`)
  for (const r of results) {
    console.log(' ' + format(r))
    if (!r.pass) failed++
  }
  if (theme === 'dark' && luminance(tokens.bg) > 0.01) {
    console.error(` FAIL canvas ${tokens.bg} is not pitch black`)
    failed++
  }
  if (theme === 'light' && luminance(tokens.bg) < 0.8) {
    console.error(` FAIL canvas ${tokens.bg} is not light`)
    failed++
  }
}

const hex = /#[0-9a-f]{3,8}\b/gi
const offenders: string[] = []
function walk(dir: string): void {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) {
      walk(path)
      continue
    }
    if (!/\.(tsx?|css)$/.test(name) || path.endsWith('tokens.css')) continue
    readFileSync(path, 'utf8').split('\n').forEach((line, i) => {
      for (const m of line.matchAll(hex)) {
        offenders.push(`${path.slice(root.length)}:${i + 1} ${m[0]}`)
      }
    })
  }
}
walk(renderer)

if (offenders.length) {
  console.error(`\nraw colours outside tokens.css (${offenders.length}):`)
  for (const o of offenders) console.error(' ' + o)
  failed += offenders.length
}

console.log(failed ? `\ncontrast: ${failed} failure(s)` : '\ncontrast: all pairs pass')
process.exit(failed ? 1 : 0)
