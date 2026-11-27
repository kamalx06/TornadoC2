#!/usr/bin/env node
// Fail when the renderer grows past its reviewed budget, or leaks a
// source map / oversized asset into the package.
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('../out/renderer', import.meta.url).pathname
const LIMITS = {
  entry: 140 * 1024,
  chunk: 620 * 1024,
  jsTotal: 1250 * 1024,
  css: 60 * 1024,
  assets: 1500 * 1024
}

type File = { rel: string; size: number }
const files: File[] = []
function walk(dir: string, rel = ''): void {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    const r = join(rel, name)
    if (statSync(path).isDirectory()) walk(path, r)
    else files.push({ rel: r, size: statSync(path).size })
  }
}
walk(root)

let failed = 0
const fail = (msg: string): void => { console.error(`FAIL ${msg}`); failed++ }

const maps = files.filter((f) => f.rel.endsWith('.map'))
if (maps.length) fail(`${maps.length} source map(s) in output`)

const js = files.filter((f) => f.rel.endsWith('.js'))
const css = files.filter((f) => f.rel.endsWith('.css'))
if (!js.length) fail('no javascript output')

const entry = js.find((f) => /(^|\/)index-[\w-]+\.js$/.test(f.rel))
if (!entry) fail('entry chunk missing')
else if (entry.size > LIMITS.entry) {
  fail(`entry ${entry.rel} ${entry.size} > ${LIMITS.entry}`)
}

for (const f of js) {
  if (f === entry) continue
  if (f.size > LIMITS.chunk) fail(`chunk ${f.rel} ${f.size} > ${LIMITS.chunk}`)
}
const jsTotal = js.reduce((n, f) => n + f.size, 0)
if (jsTotal > LIMITS.jsTotal) fail(`js total ${jsTotal} > ${LIMITS.jsTotal}`)
const cssTotal = css.reduce((n, f) => n + f.size, 0)
if (cssTotal > LIMITS.css) fail(`css ${cssTotal} > ${LIMITS.css}`)
const assets = files.reduce((n, f) => n + f.size, 0)
if (assets > LIMITS.assets) fail(`assets ${assets} > ${LIMITS.assets}`)

for (const f of [...js].sort((a, b) => b.size - a.size).slice(0, 8)) {
  console.log(` ${(f.size / 1024).toFixed(1).padStart(8)} KB  ${f.rel}`)
}
console.log(`\njs ${(jsTotal / 1024).toFixed(1)} KB · css ${(cssTotal / 1024).toFixed(1)} KB · assets ${(assets / 1024).toFixed(1)} KB`)
if (failed) { console.error(`\nbudget: ${failed} failure(s)`); process.exit(1) }
console.log('budget: ok')
