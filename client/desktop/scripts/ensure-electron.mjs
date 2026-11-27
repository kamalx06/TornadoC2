#!/usr/bin/env node
// Electron 42+ downloads its binary on first `npx electron`, but
// electron-vite resolves the path before that. Run this from
// `postinstall` and again before `dev`/`build` so a fresh clone works.
import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'

const pkg = join(process.cwd(), 'node_modules', 'electron')
const bin = join(pkg, 'dist', process.platform === 'win32'
  ? 'electron.exe' : 'electron')
const marker = join(pkg, 'path.txt')

if (existsSync(bin) || existsSync(marker)) process.exit(0)
if (!existsSync(pkg)) {
  console.error('[ensure-electron] electron package missing; run npm ci')
  process.exit(1)
}

console.log('[ensure-electron] fetching the Electron binary once')
const r = spawnSync(process.execPath, [join(pkg, 'install.js')], {
  stdio: 'inherit'
})
if (r.status !== 0) {
  console.error('[ensure-electron] download failed; re-run `npm run setup`')
  process.exit(r.status ?? 1)
}
