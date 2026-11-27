#!/usr/bin/env node
// Flip Electron fuses on a packaged binary. Run after electron-builder.
import { flipFuses, FuseVersion, FuseV1Options } from '@electron/fuses'

const target = process.argv[2]
if (!target) {
  console.error('usage: node scripts/fuses.mjs <path-to-electron-binary>')
  process.exit(2)
}

await flipFuses(target, {
  version: FuseVersion.V1,
  [FuseV1Options.RunAsNode]: false,
  [FuseV1Options.EnableCookieEncryption]: true,
  [FuseV1Options.WasmTrapHandlers]: true,
  [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
  LoadBrowserProcessSpecificV8Snapshot]: false,
  [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
  [FuseV1Options.EnableNodeCliInspectArguments]: false,
  [FuseV1Options.OnlyLoadAppFromAsar]: true,
  [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
  strictlyRequireAllFuses: true
})
console.log(`fused ${target}`)
