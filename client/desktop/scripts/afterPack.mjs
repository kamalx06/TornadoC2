#!/usr/bin/env node
// Flip fuses on the packaged Electron binary.
import { join } from 'node:path'
import { flipFuses, FuseVersion, FuseV1Options } from '@electron/fuses'

export default async function afterPack(context) {
  const exe = {
    linux: 'tornadoc2-desktop',
    win32: 'TornadoC2.exe',
    darwin: 'TornadoC2.app/Contents/MacOS/TornadoC2'
  }[context.electronPlatformName]
  if (!exe) return
  const target = join(context.appOutDir, exe)
  await flipFuses(target, {
    version: FuseVersion.V1,
    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.WasmTrapHandlers]: true,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    strictlyRequireAllFuses: true
  })
  console.log(`  • fuses flipped  ${target}`)
}
