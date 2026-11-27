#!/usr/bin/env node
// Launch the packaged renderer under Chromium, resize it through CDP and
// fail on horizontal overflow or a missing gate card. Run under Xvfb.
import { spawn } from 'node:child_process'
import electron from 'electron'

const port = 9224
const child = spawn(electron, [
  'out/main/index.js', '--no-sandbox', `--remote-debugging-port=${port}`,
  '--ozone-platform=headless', '--disable-gpu'
], { stdio: 'inherit' })

const wait = (ms) => new Promise((r) => setTimeout(r, ms))
let ws
try {
  let page
  for (let i = 0; i < 80 && !page; i++) {
    await wait(250)
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json()
      page = list.find((t) => t.type === 'page')
    } catch { /* not up yet */ }
  }
  if (!page) throw new Error('devtools target never appeared')

  ws = new WebSocket(page.webSocketDebuggerUrl)
  let seq = 0
  const pending = new Map()
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data)
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id) }
  }
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j })
  const send = (method, params = {}) => new Promise((r) => {
    const id = ++seq
    pending.set(id, r)
    ws.send(JSON.stringify({ id, method, params }))
  })
  const evalJs = async (expression) =>
    (await send('Runtime.evaluate', { expression, returnByValue: true }))
      .result?.result?.value
  await send('Page.enable')
  await wait(1200)

  const cases = [
    [1280, 720, 1],
    [1440, 900, 1],
    [1920, 1080, 1],
    [720, 450, 2]
  ]
  let failed = 0
  for (const [width, height, scale] of cases) {
    await send('Emulation.setDeviceMetricsOverride', {
      width, height, deviceScaleFactor: 1, mobile: false
    })
    await send('Emulation.setPageScaleFactor', { pageScaleFactor: scale })
    await wait(220)
    const state = await evalJs(`(() => ({
      overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
      gate: Boolean(document.querySelector('.gate-card')),
      form: Boolean(document.querySelector('form.gate-card')),
      label: document.querySelector('.gate-card h2')?.textContent
    }))()`)
    const ok = state && !state.overflow && state.gate && state.form && state.label === 'Start a session'
    console.log(`${ok ? 'PASS' : 'FAIL'} ${width}x${height} @${scale * 100}%`, state)
    if (!ok) failed++
  }
  if (failed) process.exitCode = 1
} catch (err) {
  console.error(err)
  process.exitCode = 1
} finally {
  try { ws?.close() } catch { /* ignore */ }
  child.kill('SIGTERM')
}
