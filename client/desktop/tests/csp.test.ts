import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const html = readFileSync('src/renderer/index.html', 'utf8')
const security = readFileSync('src/main/security.ts', 'utf8')

function csp(source: string): string {
  const m = source.match(/Content-Security-Policy[^]*?content="([^"]+)"/) ??
    source.match(/const CSP = \[([^]*?)\]\.join/)
  expect(m).toBeTruthy()
  return m![1]!
}

describe('CSP', () => {
  for (const [name, src] of [['meta', html], ['header', security]] as const) {
    it(`${name} denies by default and pins sources`, () => {
      const policy = csp(src)
      expect(policy).toContain("default-src 'none'")
      expect(policy).toContain("script-src 'self'")
      expect(policy).toContain("style-src 'self' 'unsafe-inline'")
      expect(policy).toContain("img-src 'self' data:")
      expect(policy).toContain("connect-src 'self'")
      expect(policy).toContain("base-uri 'none'")
      expect(policy).not.toContain("'unsafe-eval'")
    })
  }

  it('blocks plugins and form posts', () => {
    expect(security).toContain("object-src 'none'")
    expect(security).toContain("form-action 'none'")
  })
})
