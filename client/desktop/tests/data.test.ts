import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  parseConnections, parseEntries, parseProcesses
} from '../src/renderer/src/lib/data'

const f = (name: string): string =>
  readFileSync(`tests/fixtures/data/${name}`, 'utf8')

describe('process parser', () => {
  it('reads PID-first Linux output', () => {
    const p = parseProcesses(f('ps-linux.txt'))
    expect(p).toHaveLength(4)
    expect(p[0]).toEqual({
      pid: 1, name: 'init', cmd: '/sbin/init splash'
    })
  })

  it('reads name-first Windows output', () => {
    const p = parseProcesses(f('ps-windows.txt'))
    expect(p[2]).toEqual({ pid: 4412, name: 'explorer.exe', cmd: 'explorer.exe' })
  })

  it('survives junk and caps', () => {
    expect(parseProcesses('')).toEqual([])
    expect(parseProcesses('nonsense\nfoo bar\n2 x')).toEqual([
      { pid: 2, name: 'x', cmd: 'x' }
    ])
  })
})

describe('connection parser', () => {
  it('parses Linux rows without PID', () => {
    const c = parseConnections(f('netstat-linux.txt'))
    expect(c).toHaveLength(3)
    expect(c[2]).toEqual({
      proto: 'udp', local: '10.0.0.5:53', remote: '8.8.8.8:53',
      state: 'ESTABLISHED', pid: undefined
    })
  })

  it('parses Windows rows with PID', () => {
    const c = parseConnections(f('netstat-windows.txt'))
    expect(c[1]?.pid).toBe(4412)
  })

  it('drops malformed rows', () => {
    expect(parseConnections('tcp nope\nfoo 1 2 3')).toEqual([])
  })
})

describe('directory parser', () => {
  it('lists direct children with type and sorted dirs first', () => {
    const e = parseEntries(f('find-dirs.txt'), f('find-files.txt'), '/var/www')
    expect(e.map((x) => x.name)).toEqual(['site', 'robots.txt'])
    expect(e[1]?.dir).toBe(false)
    expect(e[0]?.dir).toBe(true)
  })

  it('merges file output and ignores depth', () => {
    const e = parseEntries('', '/var/www/a.txt\n/var/www/sub/b.txt', '/var/www')
    expect(e).toEqual([{ path: '/var/www/a.txt', name: 'a.txt', dir: false }])
  })

  it('handles a trailing slash base and junk', () => {
    expect(parseEntries('', '/tmp/a', '/tmp/')).toEqual([
      { path: '/tmp/a', name: 'a', dir: false }
    ])
    expect(parseEntries('', '///', '///')).toEqual([])
  })
})

describe('path helpers', () => {
  it('walks up posix and windows roots', async () => {
    const { parentPath } = await import('../src/renderer/src/lib/data')
    expect(parentPath('/var/www/site')).toBe('/var/www')
    expect(parentPath('/var')).toBe('/')
    expect(parentPath('/')).toBe('/')
    expect(parentPath('C:/Users/alice')).toBe('C:/Users')
    expect(parentPath('C:/')).toBe('C:\\')
  })

  it('builds crumbs without losing the drive', async () => {
    const { crumbs } = await import('../src/renderer/src/lib/data')
    expect(crumbs('/var/www').map((c) => c.path))
      .toEqual(['/var', '/var/www'])
    expect(crumbs('C:/Users/alice').map((c) => c.path))
      .toEqual(['C:/Users', 'C:/Users/alice'])
  })
})
