import { invoke } from '../hooks'

const COMMON = [
  'whoami', 'pwd', 'ls', 'info', 'ps', 'netstat', 'screenshot',
  'upload', 'download', 'sleep', 'kill', 'shell'
]

type Catalogue = { beacon?: string[]; categories?: Record<string, string[]> }

const cache = new Map<string, string[]>()

export async function verbsFor(os?: string): Promise<string[]> {
  const key = os || 'any'
  const hit = cache.get(key)
  if (hit) return hit
  let list: string[] = COMMON
  try {
    const r = await invoke<Catalogue>('commands', { target_os: os })
    const flat = [
      ...(r.beacon ?? []),
      ...Object.values(r.categories ?? {}).flat()
    ].filter((v): v is string => typeof v === 'string')
    if (flat.length) list = [...new Set([...COMMON, ...flat.sort()])]
  } catch {
    /* fall back to the common set */
  }
  cache.set(key, list)
  return list
}

export function matchVerbs(list: string[], prefix: string): string[] {
  const p = prefix.toLowerCase()
  if (!p) return list.slice(0, 40)
  return list.filter((v) => v.toLowerCase().startsWith(p)).slice(0, 40)
}
