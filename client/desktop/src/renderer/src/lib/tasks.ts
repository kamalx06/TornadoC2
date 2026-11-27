import { invoke } from '../hooks'
import { pushTask } from './events'

export type TaskResult = { output: string; error?: string }

function decode(s: string): string {
  try {
    const raw = atob(s)
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return s
  }
}

/** Queue a verb and poll for one result. `signal` abandons local polling. */
export async function runVerb(
  id: number,
  verb: string,
  args: string[] = [],
  signal?: AbortSignal,
  timeoutMs = 60_000
): Promise<TaskResult> {
  pushTask(`→ ${verb}${args.length ? ` ${args.join(' ')}` : ''} on #${id}`)
  const r = (await invoke('task', { id, verb, args })) as { task_id?: string }
  if (!r.task_id) throw new Error(`${verb}: not queued`)
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
    const res = (await invoke('task.result', {
      id, taskId: r.task_id, wait: 2
    })) as { ready?: boolean; output?: string; error?: string }
    if (res.ready) {
      pushTask(res.error ? `✗ ${verb} on #${id}: ${res.error}`
        : `✓ ${verb} on #${id}`, res.error ? 'err' : 'task')
      return { output: decode(res.output ?? ''), error: res.error }
    }
  }
  pushTask(`✗ ${verb} on #${id}: timed out`, 'err')
  throw new Error(`${verb}: timed out`)
}
