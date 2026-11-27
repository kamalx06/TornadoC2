import { z } from 'zod'

/** Protocol version between renderer, preload and main. */
export const PROTO = 1

export const methodSchema = z.enum([
  'hello',
  'ping',
  'status',
  'connect',
  'disconnect',
  'capabilities',
  'events',
  'beacons',
  'task',
  'task.result',
  'beacon.alias',
  'beacon.tag',
  'beacon.forget',
  'listener.start',
  'listener.probe',
  'listener.stop',
  'jump',
  'evidence.add',
  'finding.add',
  'bulk',
  'ai.ask',
  'job.list',
  'job.cancel',
  'upload.start',
  'download.start',
  'build.start',
  'build.options',
  'build.validate',
  'build.profiles',
  'build.config.import',
  'shell',
  'socks',
  'bof.run',
  'assembly.run',
  'creds.list',
  'creds.reveal',
  'audit.verify',
  'ai.config.get',
  'ai.config.set',
  'listeners',
  'listeners.health',
  'listeners.get',
  'listeners.certs',
  'listeners.profiles',
  'listener.create',
  'listener.update',
  'listener.delete',
  'chat.history',
  'chat.send',
  'beacon.note',
  'loot.list',
  'armory.installed',
  'armory.list',
  'armory.info',
  'armory.install',
  'armory.uninstall',
  'armory.update',
  'identify',
  'model',
  'timeline',
  'audit',
  'report',
  'evidence',
  'export.ioc',
  'export.stix',
  'graph',
  'commands'
])
export type Method = z.infer<typeof methodSchema>

export const paramsSchema = z.record(z.string(), z.unknown()).default({})

export const requestSchema = z.object({
  method: methodSchema,
  params: paramsSchema,
  timeoutMs: z.number().int().positive().max(15 * 60_000).optional()
})
export type Request = z.infer<typeof requestSchema>

export const responseSchema = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(true), result: z.unknown() }),
  z.object({
    ok: z.literal(false),
    error: z.string(),
    code: z.string().optional()
  })
])
export type Response = z.infer<typeof responseSchema>

export const eventSchema = z.object({
  event: z.string(),
  data: z.unknown()
})

export const connectResultSchema = z.object({
  name: z.string(),
  role: z.string(),
  host: z.string(),
  port: z.number(),
  caps: z.array(z.string())
})
export type ConnectResult = z.infer<typeof connectResultSchema>

export const beaconSchema = z.object({
  id: z.number(),
  display_name: z.string().optional(),
  alias: z.string().optional(),
  os: z.string().optional(),
  arch: z.string().optional(),
  alive: z.boolean().optional(),
  last_seen_age: z.number().optional(),
  privilege: z.string().optional(),
  elevated: z.boolean().optional(),
  integrity: z.string().optional(),
  parent_name: z.string().optional(),
  fingerprint: z.string().optional(),
  checkins: z.number().optional(),
  last_addr: z.string().optional(),
  sleep_interval: z.number().optional(),
  viewers: z.array(z.object({ name: z.string() })).optional()
})
export type Beacon = z.infer<typeof beaconSchema>

export const statusSchema = z.object({
  connected: z.boolean(),
  config: z.string(),
  operator: z.string().optional(),
  role: z.string().optional(),
  caps: z.array(z.string()).optional()
})
export type Status = z.infer<typeof statusSchema>

/** Channel names used by preload → renderer. */
export const EVENTS = ['log', 'conn'] as const
export type EventName = (typeof EVENTS)[number]

export const listenerSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  type: z.string().optional(),
  host: z.string().optional(),
  port: z.union([z.number(), z.string()]).optional(),
  status: z.string().optional(),
  tls: z.string().optional(),
  profiles: z.array(z.string()).optional(),
  created_by: z.string().optional(),
  error_message: z.string().optional(),
  health: z.enum(['unknown', 'ok', 'degraded', 'down']).optional(),
  cert_days_left: z.number().optional()
})
export type Listener = z.infer<typeof listenerSchema>

export const healthRowSchema = listenerSchema.extend({
  last_ok: z.number().optional(),
  last_error: z.string().optional(),
  probe_ms: z.number().optional(),
  history: z.array(z.object({
    ts: z.number(), state: z.string(),
    error: z.string().optional(), ms: z.number().optional()
  })).optional()
})
export type HealthRow = z.infer<typeof healthRowSchema>

export const findingSchema = z.object({
  id: z.number(), ts: z.number(), title: z.string(),
  severity: z.string(), host: z.string(), detail: z.string(),
  by: z.string(), evidence: z.array(z.string()).optional()
})
export const entitySchema = z.object({
  id: z.number(), ts: z.number(), host: z.string().optional(),
  user: z.string().optional(), name: z.string().optional(),
  kind: z.string().optional(), access: z.string().optional(),
  state: z.string().optional(), sha256: z.string().optional(),
  size: z.number().optional(), detail: z.string().optional(),
  by: z.string().optional()
})
export const timelineSchema = z.object({
  ts: z.number(), kind: z.string(), text: z.string(), by: z.string()
})
export const modelSchema = z.object({
  schema: z.number().optional(),
  dataset: z.string().optional(),
  hosts: z.array(z.object({
    hostname: z.string().optional(), machine_id: z.string().optional(),
    os: z.string().optional(), arch: z.string().optional(),
    user: z.string().optional(), privilege: z.string().optional(),
    beacon_id: z.number().optional()
  })).optional(),
  users: z.array(entitySchema).optional(),
  shares: z.array(entitySchema).optional(),
  services: z.array(entitySchema).optional(),
  evidence: z.array(entitySchema).optional(),
  findings: z.array(findingSchema).optional(),
  timeline: z.array(timelineSchema).optional(),
  mitre: z.array(z.object({
    tactic: z.string(), technique: z.string(), kind: z.string()
  })).optional()
})
export type Model = z.infer<typeof modelSchema>

export const auditRowSchema = z.object({
  id: z.string().optional(), ts: z.string().optional(),
  operator: z.string().optional(), action: z.string().optional(),
  target: z.string().optional(), outcome: z.string().optional(),
  detail: z.string().optional()
})
export type AuditRow = z.infer<typeof auditRowSchema>

export const chatMessageSchema = z.object({
  id: z.number().optional(), ts: z.number().optional(),
  operator: z.string().optional(), text: z.string().optional(),
  kind: z.string().optional()
})
export type ChatMessage = z.infer<typeof chatMessageSchema>

export const graphSchema = z.object({
  nodes: z.array(z.object({
    id: z.number(), user: z.string().optional(),
    privilege: z.string().optional(), hostname: z.string().optional(),
    name: z.string().optional(), os: z.string().optional(),
    arch: z.string().optional(), domain: z.string().optional(),
    subnet: z.string().optional(), ports: z.array(z.string()).optional(),
    alive: z.boolean().optional(), elevated: z.boolean().optional(),
    age: z.number().optional(), checkins: z.number().optional(),
    fingerprint: z.string().optional(), pid: z.number().optional(),
    parent_pid: z.number().optional(), parent_name: z.string().optional(),
    parent_id: z.number().nullable().optional(),
    integrity: z.string().optional(), groups: z.array(z.string()).optional()
  })),
  edges: z.array(z.object({
    from: z.number(), to: z.number(),
    shared: z.array(z.string()).optional()
  })),
  groups: z.record(z.string(), z.record(z.string(), z.array(z.number()))).optional(),
  generated: z.number().optional()
})
export type Graph = z.infer<typeof graphSchema>

export const certListSchema = z.object({
  certs: z.array(z.string()).default([]),
  keys: z.array(z.string()).default([]),
  cas: z.array(z.string()).default([])
})
export const profileListSchema = z.object({
  profiles: z.array(z.object({
    name: z.string(), description: z.string().optional()
  })).default([])
})

export const credSchema = z.object({
  id: z.string(), user: z.string().optional(), domain: z.string().optional(),
  kind: z.string().optional(), value: z.string().optional(),
  source_beacon: z.number().optional(), found_by: z.string().optional(),
  validation_status: z.string().optional(), notes: z.string().optional()
})
export type Cred = z.infer<typeof credSchema>
