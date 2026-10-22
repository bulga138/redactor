import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export interface Config {
  /** Master switch. */
  enabled: boolean
  /** Tool names whose output is left untouched. */
  skipTools: string[]
  /** Literal values that survive redaction (test keys, public ids…). */
  allow: string[]
  /** Log every redaction to the OpenCode server log. */
  log: boolean
  /** Replace the whole output when a command reads a secret-bearing file. */
  redactSecretFiles: boolean
  /** File-name patterns (basename, `*`/`?` wildcards) treated as secret-bearing. */
  secretPaths: string[]
  /** File-name patterns exempt from the path check (templates, examples). */
  allowPaths: string[]
}

export const DEFAULTS: Config = {
  enabled: true,
  skipTools: [],
  allow: [],
  log: false,
  redactSecretFiles: true,
  secretPaths: [
    '.env',
    '.env.*',
    '*.env',
    '*.pem',
    '*.key',
    '*.p12',
    '*.pfx',
    'id_rsa',
    'id_ed25519',
    'credentials',
    '.npmrc',
    '.pypirc',
    '.netrc',
    'kubeconfig',
  ],
  allowPaths: [
    '.env.example',
    '.env.template',
    '.env.sample',
    '.env.dist',
    'example.env',
    '*.example',
    '*.template',
    '*.sample',
  ],
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name]
  if (raw === undefined) return fallback
  return !/^(0|false|no|off)$/i.test(raw.trim())
}

function envList(name: string): string[] {
  const raw = process.env[name]
  if (!raw) return []
  return raw
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
}

function sanitize(raw: Partial<Config> | undefined): Partial<Config> {
  if (!raw) return {}
  return {
    ...(typeof raw.enabled === 'boolean' ? { enabled: raw.enabled } : {}),
    ...(Array.isArray(raw.skipTools) ? { skipTools: raw.skipTools } : {}),
    ...(Array.isArray(raw.allow) ? { allow: raw.allow } : {}),
    ...(typeof raw.log === 'boolean' ? { log: raw.log } : {}),
    ...(typeof raw.redactSecretFiles === 'boolean'
      ? { redactSecretFiles: raw.redactSecretFiles }
      : {}),
    ...(Array.isArray(raw.secretPaths) ? { secretPaths: raw.secretPaths } : {}),
    ...(Array.isArray(raw.allowPaths) ? { allowPaths: raw.allowPaths } : {}),
  }
}

function fromFile(path: string): Partial<Config> {
  if (!existsSync(path)) return {}
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<Config>
    return sanitize(raw)
  } catch {
    return {}
  }
}

let cached: Config | undefined

/**
 * Resolve config: defaults < global file < plugin options < project file < env.
 * `options` are the plugin options OpenCode passes through `ctx.options`
 * (e.g. `"plugin": { "@bulga138/redactor": { … } }` in opencode.json).
 */
export function getConfig(options?: Record<string, unknown>): Config {
  if (cached) return cached

  const global = fromFile(join(homedir(), '.config', 'redactor', 'config.json'))
  const project = fromFile(join(process.cwd(), '.redactor', 'config.json'))
  const opts = sanitize(options as Partial<Config> | undefined)

  cached = {
    ...DEFAULTS,
    ...global,
    ...opts,
    ...project,
    enabled: envBool(
      'REDACTOR_ENABLED',
      project.enabled ?? opts.enabled ?? global.enabled ?? DEFAULTS.enabled
    ),
    skipTools: envList('REDACTOR_SKIP_TOOLS').length
      ? envList('REDACTOR_SKIP_TOOLS')
      : [...(global.skipTools ?? []), ...(opts.skipTools ?? []), ...(project.skipTools ?? [])],
    allow: envList('REDACTOR_ALLOW').length
      ? envList('REDACTOR_ALLOW')
      : [...(global.allow ?? []), ...(opts.allow ?? []), ...(project.allow ?? [])],
    log: envBool('REDACTOR_LOG', project.log ?? opts.log ?? global.log ?? DEFAULTS.log),
    redactSecretFiles: envBool(
      'REDACTOR_REDACT_SECRET_FILES',
      project.redactSecretFiles ??
        opts.redactSecretFiles ??
        global.redactSecretFiles ??
        DEFAULTS.redactSecretFiles
    ),
    // Additive: the defaults always apply, the lists only add to them.
    secretPaths: [
      ...DEFAULTS.secretPaths,
      ...(global.secretPaths ?? []),
      ...(opts.secretPaths ?? []),
      ...(project.secretPaths ?? []),
      ...envList('REDACTOR_SECRET_PATHS'),
    ],
    allowPaths: [
      ...DEFAULTS.allowPaths,
      ...(global.allowPaths ?? []),
      ...(opts.allowPaths ?? []),
      ...(project.allowPaths ?? []),
      ...envList('REDACTOR_ALLOW_PATHS'),
    ],
  }
  return cached
}

/** Test helper. */
export function resetConfig(): void {
  cached = undefined
}
