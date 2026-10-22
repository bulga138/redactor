import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

export interface Config {
  /** Master switch. */
  enabled: boolean
  /** Tool names whose output is left untouched. */
  skipTools: string[]
  /** Literal values that survive redaction (test keys, public ids…). */
  allow: string[]
  /** Log every redaction to the OpenCode server log. */
  log: boolean
}

const DEFAULTS: Config = {
  enabled: true,
  skipTools: [],
  allow: [],
  log: false,
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
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

function fromFile(path: string): Partial<Config> {
  if (!existsSync(path)) return {}
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<Config>
    return {
      ...(typeof raw.enabled === "boolean" ? { enabled: raw.enabled } : {}),
      ...(Array.isArray(raw.skipTools) ? { skipTools: raw.skipTools } : {}),
      ...(Array.isArray(raw.allow) ? { allow: raw.allow } : {}),
      ...(typeof raw.log === "boolean" ? { log: raw.log } : {}),
    }
  } catch {
    return {}
  }
}

let cached: Config | undefined

/** Resolve config: defaults < global file < project file < env. */
export function getConfig(): Config {
  if (cached) return cached

  const global = fromFile(join(homedir(), ".config", "redactor", "config.json"))
  const project = fromFile(join(process.cwd(), ".redactor", "config.json"))

  cached = {
    ...DEFAULTS,
    ...global,
    ...project,
    enabled: envBool("REDACTOR_ENABLED", global.enabled ?? project.enabled ?? DEFAULTS.enabled),
    skipTools: envList("REDACTOR_SKIP_TOOLS").length
      ? envList("REDACTOR_SKIP_TOOLS")
      : [...(global.skipTools ?? []), ...(project.skipTools ?? [])],
    allow: envList("REDACTOR_ALLOW").length
      ? envList("REDACTOR_ALLOW")
      : [...(global.allow ?? []), ...(project.allow ?? [])],
    log: envBool("REDACTOR_LOG", global.log ?? project.log ?? DEFAULTS.log),
  }
  return cached
}

/** Test helper. */
export function resetConfig(): void {
  cached = undefined
}
