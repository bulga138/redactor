/**
 * REDACTOR — keeps credentials out of the model's context.
 *
 * Two layers:
 *   1. `ctx.tool.hook("execute.after")` — redacts the tool result in place, so
 *      the secret never reaches the model and (when OpenCode persists the hook's
 *      result) never reaches the session store either.
 *   2. `ctx.session.hook("context")` — safety net that redacts tool results in
 *      the outgoing messages, covering results stored before the plugin loaded
 *      or produced by tools that bypass the hook.
 *
 * Tool *inputs* are never rewritten: changing them would make the model believe
 * it ran a different command than it actually did.
 */
import { Plugin } from "@opencode/plugin"
import { redact } from "./redact.js"
import { getConfig } from "./config.js"

interface MutableContentPart {
  type: string
  text?: string
  result?: { type?: string; value?: unknown }
}

// Detects a reference to an env var / key / token whose *name* contains a
// secret-ish word (KEY, TOKEN, SECRET, PASSWORD, …). Used to guard outputs
// that echo such a variable even when the value itself has no recognisable
// format (e.g. `echo $API_KEY` printing an arbitrary password).
const SECRET_VAR_RE =
  /\$(?:\{)?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*(?:\})?|process\.env(?:\[['"]?[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*['"]?\]|\.[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)|os\.(?:getenv|environ(?:\.get)?)\(\s*['"][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*['"]\s*\)|\bgetenv\s*\(\s*['"][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*['"]\s*\)/i

export function referencesSecretVar(input: unknown): boolean {
  const text = typeof input === "string" ? input : JSON.stringify(input ?? "")
  return SECRET_VAR_RE.test(text)
}

// Extract the names of secret-named variables referenced in `input`, so the
// redacted marker can name them (the *name* is not a secret, only the value is).
export function secretVarNames(input: unknown): string[] {
  const text = typeof input === "string" ? input : JSON.stringify(input ?? "")
  const out = new Set<string>()
  const patterns: RegExp[] = [
    /\$\{?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)\}?/gi,
    /process\.env(?:\[['"]?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)['"]?\]|\.[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)/gi,
    /os\.(?:getenv|environ(?:\.get)?)\(\s*['"]([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)['"]\s*\)/gi,
    /\bgetenv\s*\(\s*['"]([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)['"]\s*\)/gi,
  ]
  for (const re of patterns) {
    re.lastIndex = 0
    for (const m of text.matchAll(re)) {
      const name = (m[1] ?? m[0]).replace(/^\$/, "").replace(/[{}]/g, "")
      if (name) out.add(name.toUpperCase())
    }
  }
  // Quoted identifier form (e.g. grep "API_KEY"): capture the whole quoted term.
  for (const m of text.matchAll(/["']([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*)["']/gi)) {
    out.add(m[1].toUpperCase())
  }
  return [...out]
}

// Detects a *quoted* identifier whose name contains a secret-ish word, e.g.
// `grep "API_KEY" src/`. The output of such a command is searched text that
// may contain real assignments, so we never destroy it wholesale — we only
// append the guidance note and rely on the value patterns below.
const SECRET_NAME_RE = /["'][^"']*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[^"']*["']/i

export function referencesSecretName(input: unknown): boolean {
  const text = typeof input === "string" ? input : JSON.stringify(input ?? "")
  return SECRET_NAME_RE.test(text)
}

export const NOTE =
  "\n\n[redactor] A credential or secret-named variable was involved. If you need to check or use an env var, key, or token, do not print its content - verify it is not null and use it directly."

export function appendNote(text: string, note: string = NOTE): string {
  return text.includes("[redactor]") ? text : text + note
}

export default Plugin.define({
  id: "redactor",
  async setup(ctx) {
    const cfg = getConfig()
    if (!cfg.enabled) {
      console.error("[redactor] disabled via config")
      return
    }
    const allow = cfg.allow

    const report = (tool: string, types: string[]) => {
      if (cfg.log) console.error(`[redactor] ${tool}: ${types.join(", ")}`)
    }

    const toolHook = await ctx.tool.hook("execute.after", async (event) => {
      if (cfg.skipTools.includes(event.tool)) return

      // Error text can carry the secret too ("invalid api key sk-…").
      if (event.status === "error") {
        const err = event.error as { message?: string }
        if (typeof err?.message === "string") {
          const r = redact(err.message, { allow })
          if (r.count) {
            err.message = r.output
            report(event.tool, r.types)
          }
          if (r.count || referencesSecretVar(event.input) || referencesSecretName(event.input)) {
            const names = secretVarNames(event.input)
            const noteText = names.length
              ? `\\n\\n[redactor] Secret-named variable(s) involved: ${names.join(", ")}. Do not print their values - verify they are non-null and use them directly.`
              : NOTE
            err.message = appendNote(err.message, noteText)
          }
        }
        return
      }

      const result = event.result as { content?: unknown; output?: unknown }
      if (!result) return

      let changed = false
      const types = new Set<string>()

      if (typeof result.content === "string") {
        const r = redact(result.content, { allow })
        if (r.count) {
          result.content = r.output
          changed = true
          r.types.forEach((t) => types.add(t))
        }
      } else if (Array.isArray(result.content)) {
        const next = result.content.map((part) => {
          if (part && part.type === "text" && typeof part.text === "string") {
            const r = redact(part.text, { allow })
            if (r.count) {
              r.types.forEach((t) => types.add(t))
              return { ...part, text: r.output }
            }
          }
          return part
        })
        if (types.size) {
          result.content = next
          changed = true
        }
      }

      if (typeof result.output === "string") {
        const r = redact(result.output, { allow })
        if (r.count) {
          result.output = r.output
          changed = true
          r.types.forEach((t) => types.add(t))
        }
      }

      // Guidance + (when safe) full redaction for secret-named variables.
      const inputRefsSecret = referencesSecretVar(event.input)
      const inputRefsName = referencesSecretName(event.input)
      const triggered = inputRefsSecret || inputRefsName

      // When a command references a secret-named variable (e.g. `echo $DB_PASSWORD`),
      // its output IS the secret. Redact the whole output so the value cannot leak,
      // but only when the output is short (a printed value) — multi-line output
      // such as `grep` results is preserved and handled by the patterns above.
      const contentText =
        typeof result.content === "string"
          ? result.content
          : Array.isArray(result.content)
            ? (result.content as MutableContentPart[])
                .map((p) => (p && p.type === "text" && typeof p.text === "string" ? p.text : ""))
                .join("\n")
            : ""
      const outputText = typeof result.output === "string" ? result.output : ""
      const combined = (contentText + "\n" + outputText).trim()
      const shortOutput = combined.length > 0 && combined.length <= 300

      if (inputRefsSecret && shortOutput) {
        const names = secretVarNames(event.input)
        const label = names.length ? `env_var_leak:${names.join(",")}` : "env_var_leak"
        const marker = `[REDACTED:${label}]`
        const note = names.length
          ? `\\n\\n[redactor] Secret-named variable(s) involved: ${names.join(", ")}. Do not print their values — verify they are non-null and use them directly.`
          : NOTE
        if (typeof result.content === "string") result.content = marker + note
        else if (Array.isArray(result.content)) {
          result.content = [{ type: "text", text: marker + note }]
        }
        if (typeof result.output === "string") result.output = marker + note
        changed = true
        types.add("env_var_leak")
        report(event.tool, [...types])
      } else if (changed || triggered) {
        const names = secretVarNames(event.input)
        const noteText = names.length
          ? `\\n\\n[redactor] Secret-named variable(s) involved: ${names.join(", ")}. Do not print their values - verify they are non-null and use them directly.`
          : NOTE
        if (typeof result.content === "string") result.content = appendNote(result.content, noteText)
        else if (Array.isArray(result.content)) {
          const parts = result.content as MutableContentPart[]
          const last = parts.length ? parts[parts.length - 1] : null
          if (last && last.type === "text" && typeof last.text === "string") {
            last.text = appendNote(last.text, noteText)
          } else {
            parts.push({ type: "text", text: noteText.trim() })
          }
        }
        if (typeof result.output === "string") result.output = appendNote(result.output, noteText)
        if (changed) report(event.tool, [...types])
        else report(event.tool, ["env_var_reference"])
      }
    })

    const contextHook = await ctx.session.hook("context", async (event) => {
      for (const message of event.messages) {
        const parts = message.content as unknown as MutableContentPart[]
        for (const part of parts) {
          if (part.type !== "tool-result" || !part.result) continue
          const value = part.result.value

          if (typeof value === "string") {
            const r = redact(value, { allow })
            if (r.count) part.result = { ...part.result, value: appendNote(r.output) }
            continue
          }

          if (Array.isArray(value)) {
            let touched = false
            const next = value.map((item) => {
              const c = item as { type?: string; text?: string }
              if (c && c.type === "text" && typeof c.text === "string") {
                const r = redact(c.text, { allow })
                if (r.count) {
                  touched = true
                  return { ...c, text: appendNote(r.output) }
                }
              }
              return item
            })
            if (touched) part.result = { ...part.result, value: next }
          }
        }
      }
    })

    return () => {
      void toolHook.dispose()
      void contextHook.dispose()
    }
  },
})
