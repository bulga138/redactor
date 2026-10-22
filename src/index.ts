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

      if (changed) report(event.tool, [...types])
    })

    const contextHook = await ctx.session.hook("context", async (event) => {
      for (const message of event.messages) {
        const parts = message.content as unknown as MutableContentPart[]
        for (const part of parts) {
          if (part.type !== "tool-result" || !part.result) continue
          const value = part.result.value

          if (typeof value === "string") {
            const r = redact(value, { allow })
            if (r.count) part.result = { ...part.result, value: r.output }
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
                  return { ...c, text: r.output }
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
