# REDACTOR

**Keeps credentials out of your model's context.** An [OpenCode](https://opencode.ai) V2 plugin.

Every tool result — file reads, shell output, web fetches, MCP payloads — is scanned for
credential-shaped strings and the secret is replaced with `[REDACTED:type]` *before* the model
sees it. The model still gets the surrounding context, never the key.

```diff
- export const key = "sk-proj-abc123…"
+ export const key = "[REDACTED:sk_key]"
```

## Why

A secret that reaches the model is a secret that reaches the provider, the session log, every
compaction summary, and every future turn. Re-reading the file does not help — the model already
has the value. REDACTOR removes it at the source.

## Install

```jsonc
// opencode.json
{
  "plugins": ["@bulga138/redactor"]
}
```

Requires OpenCode 2.x (the V2 plugin API).

## How it works

1. `ctx.tool.hook("execute.after")` — rewrites the tool result in place: the secret never reaches
   the model, and OpenCode persists the already-redacted result.
2. `ctx.session.hook("context")` — safety net for results stored before the plugin loaded or
   produced by tools that bypass the hook. Only tool results are touched; your prompts and the
   model's own text are left alone.

Tool **inputs** are never rewritten — changing them would make the model believe it ran a
different command than it actually ran.

## What it catches

| Family | Examples |
| --- | --- |
| Cloud | `AKIA…`/`ASIA…`, `aws_secret_access_key=…`, Azure `AccountKey=…` |
| Model providers | `sk-…`, `sk-proj-…`, `sk-or-v1-…` (OpenRouter), `AIza…` (Gemini), `GOCSPX-…` |
| VCS | `ghp_`/`gho_`/`ghs_`/`ghr_`/`github_pat_…`, `glpat-…` |
| SaaS | Slack `xox…`, Stripe `sk_live_…`, npm `npm_…`, HuggingFace `hf_…`, Twilio, Telegram bot tokens, Sentry DSN, Discord webhooks |
| Transport | `Authorization: Bearer …`, `postgres://user:pass@…`, `https://user:pass@…` |
| Generic | `api_key=…`, `"client_secret": "…"`, `FOO_TOKEN=…`, PEM private key blocks, JWTs |

Matches are replaced with `[REDACTED:{type}]`, so the model can still see that *a* credential was
there and which kind it was.

**Precision over recall:** obvious placeholders (`your-api-key-here`, `sk-EXAMPLE…`, `changeme`,
`xxx`) are left untouched, and generic assignment matching needs a long enough value to fire.

## Configuration

Env vars (highest priority):

| Var | Default | Description |
| --- | --- | --- |
| `REDACTOR_ENABLED` | `true` | Master switch. |
| `REDACTOR_SKIP_TOOLS` | – | Comma-separated tool names whose output is not touched (e.g. `read`). |
| `REDACTOR_ALLOW` | – | Comma-separated literal values that survive redaction (your test keys). |
| `REDACTOR_LOG` | `false` | Log every redaction to the OpenCode server log. |

Config file at `~/.config/redactor/config.json` (or `.redactor/config.json` in the project, which
wins):

```json
{
  "enabled": true,
  "skipTools": ["read"],
  "allow": ["test_key_123"],
  "log": false
}
```

## Limitations

- A secret already in the model's context stays there (start a new session to drop it).
- Tool inputs are not rewritten (see above).
- A secret split across two tool calls is not detected — this is not a DLP product.

## License

MIT
