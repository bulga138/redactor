/**
 * REDACTOR secret redaction
 *
 * Replaces credential-shaped text with [REDACTED:{type}] so the surrounding
 * context survives but the secret does not.
 *
 * The pattern set is deliberately high-precision: a secret that is not redacted
 * leaks, but a false positive corrupts output the model needs. Generic
 * assignment matching therefore requires a long enough value, and obvious
 * placeholders ("your-key-here", "changeme") are left alone.
 *
 * Pattern group convention:
 *   'whole'   — the whole match is the secret.
 *   'prefix'  — group 1 is kept, group 2 is the secret, group 3 (optional) is kept.
 */

export interface RedactionResult {
  output: string
  count: number
  types: string[]
}

export interface RedactOptions {
  /** Literal values that must survive redaction (e.g. a test key you use). */
  allow?: string[]
}

type Mode = 'whole' | 'prefix'

interface Pattern {
  type: string
  regex: RegExp
  mode: Mode
}

const PATTERNS: Pattern[] = [
  // PEM private key blocks — before everything else, they contain other patterns
  {
    type: 'pem_key',
    mode: 'whole',
    regex: /-----BEGIN (?:[A-Z ]*)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]*)?PRIVATE KEY-----/g,
  },
  // JWT — three base64url segments
  {
    type: 'jwt',
    mode: 'whole',
    regex: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g,
  },

  // Cloud / infra
  { type: 'aws_access_key', mode: 'whole', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  {
    type: 'aws_secret_key',
    mode: 'prefix',
    regex:
      /((?:aws_secret_access_key|aws_session_token)["']?\s*[=:]\s*["']?)([A-Za-z0-9/+=]{40,})/gi,
  },
  { type: 'azure_storage_key', mode: 'prefix', regex: /(AccountKey=)([A-Za-z0-9+/=]{60,})/g },

  // GitHub / GitLab
  {
    type: 'github_token',
    mode: 'whole',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
  },
  { type: 'gitlab_token', mode: 'whole', regex: /\bglpat-[A-Za-z0-9\-_]{20,}\b/g },

  // Model providers
  { type: 'sk_key', mode: 'whole', regex: /\bsk-(?:ant-|proj-)?[A-Za-z0-9\-_]{20,}\b/g },
  { type: 'openrouter_key', mode: 'whole', regex: /\bsk-or-v1-[A-Za-z0-9]{40,}\b/g },
  { type: 'gemini_key', mode: 'whole', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { type: 'google_oauth_secret', mode: 'whole', regex: /\bGOCSPX-[A-Za-z0-9\-_]{28}\b/g },

  // SaaS
  { type: 'slack_token', mode: 'whole', regex: /\b(?:xox[baprs]|xapp)-[A-Za-z0-9-]{10,}\b/g },
  { type: 'stripe_key', mode: 'whole', regex: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { type: 'npm_token', mode: 'whole', regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { type: 'hf_token', mode: 'whole', regex: /\bhf_[A-Za-z0-9]{34}\b/g },
  { type: 'twilio_key', mode: 'whole', regex: /\b(?:SK|AC)[0-9a-fA-F]{32}\b/g },
  { type: 'telegram_bot_token', mode: 'whole', regex: /\b\d{8,10}:[A-Za-z0-9\-_]{35}\b/g },
  {
    type: 'sentry_dsn',
    mode: 'prefix',
    regex: /(https:\/\/)([a-f0-9]{32})(@[a-z0-9.\-]+)/g,
  },
  {
    type: 'discord_webhook',
    mode: 'prefix',
    regex: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/)([A-Za-z0-9\-_]{30,})/g,
  },

  // Provider tokens that carry a distinctive prefix. Prefix formats are
  // zero-false-positive, so they are safe to redact unconditionally; the
  // coverage was mined from MIT-licensed community pattern sets (see README
  // "Sources"). Keyword-only formats (Cloudflare, Datadog, Okta, …) are
  // intentionally left out: their tokens have no prefix, so matching them
  // means guessing, and the generic assignment patterns already cover the
  // common "PROVIDER_TOKEN=…" shape.
  { type: 'digitalocean_pat', mode: 'whole', regex: /\bdop_v1_[0-9a-f]{64}\b/g },
  { type: 'vercel_token', mode: 'whole', regex: /\bvcp_[A-Za-z0-9]{24}\b/g },
  { type: 'netlify_token', mode: 'whole', regex: /\bnfp_[A-Za-z0-9_-]{36}\b/g },
  { type: 'fly_token', mode: 'whole', regex: /\bfm2_[A-Za-z0-9_-]{40,}\b/g },
  { type: 'vault_token', mode: 'whole', regex: /\b(?:hvs|hvb)\.[A-Za-z0-9_-]{24,}\b/g },
  {
    type: 'terraform_token',
    mode: 'whole',
    regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,70}\b/g,
  },
  { type: 'doppler_token', mode: 'whole', regex: /\bdp\.pt\.[A-Za-z0-9]{43}\b/g },
  { type: 'pulumi_token', mode: 'whole', regex: /\bpul-[0-9a-f]{40}\b/g },
  { type: 'databricks_token', mode: 'whole', regex: /\bdapi[0-9a-f]{32}\b/g },
  {
    type: 'age_secret_key',
    mode: 'whole',
    regex: /\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b/g,
  },

  // Model providers
  { type: 'groq_key', mode: 'whole', regex: /\bgsk_[A-Za-z0-9]{32,64}\b/g },
  { type: 'xai_key', mode: 'whole', regex: /\bxai-[A-Za-z0-9]{60,120}\b/g },
  { type: 'perplexity_key', mode: 'whole', regex: /\bpplx-[A-Za-z0-9]{32,64}\b/g },
  { type: 'replicate_token', mode: 'whole', regex: /\br8_[A-Za-z0-9]{35,40}\b/g },
  { type: 'google_oauth_token', mode: 'whole', regex: /\bya29\.[A-Za-z0-9_-]{20,}\b/g },

  // CI / package registries
  { type: 'docker_token', mode: 'whole', regex: /\bdckr_pat_[A-Za-z0-9_-]{20,64}\b/g },
  {
    type: 'circleci_token',
    mode: 'whole',
    regex: /\bCCIP(?:AT|PRJ)_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40}\b/g,
  },
  { type: 'pypi_token', mode: 'whole', regex: /\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}\b/g },
  { type: 'rubygems_token', mode: 'whole', regex: /\brubygems_[0-9a-f]{48}\b/g },

  // SaaS / productivity
  { type: 'grafana_token', mode: 'whole', regex: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/g },
  { type: 'grafana_cloud_token', mode: 'whole', regex: /\bglc_[A-Za-z0-9+/=]{32,}\b/g },
  { type: 'notion_token', mode: 'whole', regex: /\bntn_[A-Za-z0-9]{40,60}\b/g },
  { type: 'airtable_token', mode: 'whole', regex: /\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b/g },
  { type: 'postman_token', mode: 'whole', regex: /\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b/g },
  { type: 'atlassian_token', mode: 'whole', regex: /\bATATT3[A-Za-z0-9_=-]{100,}\b/g },
  { type: 'mailchimp_key', mode: 'whole', regex: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g },
  {
    type: 'sendgrid_key',
    mode: 'whole',
    regex: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g,
  },
  { type: 'stripe_webhook_secret', mode: 'whole', regex: /\bwhsec_[A-Za-z0-9]{32,}\b/g },

  // Payments
  { type: 'shopify_token', mode: 'whole', regex: /\b(?:shpat|shpss)_[0-9a-fA-F]{32}\b/g },
  { type: 'square_token', mode: 'whole', regex: /\b(?:sq0atp-|sq0csp-)[0-9A-Za-z_-]{22}\b/g },
  { type: 'square_access_token', mode: 'whole', regex: /\bEAAA[0-9A-Za-z_-]{60}\b/g },
  {
    type: 'braintree_token',
    mode: 'whole',
    regex: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g,
  },

  // Social
  { type: 'facebook_token', mode: 'whole', regex: /\bEAA[0-9A-Za-z]{90,}\b/g },
  { type: 'twitter_token', mode: 'whole', regex: /\bA{22}[0-9A-Za-z%]{80,}\b/g },

  // Strong-named keys with a low value floor: when the key name itself says
  // "password"/"secret"/"token"/…, even a short value is a credential. The
  // generic pattern above keeps a 12-char floor to avoid false positives on
  // things like `key=true`; this one is stricter about the name and looser
  // about the value.
  //
  // Assignment matching accepts "=", ":", "->" and "=>" as separators, takes a
  // quoted value whole, and only fires when the value sits at a terminator —
  // so `SECRET -> value` cannot slip past, and `secret = pattern.mode === "x"`
  // is left alone instead of being mangled.
  {
    type: 'named_secret',
    mode: 'prefix',
    regex:
      /\b([A-Za-z0-9_.-]*(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?token|password|passwd|pwd|credential|apikey|api[_-]?secret|service[_-]?role[_-]?key|dsn|connection[_-]?string)[A-Za-z0-9_.-]*["']?\s*(?:=>|->|[:=])\s*)((?:"[^"\r\n]{4,}"|'[^'\r\n]{4,}'|[^\s"',;(){}<>]{4,}))(?=\s*(?:$|[,;)\]}]|#|\/\/))/gim,
  },

  // Transport auth
  {
    type: 'bearer_token',
    mode: 'prefix',
    regex: /(Authorization:\s*Bearer\s+)([A-Za-z0-9\-_.~+/]+=*)/gi,
  },
  {
    type: 'url_credentials',
    mode: 'prefix',
    regex: /((?:[a-z][a-z0-9+.\-]*:\/\/)[^\s:@/]+:)([^\s@/]+)(@[A-Za-z0-9.\-]+(?::\d+)?)/gi,
  },

  // Generic assignments: api_key = "…", token: …, "client_secret": "…"
  // The key name may be prefixed (aws_access_key_id, MY_API_KEY, DB_PASSWORD),
  // so the whole name is captured and kept — a leading \b would miss those
  // because "_" is a word character.
  {
    type: 'generic_secret',
    mode: 'prefix',
    regex:
      /\b([A-Za-z0-9_.-]*(?:api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?token|secret|password|passwd|pwd|credential|token|apikey|api[_-]?secret|service[_-]?role[_-]?key|dsn|connection[_-]?string)[A-Za-z0-9_.-]*["']?\s*(?:=>|->|[:=])\s*)((?:"[^"\r\n]{12,}"|'[^'\r\n]{12,}'|[^\s"',;(){}<>]{12,}))(?=\s*(?:$|[,;)\]}]|#|\/\/))/gim,
  },
  // Uppercase env assignments with a short value: FOO_TOKEN=abc123
  {
    type: 'env_secret',
    mode: 'prefix',
    regex:
      /^([ \t]*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|SERVICE_ROLE_KEY|ROLE_KEY|DSN|CONNECTION_STRING)[A-Z0-9_]*[ \t]*(?:=>|->|=)[ \t]*)((?:"[^"\r\n]{6,}"|'[^'\r\n]{6,}'|[^\s"'#(){}<>]{6,}))(?=\s*(?:$|[,;)\]}]|#|\/\/))/gm,
  },
]

// Values that are obviously not real credentials. The word-like markers must
// stand alone: "AKIA…EXAMPLE" (AWS' documented key) still gets redacted.
const PLACEHOLDER =
  /(?:^|[^A-Za-z0-9])(?:example|placeholder|changeme|dummy|redacted)(?:[^A-Za-z0-9]|$)|your[_-]?\w+|x{3,}|\.{3,}|\*+|<[^>]+>|\{\{[^}]+\}\}/i

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value)
}

function isAllowed(value: string, allow: string[]): boolean {
  return allow.some(a => a.length > 0 && value.includes(a))
}

/**
 * Redact secrets from a string.
 * Returns the redacted string, the number of replacements and the types found.
 */
export function redact(input: string, opts: RedactOptions = {}): RedactionResult {
  const allow = opts.allow ?? []
  let out = input
  let count = 0
  const types = new Set<string>()

  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0
    out = out.replace(pattern.regex, (...args: unknown[]) => {
      const match = args[0] as string
      // Callback args: [match, ...groups, offset, wholeString]
      const groups = args.slice(1, -2) as string[]

      const secret = pattern.mode === 'prefix' ? (groups[1] ?? match) : match
      const prefix = pattern.mode === 'prefix' ? (groups[0] ?? '') : ''
      const tail = pattern.mode === 'prefix' ? (groups[2] ?? '') : ''

      if (isAllowed(secret, allow)) return match
      if (isPlaceholder(secret)) return match

      types.add(pattern.type)
      count++
      return `${prefix}[REDACTED:${pattern.type}]${tail}`
    })
    pattern.regex.lastIndex = 0
  }

  return { output: out, count, types: [...types] }
}

/** True when the text contains something that looks like a credential. */
export function containsSecrets(input: string, opts: RedactOptions = {}): boolean {
  return redact(input, opts).count > 0
}

/** Pattern types this module can detect (for docs and diagnostics). */
export function patternTypes(): string[] {
  return PATTERNS.map(p => p.type)
}
