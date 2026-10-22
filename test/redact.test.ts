import { describe, expect, test } from "bun:test"
import { containsSecrets, redact } from "../src/redact.js"

const KEY = "AKIAIOSFODNN7EXAMPLE"

describe("provider patterns", () => {
  test("aws access key", () => {
    const r = redact(`key=${KEY}`)
    expect(r.count).toBe(1)
    expect(r.output).not.toContain(KEY)
    expect(r.output).toContain("[REDACTED:aws_access_key]")
  })

  test("github token", () => {
    const r = redact("ghp_0123456789abcdefghijklmnopqrstuvwxyzAB")
    expect(r.count).toBe(1)
    expect(r.output).toContain("[REDACTED:github_token]")
  })

  test("openai style key", () => {
    const r = redact("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789")
    expect(r.count).toBe(1)
    expect(r.output).toContain("[REDACTED:sk_key]")
  })

  test("gemini key", () => {
    const r = redact("AIzaSyD-1234567890abcdefghijklmnopqrstu")
    expect(r.count).toBe(1)
    expect(r.output).toContain("[REDACTED:gemini_key]")
  })

  test("jwt", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    const r = redact(`Authorization: Bearer ${jwt}`)
    expect(r.count).toBeGreaterThan(0)
    expect(r.output).not.toContain(jwt)
  })

  test("pem private key block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    const r = redact(pem)
    expect(r.count).toBe(1)
    expect(r.output).toBe("[REDACTED:pem_key]")
  })

  test("connection string password", () => {
    const r = redact("postgres://appuser:hunter2@db.internal:5432/app")
    expect(r.count).toBe(1)
    expect(r.output).not.toContain("hunter2")
    expect(r.output).toContain("postgres://appuser:")
  })
})

describe("generic assignments", () => {
  test("env style assignment", () => {
    const r = redact("STRIPE_SECRET_KEY=sk_live_abcdefghij1234567890")
    expect(r.count).toBeGreaterThan(0)
    expect(r.output).not.toContain("sk_live_abcdefghij1234567890")
  })

  test("json style assignment", () => {
    const r = redact('{"api_key": "abcd1234efgh5678ijkl"}')
    expect(r.count).toBe(1)
    expect(r.output).not.toContain("abcd1234efgh5678ijkl")
  })

  test("bearer header keeps the scheme", () => {
    const r = redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    expect(r.output).toContain("Authorization: Bearer ")
    expect(r.output).toContain("[REDACTED:bearer_token]")
  })

  test("prefixed key name is still caught", () => {
    const r = redact("aws_access_key_id = AKIAZ3XY7QWERTYUIOPAS")
    expect(r.count).toBe(1)
    expect(r.output).not.toContain("AKIAZ3XY7QWERTYUIOPAS")
    expect(r.output).toContain("aws_access_key_id = ")
  })

  test("uppercase env key name is caught", () => {
    const r = redact("MY_API_KEY=abcd1234efgh5678")
    expect(r.count).toBe(1)
    expect(r.output).not.toContain("abcd1234efgh5678")
  })
})

describe("false positives", () => {
  test("ordinary prose is untouched", () => {
    const text = "The server returned 200 and the token was missing from the header."
    const r = redact(text)
    expect(r.count).toBe(0)
    expect(r.output).toBe(text)
  })

  test("placeholders survive", () => {
    const text = "api_key=your-api-key-here"
    expect(redact(text).count).toBe(0)
  })

  test("allowlist wins over the pattern", () => {
    const r = redact(`key=${KEY}`, { allow: [KEY] })
    expect(r.count).toBe(0)
    expect(r.output).toContain(KEY)
  })
})

describe("behaviour", () => {
  test("is idempotent", () => {
    const once = redact(`key=${KEY}`).output
    const twice = redact(once)
    expect(twice.count).toBe(0)
    expect(twice.output).toBe(once)
  })

  test("containsSecrets detects without changing text", () => {
    expect(containsSecrets(`key=${KEY}`)).toBe(true)
    expect(containsSecrets("nothing here")).toBe(false)
  })
})

// Formats mined from MIT-licensed community pattern sets (regextokens, GitSentry).
// Each sample is the bare token: no assignment context, so only the provider
// pattern can fire and the count stays 1.
describe("mined provider patterns", () => {
  const CASES: Array<[string, string]> = [
    ["digitalocean_pat", "dop_v1_" + "a1".repeat(32)],
    ["vercel_token", "vcp_" + "V".repeat(24)],
    ["netlify_token", "nfp_" + "b2".repeat(18)],
    ["fly_token", "fm2_" + "c3".repeat(20)],
    ["vault_token", "hvs." + "d4".repeat(12)],
    ["terraform_token", "e5".repeat(7) + ".atlasv1." + "f6".repeat(31)],
    ["doppler_token", "dp.pt." + "g7".repeat(21) + "x"],
    ["pulumi_token", "pul-" + "a1".repeat(20)],
    ["databricks_token", "dapi" + "a1".repeat(16)],
    ["age_secret_key", "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L".repeat(2).slice(0, 58)],
    ["groq_key", "gsk_" + "j1".repeat(16)],
    ["xai_key", "xai-" + "k2".repeat(30)],
    ["perplexity_key", "pplx-" + "l3".repeat(16)],
    ["replicate_token", "r8_" + "m4".repeat(18)],
    ["google_oauth_token", "ya29." + "n5".repeat(15)],
    ["docker_token", "dckr_pat_" + "o6".repeat(15)],
    ["circleci_token", "CCIPAT_" + "p7".repeat(10) + "_" + "a8".repeat(20)],
    ["pypi_token", "pypi-AgEIcHlwaS5vcmc" + "r9".repeat(25)],
    ["rubygems_token", "rubygems_" + "b1".repeat(24)],
    ["grafana_token", "glsa_" + "c2".repeat(16) + "_" + "d3".repeat(4)],
    ["grafana_cloud_token", "glc_" + "e4".repeat(20)],
    ["notion_token", "ntn_" + "f5".repeat(20)],
    ["airtable_token", "pat" + "g6".repeat(7) + "." + "a7".repeat(32)],
    ["postman_token", "PMAK-" + "b8".repeat(12) + "-" + "c9".repeat(17)],
    ["atlassian_token", "ATATT3" + "x7Kq2mZ9pL4tR8vW3yN6cH1sD5gJ0fB7kQ2xM9nV4".repeat(3)],
    ["mailchimp_key", "d4".repeat(16) + "-us12"],
    ["sendgrid_key", "SG." + "e5".repeat(11) + "." + "f6".repeat(21) + "f"],
    ["stripe_webhook_secret", "whsec_" + "a7".repeat(16)],
    ["shopify_token", "shpat_" + "b8".repeat(16)],
    ["square_token", "sq0atp-" + "c9".repeat(11)],
    ["square_access_token", "EAAA" + "d1".repeat(30)],
    ["braintree_token", "access_token$production$" + "e2".repeat(8) + "$" + "a3".repeat(16)],
    ["facebook_token", "EAA" + "x7".repeat(45)],
    ["twitter_token", "A".repeat(22) + "b1".repeat(40)],
    ["slack_token", "xapp-1-A01234567890-1234567890123-abcdef"],
  ]

  for (const [type, secret] of CASES) {
    test(type, () => {
      const r = redact(secret)
      expect(r.count).toBe(1)
      expect(r.output).not.toContain(secret)
      expect(r.output).toContain(`[REDACTED:${type}]`)
    })
  }

  test("benign text is untouched", () => {
    const text = 'const greeting = "hello world"; // 1234567890\nconst url = "https://example.com/docs"'
    expect(redact(text).count).toBe(0)
  })
})
