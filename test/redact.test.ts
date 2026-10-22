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
