import { describe, expect, test } from "bun:test"
import { appendNote, referencesSecretVar } from "../src/index.js"

describe("referencesSecretVar", () => {
  test("detects $VAR references", () => {
    expect(referencesSecretVar("echo $API_KEY")).toBe(true)
    expect(referencesSecretVar("echo ${SECRET_TOKEN}")).toBe(true)
    expect(referencesSecretVar('print(process.env.PASSWORD)')).toBe(true)
    expect(referencesSecretVar('os.getenv("DB_TOKEN")')).toBe(true)
    expect(referencesSecretVar('getenv("AUTH_SECRET")')).toBe(true)
  })
  test("ignores non-secret variable names", () => {
    expect(referencesSecretVar("echo $HOME")).toBe(false)
    expect(referencesSecretVar("grep API_KEY src/")).toBe(false)
    expect(referencesSecretVar("const x = 1")).toBe(false)
  })
})

describe("appendNote", () => {
  test("appends once and is idempotent", () => {
    const once = appendNote("hello")
    expect(once).toContain("[redactor]")
    expect(appendNote(once)).toBe(once)
  })
})
