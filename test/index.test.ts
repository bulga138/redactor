import { describe, expect, test } from 'bun:test'
import {
  appendNote,
  referencesSecretName,
  referencesSecretVar,
  secretVarNames,
} from '../src/index.js'

describe('referencesSecretVar', () => {
  test('detects $VAR references', () => {
    expect(referencesSecretVar('echo $API_KEY')).toBe(true)
    expect(referencesSecretVar('echo ${SECRET_TOKEN}')).toBe(true)
    expect(referencesSecretVar('print(process.env.PASSWORD)')).toBe(true)
    expect(referencesSecretVar('os.getenv("DB_TOKEN")')).toBe(true)
    expect(referencesSecretVar('getenv("AUTH_SECRET")')).toBe(true)
  })
  test('ignores non-secret variable names', () => {
    expect(referencesSecretVar('echo $HOME')).toBe(false)
    expect(referencesSecretVar('grep API_KEY src/')).toBe(false)
    expect(referencesSecretVar('const x = 1')).toBe(false)
  })

  test('referencesSecretName detects quoted secret identifiers', () => {
    expect(referencesSecretName('grep "API_KEY" src/')).toBe(true)
    expect(referencesSecretName("grep 'DB_PASSWORD' .")).toBe(true)
    expect(referencesSecretName('search "token"')).toBe(true)
  })
  test('referencesSecretName ignores plain words', () => {
    expect(referencesSecretName('grep hello src/')).toBe(false)
    expect(referencesSecretName('echo done')).toBe(false)
  })

  test('secretVarNames extracts variable names', () => {
    expect(secretVarNames('echo $DB_PASSWORD')).toEqual(['DB_PASSWORD'])
    expect(secretVarNames('os.getenv("API_KEY")')).toEqual(['API_KEY'])
    expect(secretVarNames('grep "API_KEY" src/')).toEqual(['API_KEY'])
    expect(secretVarNames('echo $HOME')).toEqual([])
  })

  // Regression: the input arrives as an object { command: "..." }. Stringifying
  // the whole object wraps the command in outer quotes, which made the regexes
  // match secret-ish words inside unquoted paths (e.g. "token-accumulator").
  test('ignores secret-ish words inside unquoted paths', () => {
    const input = {
      command:
        "cd C:\\Users\\bulga\\Documents\\programacion\\token-accumulator-counter-opencode; git log -1 --oneline; echo '---STATUS---'; git status --short --branch",
    }
    expect(referencesSecretName(input)).toBe(false)
    expect(referencesSecretVar(input)).toBe(false)
    expect(secretVarNames(input)).toEqual([])
  })
  test('still detects quoted secret identifiers in object input', () => {
    expect(referencesSecretName({ command: 'grep "API_KEY" src/' })).toBe(true)
    expect(secretVarNames({ command: 'grep "API_KEY" src/' })).toEqual(['API_KEY'])
  })
})

describe('appendNote', () => {
  test('appends once and is idempotent', () => {
    const once = appendNote('hello')
    expect(once).toContain('[redactor]')
    expect(appendNote(once)).toBe(once)
  })
})
