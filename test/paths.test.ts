import { describe, expect, test } from 'bun:test'
import { secretFileInInput } from '../src/index.js'
import { DEFAULTS, getConfig, resetConfig } from '../src/config.js'

describe('secretFileInInput', () => {
  test('detects a shell command that reads a secret file', () => {
    expect(secretFileInInput('bash', { command: 'cat .env' }, DEFAULTS)).toBe('.env')
    expect(secretFileInInput('bash', { command: 'base64 -w0 .env' }, DEFAULTS)).toBe('.env')
    expect(secretFileInInput('bash', { command: 'Get-Content .env -Raw' }, DEFAULTS)).toBe('.env')
    expect(secretFileInInput('bash', { command: 'cat server.pem' }, DEFAULTS)).toBe('server.pem')
  })

  test('detects the read tool reading a secret file', () => {
    expect(secretFileInInput('read', { filePath: 'C:/proj/.env' }, DEFAULTS)).toBe('.env')
    expect(secretFileInInput('read', { filePath: 'C:/proj/server.key' }, DEFAULTS)).toBe(
      'server.key'
    )
  })

  test('leaves searches and unrelated commands alone', () => {
    expect(secretFileInInput('bash', { command: 'rg ".env" src/' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'rg .env src/' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'grep -rn API_KEY .' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'git status' }, DEFAULTS)).toBeUndefined()
    expect(
      secretFileInInput(
        'bash',
        { command: 'cat src/token-accumulator-counter-opencode/index.ts' },
        DEFAULTS
      )
    ).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'cat > .env' }, DEFAULTS)).toBeUndefined()
  })

  test('templates and examples stay readable', () => {
    expect(secretFileInInput('bash', { command: 'cat .env.template' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'cat .env.example' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('bash', { command: 'cat example.env' }, DEFAULTS)).toBeUndefined()
    expect(secretFileInInput('read', { filePath: 'C:/proj/.env.sample' }, DEFAULTS)).toBeUndefined()
  })

  test('the trigger can be switched off', () => {
    const off = { ...DEFAULTS, redactSecretFiles: false }
    expect(secretFileInInput('bash', { command: 'cat .env' }, off)).toBeUndefined()
  })
})

describe('config', () => {
  test('the secret-file switch follows REDACTOR_REDACT_SECRET_FILES', () => {
    resetConfig()
    process.env.REDACTOR_REDACT_SECRET_FILES = '0'
    expect(getConfig().redactSecretFiles).toBe(false)
    delete process.env.REDACTOR_REDACT_SECRET_FILES
    resetConfig()
    expect(getConfig().redactSecretFiles).toBe(true)
  })
})
