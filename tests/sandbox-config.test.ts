import assert from 'node:assert/strict'
import test from 'node:test'
import { requireValidationSandbox, SandboxUnavailableError } from '../src/sandbox.ts'
import type { Config } from '../src/config.ts'

const image = `sha256:${'a'.repeat(64)}`
const base = { enabled: true, maxFiles: 10, maxFileBytes: 1024, stateDir: '' } as Config

test('validation sandbox defaults to the standard local Docker socket', () => {
  assert.equal(requireValidationSandbox({ ...base, validationSandbox: { executable: '/usr/local/bin/docker', image } }).socket, '/var/run/docker.sock')
})

test('validation sandbox accepts an explicit absolute local Unix socket', () => {
  const socket = '/Users/someone/.colima/default/docker.sock'
  assert.equal(requireValidationSandbox({ ...base, validationSandbox: { executable: '/usr/local/bin/docker', image, socket } }).socket, socket)
})

test('validation sandbox refuses relative, remote or shell-like socket values and unpinned images', () => {
  for (const socket of ['docker.sock', 'tcp://10.0.0.1:2375', '/tmp/a b.sock', '/tmp/x;rm']) {
    assert.throws(() => requireValidationSandbox({ ...base, validationSandbox: { executable: '/usr/local/bin/docker', image, socket } }), SandboxUnavailableError)
  }
  assert.throws(() => requireValidationSandbox({ ...base, validationSandbox: { executable: '/usr/local/bin/docker', image: 'node:22' } }), SandboxUnavailableError)
  assert.throws(() => requireValidationSandbox({ ...base, validationSandbox: { executable: 'docker', image } }), SandboxUnavailableError)
})
