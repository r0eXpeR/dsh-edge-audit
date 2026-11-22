import assert from 'node:assert/strict'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import type { Agent, CreateAgentOptions } from '@deepseek-ai/dsh-agent'
import { createAuditAgent, workspaceDirectory } from '../src/runtime.ts'

test('optional Agent service is read through Cordis get and preserves parent, route, signal and scoped setup', async () => {
  const ctx = new Context()
  const signal = new AbortController().signal
  const parent = { options: { provider: 'fixture', model: 'fixture-model' }, session: { id: 'parent', header: { delegationDepth: 2 } } } as unknown as Agent
  let received: CreateAgentOptions | undefined
  ctx.provide('agents', {
    currentInitiator: () => parent,
    async create(options: CreateAgentOptions) { received = options; return { agent: {}, async dispose() {} } },
  } as never)
  const setup = () => undefined
  const fiber = await ctx.plugin({
    async apply(scope: Context) {
      // 故意不声明 agents inject；与插件在引擎-only profile 下的可选能力一致。
      await createAuditAgent(scope, { sessionId: 'child' as never, signal, meta: { cwd: '/private/tmp', origin: 'subagent' }, setup })
    },
  })
  assert.equal(received?.parentAgent, parent)
  assert.deepEqual(received?.agentOptions, parent.options)
  assert.notEqual(received?.agentOptions, parent.options)
  assert.equal(received?.signal, signal)
  assert.equal(typeof received?.setup, 'function')
  assert.notEqual(received?.setup,setup,'setup adds the untrusted-data boundary')
  assert.equal(received?.meta?.parentSession, 'parent')
  assert.equal(received?.meta?.delegationDepth, 3)
  await fiber.dispose()
})

test('workspace follows committed Session directory and never changes the process directory', async () => {
  const ctx = new Context(), before = process.cwd()
  const first = { session: { header: { cwd: '/original/one' } } } as unknown as Agent
  const second = { session: { header: { cwd: '/original/two' } } } as unknown as Agent
  ctx.provide('workingDirectory', { get: (session: unknown) => session === first.session ? '/current/one' : '/current/two' } as never)
  const results = await Promise.all([first, second].map(agent => Promise.resolve(workspaceDirectory(ctx, agent))))
  assert.deepEqual(results, ['/current/one', '/current/two'])
  assert.equal(process.cwd(), before)
})
