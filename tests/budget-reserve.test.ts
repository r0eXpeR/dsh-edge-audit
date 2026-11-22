import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { auditBudgetReason, auditDiscoveryReserveReason } from '../src/audit-budget.ts'
import { createAuditAgent } from '../src/runtime.ts'
import { investigationStatus } from '../src/investigation-status.ts'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan } from '../src/state.ts'

test('发现阶段达到预留阈值后不再创建模型 Worker，闭环预算仍保留', async () => {
  const root = await mkdtemp('/private/tmp/dsh-budget-reserve-')
  const state = await mkdtemp('/private/tmp/dsh-budget-reserve-state-')
  try {
    await writeFile(join(root, 'app.ts'), 'export const safe = 1;\n')
    const config = { enabled: true, maxFiles: 500, maxFileBytes: 262144, stateDir: state }
    const scan = await runScan(root, config, 'standard', '', false, state)
    scan.auditBudget = { maxModelTokens: 1000 }
    scan.modelExecutions = [{ sessionId: 'already-finished', actorId: 'session:already-finished', role: 'discoverer', at: new Date().toISOString(), usage: { inputTokens: 700, outputTokens: 100, cacheReadTokens: 0, cacheWriteTokens: 0, calls: 1 }, usageComplete: true, toolCalls: 1 }]
    await saveScan(state, scan)
    assert.equal(await auditBudgetReason(state, scan.id, 1000), undefined)
    assert.match((await auditDiscoveryReserveReason(state, scan.id, 1000))!, /reserved for coverage critique and candidate closure/)
    let created = 0
    const ctx = { agents: { async create() { created++; throw new Error('Unexpected worker creation') } } }
    await assert.rejects(() => createAuditAgent(ctx as never, { sessionId: 'reserve-test' } as never, { id: 'new-discoverer', role: 'discoverer', scanId: scan.id, stateDir: state, maxModelTokens: 1000 }), /Discovery paused/)
    assert.equal(created, 0)
    scan.modelExecutions[0].usage = null
    await saveScan(state, scan)
    assert.match((await auditDiscoveryReserveReason(state, scan.id, 1000))!, /did not retain usage/)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('同一预算账户的并发 Worker 等待前一个用量落账后再决定是否创建', async () => {
  const root = await mkdtemp('/private/tmp/dsh-budget-serial-')
  const state = await mkdtemp('/private/tmp/dsh-budget-serial-state-')
  try {
    await writeFile(join(root, 'app.ts'), 'export const safe = 1;\n')
    const config = { enabled: true, maxFiles: 500, maxFileBytes: 262144, stateDir: state }
    const scan = await runScan(root, config, 'standard', '', false, state)
    await saveScan(state, scan)
    let created = 0
    const ctx = { agents: { async create(options: { sessionId: string }) {
      created++
      return { agent: { session: { id: options.sessionId, deriveMessages: () => [], snapshotEvents: () => [
        { type: 'assistant/message', data: { usage: { inputTokens: 700, outputTokens: 100, cacheReadTokens: 0, cacheWriteTokens: 0 } } },
        { type: 'turn/end', data: { reason: { kind: 'completed' } } },
      ] } }, async dispose() {} }
    } } }
    const first = await createAuditAgent(ctx as never, { sessionId: 'budget-first' } as never, { id: 'first', role: 'discoverer', scanId: scan.id, stateDir: state, maxModelTokens: 1000, maxConcurrentModelWorkers: 2 })
    const pending = await loadScan(state, scan.id)
    assert.ok(pending.modelExecutions?.some(row => row.sessionId === 'budget-first' && row.terminalReason === 'pending'))
    assert.match((await auditBudgetReason(state, scan.id, 1000))!, /in-flight/)
    const status = await investigationStatus(config as never, scan.id)
    assert.equal(status.budgetUnreconciled, true)
    assert.equal(status.resumable, false)
    assert.match(status.nextAction, /unfinished model usage receipt/)
    const second = createAuditAgent(ctx as never, { sessionId: 'budget-second' } as never, { id: 'second', role: 'discoverer', scanId: scan.id, stateDir: state, maxModelTokens: 1000, maxConcurrentModelWorkers: 2 })
    await new Promise(resolve => setTimeout(resolve, 30))
    assert.equal(created, 1)
    await first.dispose()
    await assert.rejects(second, /Discovery paused/)
    assert.equal(created, 1)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('Agent 创建失败会撤销未执行的预算占位', async () => {
  const root = await mkdtemp('/private/tmp/dsh-budget-create-failure-')
  const state = await mkdtemp('/private/tmp/dsh-budget-create-failure-state-')
  try {
    await writeFile(join(root, 'app.ts'), 'export const safe = 1;\n')
    const config = { enabled: true, maxFiles: 500, maxFileBytes: 262144, stateDir: state }
    const scan = await runScan(root, config, 'standard', '', false, state)
    await saveScan(state, scan)
    const ctx = { agents: { async create() { throw new Error('Factory failed before publishing an Agent.') } } }
    await assert.rejects(() => createAuditAgent(ctx as never, { sessionId: 'budget-create-failure' } as never, { id: 'failure', role: 'discoverer', scanId: scan.id, stateDir: state, maxModelTokens: 1000 }), /Factory failed/)
    const retained = await loadScan(state, scan.id)
    assert.equal(retained.modelExecutions?.some(row => row.sessionId === 'budget-create-failure'), false)
    assert.equal(await auditBudgetReason(state, scan.id, 1000), undefined)
  } finally { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})
