import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { withAuditActor } from '../src/audit-context.ts'
import { coverageDigest, observeCoveragePage, recordCoverageCritic } from '../src/coverage.ts'
import { recordCoverageCheck } from '../src/coverage.ts'
import { readScanSource } from '../src/deep-discovery.ts'
import { buildInvestigationMap } from '../src/investigation-plan.ts'
import { createLlmDiscoveryJob } from '../src/llm/discovery.ts'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan, sha256 } from '../src/state.ts'
import { reviewFixtureCoverage } from './coverage-fixture.ts'

async function fixture() {
  const root = await mkdtemp('/private/tmp/dsh-coverage-depth-')
  const state = await mkdtemp('/private/tmp/dsh-coverage-depth-state-')
  const config = { enabled: true, maxFiles: 500, maxFileBytes: 262144, stateDir: state }
  return { root, state, config, async cleanup() { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) } }
}

test('领域覆盖只由当前源码区域的信号激活', async () => {
  const f = await fixture()
  try {
    const lines = ['model.generate(request.body);', ...Array.from({ length: 399 }, (_, i) => `const value${i} = ${i};`)]
    await writeFile(join(f.root, 'app.ts'), `${lines.join('\n')}\n`)
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const units = scan.coverage.ledger ?? []
    assert.ok(units.some(unit => unit.startLine === 1 && unit.attackClass === 'ai-agent'))
    assert.ok(units.some(unit => unit.startLine === 201 && unit.attackClass === 'dataflow'))
    assert.equal(units.some(unit => unit.startLine === 201 && unit.attackClass === 'ai-agent'), false)
  } finally { await f.cleanup() }
})

test('同一区域的不同路由拥有独立覆盖单元及精确引用门禁', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'routes.ts'), "router.get('/alpha', firstHandler);\nrouter.post('/beta', secondHandler);\napp.get('/gamma', thirdHandler);\n// router.delete('/comment', ignored);\nconst example = \"app.post('/string', ignored)\";\nconst method = router.put;\n")
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, scan)
    const routes = (scan.coverage.ledger ?? []).filter(unit => unit.attackClass === 'web-auth')
    assert.deepEqual(routes.map(unit => unit.anchorLine).sort(), [1, 2, 3])
    assert.equal(new Set(routes.map(unit => unit.surface)).size, 3)
    await withAuditActor({ id: 'route-reviewer', role: 'reviewer', scanId: scan.id }, async () => {
      await readScanSource(f.config, scan.id, 'routes.ts', 1, 6)
      const second = routes.find(unit => unit.anchorLine === 2)!
      const input = { unitId: second.id, status: 'reviewed' as const, question: 'Does the second route enforce its own object boundary?', conclusion: 'The second route registration and its operation are reviewed separately from the first route.', sourceReferences: [{ file: 'routes.ts', line: 1, role: 'entrypoint' as const }], limitations: [] }
      await assert.rejects(() => recordCoverageCheck(f.config, scan.id, input), /exact route registration/)
      await recordCoverageCheck(f.config, scan.id, { ...input, sourceReferences: [{ file: 'routes.ts', line: 2, role: 'entrypoint' }] })
    })
  } finally { await f.cleanup() }
})

test('同一源码行的两个路由分别建账且历史缺口不会合并', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'routes.ts'), "router.get('/one', one); router.get('/two', two);\n")
    const prior = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const routes = prior.coverage.ledger!.filter(unit => unit.attackClass === 'web-auth')
    assert.equal(routes.length, 2)
    assert.equal(new Set(routes.map(unit => unit.surface)).size, 2)
    for (const unit of routes) { unit.status = 'blocked'; unit.reason = 'The distinct route authorization decision remains unresolved.' }
    await saveScan(f.state, prior)
    const current = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, current)
    const job = await createLlmDiscoveryJob(f.config, current.id)
    const history = JSON.parse(job.priorContext!)
    assert.equal(history.gaps.filter((gap: { attackClass: string }) => gap.attackClass === 'web-auth').length, 2)
    assert.equal(job.packets.filter(packet => packet.id.startsWith('packet_prior_gap_')).flatMap(packet => packet.questions).length, 2)
  } finally { await f.cleanup() }
})

test('clean Critic 必须独立读取每个已审单元引用的源码', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'first.ts'), 'export const first = 1;\n')
    await writeFile(join(f.root, 'second.ts'), 'export const second = 2;\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, scan)
    await reviewFixtureCoverage(f.config, scan.id)
    const current = await loadScan(f.state, scan.id)
    const input = { ledgerDigest: coverageDigest(current), reassignIds: [], missingUnits: [], rationale: 'Every reviewed boundary must have its cited source independently inspected before clean acceptance.' }
    await withAuditActor({ id: 'independent-depth-critic', role: 'coverage_critic', scanId: scan.id }, async () => {
      await readScanSource(f.config, scan.id, 'first.ts', 1, 1)
      await observeCoveragePage(f.config, scan.id, current.coverage.ledger!.map(unit => unit.id))
      await assert.rejects(() => recordCoverageCritic(f.config, scan.id, input), /independently read a reviewed unit/)
      await readScanSource(f.config, scan.id, 'second.ts', 1, 1)
      await recordCoverageCritic(f.config, scan.id, input)
    })
  } finally { await f.cleanup() }
})

test('调查图保留 Python、PHP 与 Java 的本地导入线索', async () => {
  const f = await fixture()
  try {
    await mkdir(join(f.root, 'pkg'), { recursive: true })
    await mkdir(join(f.root, 'web'), { recursive: true })
    await mkdir(join(f.root, 'src/main/java/com/acme'), { recursive: true })
    await writeFile(join(f.root, 'pkg/main.py'), 'from .service import handle\n')
    await writeFile(join(f.root, 'pkg/service.py'), 'def handle():\n    return 1\n')
    await writeFile(join(f.root, 'web/index.php'), "<?php\nrequire_once __DIR__ . '/auth.php';\n")
    await writeFile(join(f.root, 'web/auth.php'), '<?php\nfunction authorize() { return true; }\n')
    await writeFile(join(f.root, 'src/main/java/com/acme/Api.java'), 'package com.acme;\nimport com.acme.Security;\nclass Api {}\n')
    await writeFile(join(f.root, 'src/main/java/com/acme/Security.java'), 'package com.acme;\nclass Security {}\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const map = await buildInvestigationMap(scan)
    assert.ok(map.links.some(link => link.from === 'pkg/main.py' && link.to === 'pkg/service.py'))
    assert.ok(map.links.some(link => link.from === 'web/index.php' && link.to === 'web/auth.php'))
    assert.ok(map.links.some(link => link.from === 'src/main/java/com/acme/Api.java' && link.to === 'src/main/java/com/acme/Security.java'))
  } finally { await f.cleanup() }
})

test('历史未覆盖边界进入当前调查包但不继承旧结论', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'app.ts'), 'export const value = request.body;\n')
    const prior = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const gap = prior.coverage.ledger![0]
    gap.status = 'blocked'
    gap.reason = 'The exact caller identity and object authorization decision were not established.'
    await saveScan(f.state, prior)
    const current = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, current)
    const job = await createLlmDiscoveryJob(f.config, current.id)
    const history = JSON.parse(job.priorContext!)
    assert.ok(history.gaps.some((item: { path: string; priorStatus: string }) => item.path === 'app.ts' && item.priorStatus === 'blocked'))
    assert.ok(job.packets.some(packet => packet.id.startsWith('packet_prior_gap_') && packet.paths.includes('app.ts')))
    assert.ok(current.coverage.ledger?.every(unit => unit.status === 'planned'))
  } finally { await f.cleanup() }
})

test('源码变化后历史缺口不把旧行号当作当前调查位置', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'app.ts'), `${Array.from({ length: 201 }, (_, i) => `export const value${i} = ${i};`).join('\n')}\n`)
    const prior = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const oldRegion = prior.coverage.ledger!.find(unit => unit.startLine === 201)!
    oldRegion.status = 'blocked'
    oldRegion.reason = 'The exact authorization boundary at the old source location was unresolved.'
    await saveScan(f.state, prior)
    await writeFile(join(f.root, 'app.ts'), 'export const replacement = 1;\n')
    const current = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, current)
    const job = await createLlmDiscoveryJob(f.config, current.id)
    const packet = job.packets.find(item => item.id.startsWith('packet_prior_gap_'))!
    assert.ok(packet)
    assert.deepEqual(packet.regions?.map(region => [region.startLine, region.endLine]), [[1, 1]])
    assert.match(packet.questions[0], /historical line numbers are stale/)
    assert.doesNotMatch(packet.questions[0], /app\.ts:201/)
  } finally { await f.cleanup() }
})

test('同一区域的多个历史缺口分批派发，超出上限时明确记录遗漏', async () => {
  const f = await fixture()
  try {
    await writeFile(join(f.root, 'app.ts'), 'export const value = request.body;\n')
    const prior = await runScan(f.root, f.config, 'standard', '', false, f.state)
    const base = prior.coverage.ledger![0]
    prior.coverage.ledger = Array.from({ length: 25 }, (_, index) => ({ ...base, id: `cov_${sha256(String(index)).slice(0, 24)}`, boundary: `Distinct boundary ${index}`, status: 'blocked' as const, reason: `The exact control for distinct boundary ${index} remains unresolved.`, checks: [], attempts: [] }))
    await saveScan(f.state, prior)
    const current = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await saveScan(f.state, current)
    const job = await createLlmDiscoveryJob(f.config, current.id)
    const history = JSON.parse(job.priorContext!)
    const packets = job.packets.filter(item => item.id.startsWith('packet_prior_gap_'))
    assert.equal(history.gaps.length, 24)
    assert.ok(history.issues.some((issue: string) => issue.includes('additional prior unresolved coverage units')))
    assert.equal(packets.length, 3)
    assert.equal(packets.reduce((sum, packet) => sum + packet.questions.length, 0), 24)
  } finally { await f.cleanup() }
})
