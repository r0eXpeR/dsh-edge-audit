import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { withAuditActor } from '../src/audit-context.ts'
import { compareScans } from '../src/comparison.ts'
import { domainValidationSection, packagedSkillBody, skillGuidance } from '../src/skills.ts'
import { actorReadLine, rankedDomains, selectedDomains } from '../src/coverage.ts'
import { bindDiffEvidence } from '../src/diff-evidence.ts'
import { isExcludedDiffPath, parseUnifiedDiff, unquoteGitPath } from '../src/diff-parse.ts'
import { createDisclosureCampaign } from '../src/disclosure.ts'
import { createDiffDiscoveryJob, getDiffReviewItems } from '../src/llm/diff.ts'
import { replaceExpectedFile } from '../src/patch-transaction.ts'
import { runDiffScan, runScan, generateSourceThreatModel } from '../src/scanner.ts'
import { loadScan, persistInvestigationArtifacts, readArtifact, saveScan, sha256, writeArtifact } from '../src/state.ts'
import { cancelInvestigation, claimAuditTask, completeScan, prepareFinalRecordReview, recordValidation } from '../src/workbench.ts'
import { attachFixtureEndpoints } from './coverage-fixture.ts'

const git = promisify(execFile)
const repo = async (root: string, ...args: string[]) => git('git', ['-c', 'user.email=t@example.test', '-c', 'user.name=t', ...args], { cwd: root })
async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'edge-audit-root-')), state = await mkdtemp(join(tmpdir(), 'edge-audit-state-'))
  return { root, state, config: { enabled: true, maxFiles: 50, maxFileBytes: 65536, stateDir: state } as never, done: async () => { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) } }
}
async function gitFixture() {
  const f = await fixture(); await repo(f.root, 'init', '-q'); return f
}

test('parser counts hunk lines so an added "++ b/x" line cannot forge a file header', () => {
  const diff = ['diff --git a/app.ts b/app.ts', '--- a/app.ts', '+++ b/app.ts', '@@ -1,1 +1,3 @@', ' keep', '+++ b/src/evil.ts', '+++i', ''].join('\n')
  const files = parseUnifiedDiff(diff)
  assert.deepEqual(files.map(file => file.path), ['app.ts'])
  assert.deepEqual(files[0].hunks[0].lines.filter(line => line.kind === '+').map(line => line.newLine), [2, 3])
})

test('parser separates deleted, renamed and binary files and ignores no-newline markers', () => {
  const diff = ['diff --git a/gone.ts b/gone.ts', 'deleted file mode 100644', '--- a/gone.ts', '+++ /dev/null', '@@ -1 +0,0 @@', '-requireAuth()', '\\ No newline at end of file', 'diff --git a/old name.ts b/new name.ts', 'similarity index 100%', 'rename from old name.ts', 'rename to new name.ts', 'diff --git a/logo.png b/logo.png', 'Binary files a/logo.png and b/logo.png differ', 'diff --git a/x.ts b/x.ts', '--- a/x.ts', '+++ b/x.ts', '@@ -1,2 +1,2 @@', ' a', '-b', '\\ No newline at end of file', '+c', ''].join('\n')
  const files = parseUnifiedDiff(diff)
  assert.deepEqual(files.map(file => [file.path, file.status, file.binary]), [['gone.ts', 'deleted', false], ['new name.ts', 'renamed', false], ['logo.png', 'modified', true], ['x.ts', 'modified', false]])
  assert.equal(files[1].oldPath, 'old name.ts')
  assert.equal(files[3].hunks[0].lines.find(line => line.kind === '+')?.newLine, 2)
})

test('git quoted paths decode to UTF-8', () => {
  assert.equal(unquoteGitPath('"src/\\344\\270\\255.ts"'), 'src/中.ts')
  assert.equal(unquoteGitPath('plain.ts'), 'plain.ts')
})

test('Diff scan survives deletion-only and non-ASCII changes and keeps both inventories honest', async () => {
  const f = await gitFixture(); try {
    await writeFile(join(f.root, 'gone.ts'), 'requireAuth()\n'); await writeFile(join(f.root, '中文.ts'), 'export const a=1\n'); await writeFile(join(f.root, 'route.ts'), 'export const b=1\n')
    await repo(f.root, 'add', '.'); await repo(f.root, 'commit', '-qm', 'base')
    await rm(join(f.root, 'gone.ts')); await writeFile(join(f.root, '中文.ts'), 'export const a=2\n')
    const scan = await runDiffScan(f.root, undefined, '', f.state)
    assert.deepEqual(scan.coverage.diffInventory?.deleted, ['gone.ts'])
    assert.deepEqual(scan.coverage.receipts.map(receipt => receipt.path), ['中文.ts'])
    assert.ok(scan.coverage.changedLines?.['中文.ts']?.includes(1))
  } finally { await f.done() }
})

test('A deletion-only file no longer crashes the review item view', async () => {
  const f = await gitFixture(); try {
    await writeFile(join(f.root, 'route.ts'), 'function a(){\n  requireAuth()\n  return 1\n}\n')
    await repo(f.root, 'add', '.'); await repo(f.root, 'commit', '-qm', 'base')
    await writeFile(join(f.root, 'route.ts'), 'function a(){\n  return 1\n}\n')
    const scan = await runDiffScan(f.root, undefined, '', f.state); await saveScan(f.state, scan)
    const job = await createDiffDiscoveryJob(f.config, scan.id)
    const stored = JSON.parse(await readFile(join(f.state, 'diff-discovery', `${job.id}.json`), 'utf8'))
    stored.lifecycle = 'running'; stored.workers = [{ id: 'w', status: 'running', token: 't', assignedPaths: ['route.ts'], candidateIds: [] }]
    await writeFile(join(f.state, 'diff-discovery', `${job.id}.json`), JSON.stringify(stored))
    const items = getDiffReviewItems(f.config, job.id, 'w', 't')
    assert.equal(items.changedLinesTruncated, false)
    assert.deepEqual(items.items.map(item => item.path), ['route.ts'])
  } finally { await f.done() }
})

test('Lockfiles cannot consume the patch budget and are recorded as exclusions', async () => {
  const f = await gitFixture(); try {
    await writeFile(join(f.root, 'seed.ts'), 'export {}\n'); await repo(f.root, 'add', '.'); await repo(f.root, 'commit', '-qm', 'base')
    await writeFile(join(f.root, 'package-lock.json'), `${'{"x":1}\n'.repeat(200_000)}`); await writeFile(join(f.root, 'zz_route.ts'), 'export function h(req){eval(req.query.c)}\n')
    await repo(f.root, 'add', '.'); await repo(f.root, 'commit', '-qm', 'change')
    const { stdout } = await repo(f.root, 'rev-parse', 'HEAD~1')
    const scan = await runDiffScan(f.root, stdout.trim(), '', f.state, false, 'branch_diff')
    assert.ok(scan.coverage.receipts.some(receipt => receipt.path === 'zz_route.ts'))
    assert.deepEqual(scan.coverage.diffInventory?.excluded, ['package-lock.json'])
    assert.equal(isExcludedDiffPath('deep/dir/app.min.js'), true)
    assert.equal(isExcludedDiffPath('dist/app.js'), false)
  } finally { await f.done() }
})

test('Removal evidence binds through the shared parser', async () => {
  const f = await gitFixture(); try {
    await writeFile(join(f.root, 'route.ts'), 'function a(){\n  requireAuth()\n  return 1\n}\n')
    await repo(f.root, 'add', '.'); await repo(f.root, 'commit', '-qm', 'base')
    await writeFile(join(f.root, 'route.ts'), 'function a(){\n  return 1\n}\n')
    const scan = await runDiffScan(f.root, undefined, '', f.state); await persistInvestigationArtifacts(f.state, scan); await saveScan(f.state, scan)
    assert.ok(scan.diffArtifact)
    const hunk = parseUnifiedDiff(await readArtifact(scan, scan.diffArtifact!.path))[0]!.hunks[0]!.header
    await assert.doesNotReject(() => bindDiffEvidence(scan, [{ file: 'route.ts', line: 2, excerpt: 'return 1' } as never], { file: 'route.ts', hunk, explanation: 'The removed requireAuth call was the only guard on this route handler.' }))
    await assert.rejects(() => bindDiffEvidence(scan, [{ file: 'route.ts', line: 2, excerpt: 'return 1' } as never], { file: 'other.ts', hunk, explanation: 'The removed requireAuth call was the only guard on this route handler.' }), /real removal hunk/)
  } finally { await f.done() }
})

test('Non-UTF-8 targets are refused rather than corrupted', async () => {
  const f = await fixture(); try {
    const path = join(f.root, 'gbk.txt'), raw = Buffer.from([0xd6, 0xd0, 0xce, 0xc4, 0x0a]); await writeFile(path, raw)
    await assert.rejects(() => replaceExpectedFile(path, sha256(raw.toString('utf8')), 'x'), /UTF-8/)
    assert.deepEqual(await readFile(path), raw)
  } finally { await f.done() }
})

test('Empty export statements do not crash the module graph', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'seed.ts'), 'export {}\nconst a = 1\nexport { a as b }\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false)
    assert.ok(scan.coverage.receipts.some(receipt => receipt.path === 'seed.ts'))
  } finally { await f.done() }
})

test('Blank regions never become unclosable coverage units', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'empty.py'), ''); await writeFile(join(f.root, 'blank.py'), '\n\n\n'); await writeFile(join(f.root, 'real.py'), 'print(1)\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false)
    assert.deepEqual([...new Set((scan.coverage.ledger ?? []).map(unit => unit.path))], ['real.py'])
  } finally { await f.done() }
})

test('Plain English and control flow do not activate deployment or resource domains', () => {
  const ids = selectedDomains('# copied from the docs\nwhile (i < limit) { queue.push(i) }\n').map(domain => domain.id)
  assert.ok(!ids.includes('cloud')); assert.ok(!ids.includes('resources'))
  assert.ok(selectedDomains('FROM node:22-alpine\nRUN npm ci\n').some(domain => domain.id === 'cloud'))
})

test('Cancelled investigations stay cancelled through finalize and final-record preparation', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'app.ts'), 'function h(req) { eval(req.query.code) }\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false); await saveScan(f.state, scan)
    await cancelInvestigation(f.config, scan.id, 'operator stop')
    assert.equal((await completeScan(f.config, scan.id)).lifecycle, 'cancelled')
    assert.equal(await prepareFinalRecordReview(f.config, scan.id), 0)
  } finally { await f.done() }
})

test('Cancellation does not overwrite a concurrent evidence write', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'app.ts'), 'function h(req) { eval(req.query.code) }\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false); await saveScan(f.state, scan)
    const { mutateScan } = await import('../src/scan-store.ts')
    await Promise.all([mutateScan(f.config, scan.id, s => { s.activity.push({ at: new Date().toISOString(), phase: 'reporting', message: 'concurrent-marker' }) }), cancelInvestigation(f.config, scan.id, 'operator stop')])
    assert.ok((await loadScan(f.state, scan.id)).activity.some(row => row.message === 'concurrent-marker'))
  } finally { await f.done() }
})

test('Independent reviewers must read every line they cite', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'app.ts'), 'function h(req) { eval(req.query.code) }\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false); await saveScan(f.state, scan)
    const actor = { id: 'session:validator', role: 'validator' as const, scanId: scan.id }
    await withAuditActor(actor, async () => {
      const claim = (await claimAuditTask(f.config, scan.id, actor.id, 'validation'))!
      const refs = await attachFixtureEndpoints(f.config as never, scan.id, claim.candidateId, claim.claimToken)
      const input = { conclusion: 'reportable', method: 'static', attacker: 'caller', entryPoint: 'h', trustBoundary: 'request', rootControl: 'none', sink: 'eval', impact: 'code execution', directEvidence: 'eval of request data', counterevidence: 'none found', limitations: 'static only', confidence: 'high', sourceReferences: refs } as never
      await assert.rejects(() => recordValidation(f.config, scan.id, claim.candidateId, input, claim.claimToken), /read every cited/)
      const { observeSourceRead } = await import('../src/coverage.ts')
      await observeSourceRead(f.config as never, scan.id, 'app.ts', 1, 1, 'x')
      assert.equal(actorReadLine(await loadScan(f.state, scan.id), actor.id, 'app.ts', 1), true)
      await assert.doesNotReject(() => recordValidation(f.config, scan.id, claim.candidateId, input, claim.claimToken))
    })
  } finally { await f.done() }
})

test('A Diff or partial follow-up never proves an unrelated finding resolved', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'app.ts'), 'function h(req) { eval(req.query.code) }\n')
    const before = await runScan(f.root, f.config, 'standard', '', false, f.state, false)
    const finding = before.findings[0]; finding.fingerprint = 'engine:unique'
    const after = structuredClone(before); after.findings = []; after.coverage.auditComplete = true; after.mode = 'diff'
    assert.deepEqual(compareScans(before, after).resolved, [])
    const full = structuredClone(after); full.mode = 'standard'
    assert.ok(compareScans(before, full).resolved.includes(finding.id))
    full.coverage.receipts = []
    assert.deepEqual(compareScans(before, full).resolved, [])
  } finally { await f.done() }
})

test('Disclosure refuses repository symlinks that point at host secrets', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.state, 'secret'), 'host secret'); await symlink(join(f.state, 'secret'), join(f.root, 'link.txt'))
    await assert.rejects(() => createDisclosureCampaign(f.root, f.config, undefined, [{ id: 'v1', title: 'Issue title', notes: 'Notes describing the issue in enough detail.', sourcePaths: ['link.txt'] }], false), /symbolic/i)
  } finally { await f.done() }
})

test('Generated threat model recognises non-JS route frameworks', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'A.java'), '@RestController class A { @GetMapping("/x") String x(@RequestParam String q) { return q; } }\n')
    await writeFile(join(f.root, 'b.go'), 'package b\nimport "net/http"\nfunc r(){ http.HandleFunc("/y", nil) }\n')
    const model = await generateSourceThreatModel(f.root, f.config)
    assert.match(model, /A\.java`: request-handling/); assert.match(model, /b\.go`: request-handling/)
    assert.match(model, /A\.java`: caller-controlled input/)
  } finally { await f.done() }
})

test('Domain ranking follows the ledger and validators get proof standards, not the hunt list', async () => {
  const f = await fixture(); try {
    await writeFile(join(f.root, 'ipc.ts'), 'ipcMain.handle("x", () => {})\nipcMain.handle("y", () => {})\n')
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state, false)
    assert.deepEqual(rankedDomains(scan, ['ipc.ts']), ['desktop'])
    const validation = skillGuidance('validation', ['web-auth'])
    assert.ok(validation.includes('## 验证与反证'))
    assert.ok(!validation.includes(packagedSkillBody('dsh-edge-discovery', 'references/web-auth.md').split('## 类目检查点')[1]?.slice(0, 80) ?? '\0'))
    assert.ok(domainValidationSection('web-auth').length > 50)
    for (const id of ['web-auth', 'client', 'api-messaging', 'ai-agent', 'supply-chain', 'cloud', 'tenant-lifecycle', 'resources', 'desktop', 'native-memory']) assert.ok(domainValidationSection(id).includes('## 验证与反证'), id)
    assert.match(skillGuidance('attack-path'), /likelihood/i)
  } finally { await f.done() }
})


test('artifact IO refuses symbolic links and preserves the foreign file', async () => {
  const f = await fixture()
  try {
    const scan = await runScan(f.root, f.config, 'standard', '', false, f.state)
    await writeArtifact(scan, 'plain.txt', 'ordinary artifact')
    const outside = join(f.root, 'notes.txt')
    await writeFile(outside, 'ordinary fixture notes')
    await symlink(outside, join(scan.artifacts.directory, 'linked.txt'))
    await symlink(f.root, join(scan.artifacts.directory, 'linked-directory'))
    await assert.rejects(readArtifact(scan, 'linked.txt'), /non-symlink/)
    await assert.rejects(readArtifact(scan, 'linked-directory/notes.txt'), /non-symlink/)
    await assert.rejects(writeArtifact(scan, 'linked-directory/notes.txt', 'replacement'), /non-symlink/)
    assert.equal(await readFile(outside, 'utf8'), 'ordinary fixture notes')
    assert.equal(await readArtifact(scan, 'plain.txt'), 'ordinary artifact')
  } finally { await f.done() }
})

test('a changed symlink leaves a Diff source coverage gap', async () => {
  const f = await gitFixture()
  try {
    await writeFile(join(f.root, 'app.ts'), 'export const value = 1\n')
    await repo(f.root, 'add', 'app.ts')
    await repo(f.root, 'commit', '-qm', 'base')
    const outside = join(f.state, 'notes.txt')
    await writeFile(outside, 'ordinary fixture notes')
    await rm(join(f.root, 'app.ts'))
    await symlink(outside, join(f.root, 'app.ts'))

    const scan = await runDiffScan(f.root, undefined, '', f.state)
    assert.ok(scan.coverage.diffInventory?.omitted.includes('app.ts'))
    assert.equal(scan.coverage.receipts.find(row => row.path === 'app.ts')?.sourceSha256, undefined)
    assert.equal(scan.coverage.complete, false)
  } finally { await f.done() }
})
