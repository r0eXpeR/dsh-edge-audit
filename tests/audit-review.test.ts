import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { withAuditActor } from '../src/audit-context.ts'
import { runDiffScan, runScan } from '../src/scanner.ts'
import { readFrozenSource } from '../src/source-evidence.ts'
import { loadKnowledgeBase, readScanKnowledgeBase } from '../src/llm/knowledge-base.ts'
import { readLlmContext } from '../src/llm/discovery.ts'
import { loadScan, saveScan } from '../src/state.ts'
import { claimAuditTask, recordAttackPath, recordValidation } from '../src/workbench.ts'
import { readScanSource } from '../src/deep-discovery.ts'
import { createLlmDiscoveryJob } from '../src/llm/discovery.ts'
import { investigationStatus } from '../src/investigation-status.ts'
import { fixturePolicyFacts } from './coverage-fixture.ts'
import { confirmedFinding } from '../src/evidence-policy.ts'
import { createDeepInvestigationJob, runDeepInvestigation } from '../src/deep-workflow.ts'
import { loadDeepDiscoveryJob } from '../src/deep-discovery.ts'
import { loadLlmDiscoveryJob } from '../src/llm/discovery.ts'
import { nativeAuditFixture } from './native-audit-fixture.ts'
import { analyzeJavaScriptAst } from '../src/ast-analysis.ts'
import { analyzeGoFlow, analyzePythonFlow } from '../src/flow-analysis.ts'

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-review-source-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-review-state-'))
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 65536, stateDir: state }
  await writeFile(join(root, 'app.ts'), 'export function route(req) { return eval(req.query.code) }\n')
  const scan = await runScan(root, config, 'standard', '', false, state, false)
  await saveScan(state, scan)
  const finding = scan.findings[0]
  const sourceReferences = finding.locations.map(l => ({ file: l.file, line: l.line, role: l.role ?? 'root_control' as const }))
  const validation = {
    conclusion: 'reportable' as const, method: 'static' as const,
    attacker: 'The request caller controls query.code.', entryPoint: 'The exported route request parameter.',
    trustBoundary: 'Request text becomes evaluated code.', rootControl: 'No guard before the eval call.',
    sink: 'eval(req.query.code)', impact: 'Caller-controlled code evaluation.',
    directEvidence: 'The exact query expression is the argument to eval.', counterevidence: 'No local rejecting guard.',
    limitations: 'Static fixture only; no deployment or runtime claim.', confidence: 'medium' as const, sourceReferences,
  }
  const attack = { policyFacts: fixturePolicyFacts, attacker: validation.attacker, entryPoint: validation.entryPoint,
    preconditions: 'The fixture route is invoked.', dataflow: 'req.query.code -> eval(req.query.code)',
    outcome: validation.impact, severityRationale: 'Source-backed execution boundary failure.',
    changeConditions: 'An enforcing upstream guard would change the conclusion.', sourceReferences }
  return { root, state, config, scan, finding, validation, attack,
    async cleanup() { await rm(root, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) } }
}

test('A validator cannot claim its own attack-path review', async () => {
  const f = await fixture()
  try {
    const task = (await claimAuditTask(f.config, f.scan.id, 'reviewer-a', 'validation'))!
    await recordValidation(f.config, f.scan.id, f.finding.candidateId, f.validation, task.claimToken)
    assert.equal(await claimAuditTask(f.config, f.scan.id, 'reviewer-a', 'attack_path'), null)
    assert.ok(await claimAuditTask(f.config, f.scan.id, 'reviewer-b', 'attack_path'))
  } finally { await f.cleanup() }
})

test('Legacy self-reviewed receipts never count as independently confirmed findings', async () => {
  const f = await fixture()
  try {
    const task = (await claimAuditTask(f.config, f.scan.id, 'validator-a', 'validation'))!
    await recordValidation(f.config, f.scan.id, f.finding.candidateId, f.validation, task.claimToken)
    const attack = (await claimAuditTask(f.config, f.scan.id, 'attack-reviewer-b', 'attack_path'))!
    const scan = await recordAttackPath(f.config, f.scan.id, f.finding.candidateId, f.attack, attack.claimToken)
    const finding = scan.findings[0]
    assert.equal(confirmedFinding(finding), true)
    finding.attackPathRecord!.reviewer = finding.validationRecord!.reviewer
    assert.equal(confirmedFinding(finding), false)
  } finally { await f.cleanup() }
})

test('An old claimed task cannot bypass independent attack-path review', async () => {
  const f = await fixture()
  try {
    const task = (await claimAuditTask(f.config, f.scan.id, 'reviewer-a', 'validation'))!
    await recordValidation(f.config, f.scan.id, f.finding.candidateId, f.validation, task.claimToken)
    const attack = (await claimAuditTask(f.config, f.scan.id, 'reviewer-b', 'attack_path'))!
    const retained = await loadScan(f.state, f.scan.id)
    retained.tasks.find(t => t.id === attack.taskId)!.claim!.owner = 'reviewer-a'
    await saveScan(f.state, retained)
    await assert.rejects(() => recordAttackPath(f.config, f.scan.id, f.finding.candidateId, f.attack, attack.claimToken), /independent|validator/i)
  } finally { await f.cleanup() }
})

test('Every validation verdict requires the actual Session to read its citations', async () => {
  for (const conclusion of ['suppressed', 'not_applicable', 'deferred'] as const) {
    const f = await fixture()
    try {
      const actor = { id: `session:${conclusion}`, role: 'validator' as const, scanId: f.scan.id }
      await withAuditActor(actor, async () => {
        const task = (await claimAuditTask(f.config, f.scan.id, actor.id, 'validation'))!
        const input = { ...f.validation, conclusion }
        await assert.rejects(() => recordValidation(f.config, f.scan.id, f.finding.candidateId, input, task.claimToken), /read every cited/)
        await readScanSource(f.config, f.scan.id, 'app.ts', 1, 1)
        await recordValidation(f.config, f.scan.id, f.finding.candidateId, input, task.claimToken)
      })
    } finally { await f.cleanup() }
  }
})

test('Completed discovery does not disable resume while validation remains unfinished', async () => {
  const f = await fixture()
  try {
    const job = await createLlmDiscoveryJob(f.config, f.scan.id)
    job.lifecycle = 'completed'; job.baseline.status = 'completed'
    if (job.architect) job.architect.status = 'completed'
    await writeFile(join(f.state, 'llm-discovery', `${job.id}.json`), JSON.stringify(job))
    const scan = await loadScan(f.state, f.scan.id)
    scan.lifecycle = 'validation'; scan.discoveryStatus = { driver: 'llm', jobId: job.id, lifecycle: 'completed' }
    await saveScan(f.state, scan)
    const status = await investigationStatus(f.config, f.scan.id)
    assert.equal(status.lifecycle, 'validation')
    assert.equal(status.resumable, true)
    assert.deepEqual(status.resume, { tool: 'security_resume_standard_scan', job_id: job.id })
    assert.ok((await readFile(join(f.state, 'llm-discovery', `${job.id}.json`), 'utf8')).includes('completed'))
  } finally { await f.cleanup() }
})

test('Node execFile variants distinguish attacker-selected executable, shell interpolation and safe argv', () => {
  const source = `function route(req) {
    execFile(req.query.executable, [])
    execFileSync('echo', [req.query.message], { shell: true })
    execFile('echo', [req.query.message], { shell: false })
    execFileSync('/usr/bin/printf', ['%s', req.query.message])
  }`
  assert.deepEqual(analyzeJavaScriptAst(source, 'app.ts').candidates.map(c => [c.rule, c.line]), [
    ['shell-command-construction', 2], ['shell-command-construction', 3],
  ])
})

test('Node process checks recognize fixed interpreters without treating literal RegExp.exec as a process sink', () => {
  const source = `function route(req) {
    /^[a-z]+$/.exec(req.query.text)
    new RegExp('^[0-9]+$').exec(req.query.id)
    spawn('/bin/sh', ['-c', req.query.script])
    execFile('node', ['--eval', req.query.code])
    execFileSync('/usr/bin/python3', ['-c', req.query.code])
    spawn('/usr/bin/node', ['fixed-script.js', req.query.text])
    execFile('printf', ['%s', req.query.text])
  }`
  assert.deepEqual(analyzeJavaScriptAst(source, 'app.ts').candidates.map(c => [c.rule, c.line]), [
    ['shell-command-construction', 4], ['shell-command-construction', 5], ['shell-command-construction', 6],
  ])
})

test('Structured process checks distinguish safe argv from command interpreters and attacker-selected executables', () => {
  const python = `import subprocess
def route():
    subprocess.run(['printf', '%s', request.args['text']], shell=False)
    subprocess.run(['sh', '-c', request.args['script']])
    subprocess.run(request.args['command'], shell=True)
    subprocess.run([request.args['executable'], '--version'])
    subprocess.run('date', env=request.json)
`
  assert.deepEqual(analyzePythonFlow(python, 'app.py').filter(c => c.rule === 'shell-command-construction').map(c => c.line), [4, 5, 6])
  const go = `package demo
func Handler() {
    exec.Command("printf", "%s", r.FormValue("text"))
    exec.Command("sh", "-c", r.FormValue("script"))
    exec.Command(r.FormValue("executable"), "--version")
    exec.CommandContext(ctx, "printf", "%s", r.FormValue("text"))
    exec.CommandContext(ctx, "sh", "-c", r.FormValue("script"))
}`
  assert.deepEqual(analyzeGoFlow(go, 'app.go').filter(c => c.rule === 'shell-command-construction').map(c => c.line), [4, 5, 7])
})

test('Deep freezes exact user context and passes it to independent Standard audits', async () => {
  const f = await fixture()
  try {
    const config = { ...f.config, deepScan: { workers: 1 as const, subagents: 1, stopAfterNoNew: 1, stopAfterConsecutiveErrors: 3, maxDiscoveryRuns: 2, maxTimeHours: 1 } }
    const context = 'Deployment assumptions to verify: tenant administrators may configure exports.\nExact user context '.repeat(100)
    const flow = await createDeepInvestigationJob(f.root, config, 'Audit the declared fixture boundary.', false, 2, context)
    const before = await loadDeepDiscoveryJob(config, flow.discoveryJobId)
    assert.equal(before.userContext, context)
    assert.ok((await loadScan(f.state, flow.scanId)).threatModel.includes(context))
    const runtime = nativeAuditFixture(config, { candidate: true })
    const result = await runDeepInvestigation(runtime.ctx as never, config, flow.id)
    assert.equal(result.lifecycle, 'completed')
    const after = await loadDeepDiscoveryJob(config, flow.discoveryJobId)
    for (const worker of after.workers) assert.equal((await loadLlmDiscoveryJob(config, worker.standardJobId!)).userContext, context)
  } finally { await f.cleanup() }
})

test('Commit review materializes and analyzes explicitly changed dist and PHP include files', async () => {
  const f = await fixture()
  const git = promisify(execFile)
  const repo = (...args: string[]) => git('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'user.email=fixture@example.test', '-c', 'user.name=fixture', ...args], { cwd: f.root })
  try {
    await repo('init', '-q')
    await mkdir(join(f.root, 'dist'))
    await writeFile(join(f.root, 'dist/app.ts'), 'export const version = 1;\n')
    await writeFile(join(f.root, 'module.inc'), '<?php\n$value = 1;\n')
    await repo('add', '.'); await repo('commit', '-qm', 'base')
    const source = 'export function changed(req) { return eval(req.query.code) }\n'
    await writeFile(join(f.root, 'dist/app.ts'), source)
    await writeFile(join(f.root, 'module.inc'), "<?php\nsystem($_GET['command']);\n")
    await repo('add', '.'); await repo('commit', '-qm', 'change')
    const scan = await runDiffScan(f.root, 'HEAD', '', f.state, false, 'commit')
    for (const path of ['dist/app.ts', 'module.inc']) {
      const receipt = scan.coverage.receipts.find(r => r.path === path)!
      assert.ok(receipt.sourceSha256, `Missing frozen source for ${path}`)
      assert.ok(await readFrozenSource(scan.evidenceRoot!, receipt))
    }
    assert.ok(scan.findings.some(f => f.locations.some(l => l.file === 'dist/app.ts') && f.cwe === 'CWE-95'))
    assert.ok(scan.findings.some(f => f.locations.some(l => l.file === 'module.inc') && f.cwe === 'CWE-78'))
  } finally { await f.cleanup() }
})

test('Knowledge-base context retains content beyond the initial preview budget', async () => {
  const f = await fixture()
  try {
    const content = 'Source-grounded context.\n'.repeat(1500) + 'DECISIVE_FINAL_CONTEXT_MARKER\n'
    await writeFile(join(f.root, 'context.md'), content)
    const kb = await loadKnowledgeBase(f.root, ['context.md'])
    assert.ok(kb.promptText.includes('DECISIVE_FINAL_CONTEXT_MARKER'))
    assert.equal(kb.skipped.length, 0)
  } finally { await f.cleanup() }
})

test('Discovery and validation share complete frozen knowledge and reject artifact drift', async () => {
  const f = await fixture()
  try {
    const config = { ...f.config, knowledgeBase: ['context.md'] }
    const original = 'Frozen source assumptions.\n'.repeat(1500) + 'ORIGINAL_CONTEXT_TAIL\n'
    await writeFile(join(f.root, 'context.md'), original)
    const job = await createLlmDiscoveryJob(config, f.scan.id)
    job.lifecycle = 'running'; job.baseline.status = 'running'
    await writeFile(join(f.state, 'llm-discovery', `${job.id}.json`), JSON.stringify(job))
    let content = '', offset = 0
    for (;;) {
      const page = await readLlmContext(config, job.id, job.baseline.id, job.baseline.token, 'knowledge_base', offset)
      assert.ok(Buffer.byteLength(page.content) <= 8000)
      content += page.content
      if (page.nextOffset === undefined) break
      offset = page.nextOffset
    }
    assert.ok(content.includes('ORIGINAL_CONTEXT_TAIL'))
    await writeFile(join(f.root, 'context.md'), 'CHANGED_CURRENT_CONTEXT\n')
    assert.equal((await readScanKnowledgeBase(config, f.scan.id)).promptText, content)
    const scan = await loadScan(f.state, f.scan.id)
    await writeFile(join(scan.artifacts.directory, scan.knowledgeBaseSnapshot!.artifactRef), 'tampered context\n')
    await assert.rejects(() => readScanKnowledgeBase(config, f.scan.id), /changed after capture/)
  } finally { await f.cleanup() }
})
