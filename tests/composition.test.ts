import { testSandbox, reviewFixtureCoverage, critiqueFixtureCoverage } from './coverage-fixture.ts'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt'
import { ToolRuntime } from '@deepseek-ai/dsh-tools'
import { apply, inject, name } from '../src/index.ts'

const execFileAsync = promisify(execFile)
// 工具运行上下文必须明确提供 Session 的已选工作目录，不能依赖宿主 cwd 回退。
const fixtureAgent=()=>({session:{id:'composition-root',header:{cwd:process.cwd()}}} as never)

test('the suite composes with DSH registries and cleans up its native tool surface on unload', async () => {
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  const names = ctx.tools.schemas().map(tool => tool.name)
  assert.equal(names.includes('security_scan'), true)
  assert.equal(names.includes('security_start_disclosure_campaign'), true)
  assert.equal(names.includes('security_disclosure_submit_report'), true)
  assert.equal(names.includes('security_review_diff'), true)
  assert.equal(names.includes('security_deep_discovery_capability'), true)
  assert.equal(names.includes('security_run_deep_investigation'), true)
  assert.equal(names.includes('security_resume_deep_investigation'), true)
  assert.equal(names.includes('security_resume_deep_discovery'), true)
  assert.equal(names.includes('security_deep_get_worklist'), true)
  assert.equal(names.includes('security_plan_candidate_validation'), true)
  assert.equal(names.includes('security_run_candidate_runtime_validation'), true)
  assert.equal(names.includes('security_run_candidate_validation_plan'), true)
  assert.equal(names.includes('security_run_remediation_verification'), true)
  assert.equal(names.includes('security_fix_finding'), true)
  assert.equal(names.includes('security_rollback_remediation'), true)
  assert.equal(names.includes('security_tracking_advisory_preview'), true)
  assert.equal(names.includes('security_create_github_security_advisory'), true)
  assert.equal(names.includes('security_import_github_findings'), true)
  assert.equal(names.includes('security_import_ticket_findings'), true)
  assert.equal(names.includes('security_triage_finding_backlog'), true)
  assert.equal(names.includes('security_start_deep_closure'), true)
  assert.equal(names.includes('security_resume_deep_closure'), true)
  assert.equal(names.includes('security_read_scan_source'), true)
  assert.equal(names.includes('security_deep_read_source'), true)
  assert.equal(ctx.tools.get('security_scan')?.output.schema.type, 'object')
  assert.match(ctx.tools.get('security_review_diff')?.description ?? '', /GitHub Actions pull_request_target shell interpolation/)
  assert.deepEqual(ctx.tools.get('security_review_diff')?.parameters.properties.mode.enum, ['working_tree', 'commit', 'branch_diff'])
  assert.deepEqual(ctx.tools.get('security_scan')?.output.schema.required, ['scanId', 'findings', 'reviewedFiles', 'complete'])
  assert.deepEqual(ctx.tools.get('security_assess')?.output.schema.required, ['scanId', 'filesScanned', 'filesSkipped', 'candidates'])
  assert.deepEqual(ctx.tools.get('security_review_diff')?.output.schema.required, ['scanId', 'mode', 'diff', 'truncated'])
  const assembled = await ctx.systemPrompt.assemble()
  assert.equal(assembled.sections.some(section => section.name === 'dsh-edge-audit:workflow'), true)
  await fiber.dispose()
  assert.equal(ctx.tools.get('security_scan'), undefined)
  assert.equal(ctx.tools.get('security_start_disclosure_campaign'), undefined)
  assert.equal(ctx.tools.get('security_import_github_findings'), undefined)
  assert.equal(ctx.tools.get('security_import_ticket_findings'), undefined)
  assert.equal(ctx.tools.get('security_start_deep_closure'), undefined)
  assert.equal(ctx.tools.get('security_run_deep_investigation'), undefined)
  const afterUnload = await ctx.systemPrompt.assemble()
  assert.equal(afterUnload.sections.some(section => section.name === 'dsh-edge-audit:workflow'), false)
})

test('public scan entry points create an investigation instead of auto-confirming static candidates', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-public-scan-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-public-scan-state-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, validationSandbox: testSandbox, stateDir: state })
  try {
    await writeFile(join(workspace, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    process.chdir(workspace)
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'public-scan' as never, name: 'security_scan', arguments: { discovery: 'engine' }, agent: fixtureAgent() })
    assert.equal(result.isError, false, result.isError ? result.error.message : '')
    const value = result.value as { scanId: string; findings: number; complete: boolean }
    assert.equal(value.findings, 1)
    assert.equal(value.complete, false,'inventory and a rule match do not complete a security audit')
    const scan = await (await import('../src/state.ts')).loadScan(state, value.scanId)
    assert.equal(scan.lifecycle, 'validation')
    assert.equal(scan.findings[0]?.disposition, 'discovered')
    assert.equal(scan.findings[0]?.ledger.some(row => row.phase === 'validation'), false)
    assert.equal(scan.tasks.filter(task => task.phase === 'validation').length, 1)
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
    await rm(state, { recursive: true, force: true })
  }
})

test('strict tool output exposes only the declared DTO while retaining imported evidence internally', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-output-'))
  const before = process.cwd()
  const ctx = new Context(); new SystemPrompt(ctx, {}); new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    await writeFile(join(workspace, 'input.json'), JSON.stringify([{ title: 'Fixture alert', description: 'Evidence for local review', cwe: 'CWE-95', locations: [{ file: 'app.ts', line: 1 }] }]))
    process.chdir(workspace)
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'strict-output' as never, name: 'security_import_findings', arguments: { path: 'input.json' },agent:fixtureAgent() })
    assert.equal(result.isError, false, result.isError ? result.error.message : '')
    const rows = result.value as Array<Record<string, unknown>>
    assert.equal(rows.length, 1)
    assert.deepEqual(Object.keys(rows[0]).sort(), ['description', 'id', 'sourcePath', 'sourceSha256', 'title'])
  } finally {
    process.chdir(before); await fiber.dispose(); await rm(workspace, { recursive: true, force: true })
  }
})

test('the DSH tool pipeline records reviewed runtime evidence without auto-confirming the candidate', {skip: !testSandbox ? 'Configure DSH_TEST_SANDBOX_EXECUTABLE and DSH_TEST_SANDBOX_IMAGE for offline runtime integration.' : false}, async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-runtime-tool-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-runtime-tool-state-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  let approvalRequests = 0
  ctx.provide('approval', { async request() { approvalRequests++; return 'allowed-once' } })
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, validationSandbox: testSandbox, stateDir: state })
  try {
    await writeFile(join(workspace, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    await writeFile(join(workspace, 'repro.js'), 'console.log("local reproduction harness")\n')
    process.chdir(workspace)
    const start = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-start' as never, name: 'security_start_investigation', arguments: {}, agent: fixtureAgent() })
    assert.equal(start.isError, false, start.isError ? start.error.message : '')
    const scanId = (start.value as { scanId: string }).scanId
    const claim = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-claim' as never, name: 'security_claim_audit_task', arguments: { scan_id: scanId, owner: 'composition-test', phase: 'validation' }, agent: fixtureAgent() })
    assert.equal(claim.isError, false, claim.isError ? claim.error.message : '')
    const task = claim.value as { candidateId: string; claimToken: string }
    const run = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-run' as never, name: 'security_run_candidate_runtime_validation', arguments: { scan_id: scanId, candidate_id: task.candidateId, claim_token: task.claimToken, method: 'realistic_interface_reproduction', command: 'node repro.js', fixture_paths: ['repro.js'], setup_summary: 'Run the source-receipted local harness in a disposable target copy.', approved: true }, agent: fixtureAgent() })
    assert.equal(run.isError, false, run.isError ? run.error.message : '')
    assert.equal((run.value as { method: string }).method, 'realistic_interface_reproduction')
    const artifact=await ctx.tools.execute({signal:new AbortController().signal,callId:'runtime-artifact-read' as never,name:'security_read_scan_context',arguments:{scan_id:scanId,candidate_id:task.candidateId,kind:'candidate_artifact',artifact_ref:(run.value as {artifactRef:string}).artifactRef},agent:fixtureAgent()})
    assert.equal(artifact.isError,false,artifact.isError?artifact.error.message:'');assert.equal(typeof (artifact.value as {content:string}).content,'string')
    assert.equal(approvalRequests, 1)
    const validation = { scan_id: scanId, candidate_id: task.candidateId, claim_token: task.claimToken, conclusion: 'reportable', method: 'runtime', attacker: 'Remote request sender.', entry_point: 'Request query input.', trust_boundary: 'HTTP request boundary.', root_control: 'Dynamic evaluation.', sink: 'eval invocation.', impact: 'Attacker-controlled execution.', direct_evidence: 'The reviewed local runtime receipt records the disposable harness execution.', counterevidence: 'No compensating local control was found.', limitations: 'The local receipt does not establish production reachability.', confidence: 'medium', source_references: [{ file: 'app.ts', line: 1, role: 'entrypoint' }, { file: 'app.ts', line: 1, role: 'sink' }] }
    const missingReceipt = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-record-missing' as never, name: 'security_record_validation', arguments: validation, agent: fixtureAgent() })
    assert.equal(missingReceipt.isError, true)
    assert.match(missingReceipt.isError ? missingReceipt.error.message : '', /requires at least one candidate-bound runtime receipt/)
    const sourceRead = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-source-read' as never, name: 'security_read_scan_source', arguments: { scan_id: scanId, path: 'app.ts', start_line: 1, end_line: 1 }, agent: fixtureAgent() })
    assert.equal(sourceRead.isError, false, sourceRead.isError ? sourceRead.error.message : '')
    const recorded = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-record' as never, name: 'security_record_validation', arguments: { ...validation, conclusion:'deferred',proof_gaps:['The harness only printed a message and did not observe the vulnerability.'], runtime_receipt_refs: [(run.value as { artifactRef: string }).artifactRef] }, agent: fixtureAgent() })
    assert.equal(recorded.isError, false, recorded.isError ? recorded.error.message : '')
    const scan = await (await import('../src/state.ts')).loadScan(state, scanId)
    assert.equal(scan.findings[0]?.disposition, 'deferred')
    assert.equal(scan.findings[0]?.evidenceLevel,'needs_validation')
    assert.equal(scan.findings[0]?.evidence.some(item => item.kind === 'runtime'), true)
    assert.deepEqual(scan.findings[0]?.validationRecord?.runtimeReceiptRefs, [(run.value as { artifactRef: string }).artifactRef])
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
    await rm(state, { recursive: true, force: true })
  }
})

test('the built npm entrypoint registers and executes through the real DSH tool pipeline', async () => {
  const packageRoot = fileURLToPath(new URL('..', import.meta.url))
  await execFileAsync('npm', ['run', 'build'], { cwd: packageRoot })
  const built = await import('../dist/index.js') as typeof import('../src/index.ts')
  assert.equal('default' in built, false)
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name: built.name, inject: built.inject, apply: built.apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'built-entrypoint' as never, name: 'security_deep_discovery_capability', arguments: {} })
    assert.equal(result.isError, false, result.isError ? result.error.message : '')
    assert.equal(typeof result.value, 'object')
    assert.equal(ctx.tools.get('security_resume_deep_discovery') !== undefined, true)
    assert.equal(ctx.tools.get('security_run_deep_investigation') !== undefined, true)
  } finally {
    await fiber.dispose()
  }
  assert.equal(ctx.tools.get('security_deep_discovery_capability'), undefined)
  assert.equal(ctx.tools.get('security_run_deep_investigation'), undefined)
})

test('write tools require DSH user approval in addition to approved: true', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-approval-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  let approvalRequests = 0
  ctx.provide('approval', {
    async request() {
      approvalRequests += 1
      return 'allowed-once'
    },
  })
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    process.chdir(workspace)
    const missingAcknowledgement = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-false' as never, name: 'security_install_precommit_hook', arguments: { approved: false }, agent: fixtureAgent() })
    assert.equal(missingAcknowledgement.isError, true)
    assert.match(missingAcknowledgement.isError ? missingAcknowledgement.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 0)
    assert.equal(existsSync(join(workspace, '.git', 'hooks', 'pre-commit')), false)

    await execFileAsync('git', ['init', '-q'], { cwd: workspace })
    const approved = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-allowed' as never, name: 'security_install_precommit_hook', arguments: { approved: true }, agent: fixtureAgent() })
    assert.equal(approved.isError, false, approved.isError ? approved.error.message : '')
    assert.equal(approvalRequests, 1)
    assert.match(await readFile(join(workspace, '.git', 'hooks', 'pre-commit'), 'utf8'), /dsh run/)

    const missingVerificationAcknowledgement = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'remediation-verification-false' as never, name: 'security_run_remediation_verification', arguments: { scan_id: 'missing', remediation_id: 'missing', approved: false }, agent: fixtureAgent() })
    assert.equal(missingVerificationAcknowledgement.isError, true)
    assert.match(missingVerificationAcknowledgement.isError ? missingVerificationAcknowledgement.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 1)

    const missingFixAcknowledgement = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'fix-false' as never, name: 'security_fix_finding', arguments: { scan_id: 'missing', finding_id: 'missing', changes: [], rationale: 'reviewed', test_plan: 'run focused tests', approved: false }, agent: fixtureAgent() })
    assert.equal(missingFixAcknowledgement.isError, true)
    assert.match(missingFixAcknowledgement.isError ? missingFixAcknowledgement.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 1)

    const missingRuntimeAcknowledgement = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-validation-false' as never, name: 'security_run_candidate_runtime_validation', arguments: { scan_id: 'missing', candidate_id: 'missing', claim_token: 'missing', method: 'realistic_interface_reproduction', command: 'node repro.js', fixture_paths: ['repro.js'], setup_summary: 'A reviewed disposable local harness.', approved: false }, agent: fixtureAgent() })
    assert.equal(missingRuntimeAcknowledgement.isError, true)
    assert.match(missingRuntimeAcknowledgement.isError ? missingRuntimeAcknowledgement.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 1)

    const approvedRuntime = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'runtime-validation-allowed' as never, name: 'security_run_candidate_runtime_validation', arguments: { scan_id: 'missing', candidate_id: 'missing', claim_token: 'missing', method: 'realistic_interface_reproduction', command: 'node repro.js', fixture_paths: ['repro.js'], setup_summary: 'A reviewed disposable local harness.', approved: true }, agent: fixtureAgent() })
    assert.equal(approvedRuntime.isError, true)
    assert.equal(approvalRequests, 2)

    const approvedVerification = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'remediation-verification-allowed' as never, name: 'security_run_remediation_verification', arguments: { scan_id: 'missing', remediation_id: 'missing', approved: true }, agent: fixtureAgent() })
    assert.equal(approvedVerification.isError, true)
    assert.equal(approvalRequests, 3)
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
  }
})

test('write tools fail closed when their DSH approval route is unavailable', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-no-approval-'))
  const previousDirectory = process.cwd()
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    process.chdir(workspace)
    const denied = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'approval-unavailable' as never, name: 'security_install_precommit_hook', arguments: { approved: true }, agent: fixtureAgent() })
    assert.equal(denied.isError, true)
    assert.match(denied.isError ? denied.error.message : '', /may send source context/)
    assert.equal(existsSync(join(workspace, '.git', 'hooks', 'pre-commit')), false)
  } finally {
    process.chdir(previousDirectory)
    await fiber.dispose()
    await rm(workspace, { recursive: true, force: true })
  }
})

test('GitHub advisory creation is an approval-gated DSH write tool', async () => {
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  let approvalRequests = 0
  ctx.provide('approval', { async request() { approvalRequests++; return 'allowed-once' } })
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '' })
  try {
    const result = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'advisory-approval' as never, name: 'security_create_github_security_advisory', arguments: { scan_id: 'missing', finding_id: 'missing', token: 'test-token', approved: false }, agent: fixtureAgent() })
    assert.equal(result.isError, true)
    assert.match(result.isError ? result.error.message : '', /requires approved: true/)
    assert.equal(approvalRequests, 0)
    const approved = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'advisory-approved' as never, name: 'security_create_github_security_advisory', arguments: { scan_id: 'missing', finding_id: 'missing', token: 'test-token', approved: true }, agent: fixtureAgent() })
    assert.equal(approved.isError, true)
    assert.equal(approvalRequests, 1)
  } finally { await fiber.dispose() }
})

test('finding annotations cannot bypass formal DSH validation and attack-path receipts', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-annotation-'))
  const state = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-annotation-state-'))
  const previousDirectory = process.cwd()
  const ctx = new Context(); new SystemPrompt(ctx, {}); new ToolRuntime(ctx, {})
  const fiber = await ctx.plugin({ name, inject, apply }, { enabled: true, maxFiles: 10, maxFileBytes: 4096, validationSandbox: testSandbox, stateDir: state })
  try {
    await writeFile(join(workspace, 'app.ts'), 'function route(req) { return eval(req.query.code) }\n')
    process.chdir(workspace)
    const started = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'annotation-start' as never, name: 'security_start_investigation', arguments: {}, agent: fixtureAgent() })
    const scanId = (started.value as { scanId: string }).scanId
    const scan = await (await import('../src/state.ts')).loadScan(state, scanId)
    const findingId = scan.findings[0]!.id
    const bypass = await ctx.tools.execute({ signal: new AbortController().signal, callId: 'annotation-bypass' as never, name: 'security_update_finding', arguments: { scan_id: scanId, finding_id: findingId, status: 'false_positive', validation: 'Looks safe.' }, agent: fixtureAgent() })
    assert.equal(bypass.isError, true)
    assert.match(bypass.isError ? bypass.error.message : '', /formal structured validation receipt/)
  } finally { process.chdir(previousDirectory); await fiber.dispose(); await rm(workspace, { recursive: true, force: true }); await rm(state, { recursive: true, force: true }) }
})

test('saved scan tools and history are scoped to the active workspace, including legacy indexes', async () => {
  const first = await mkdtemp(join(tmpdir(), 'dsh-scan-scope-first-'))
  const second = await mkdtemp(join(tmpdir(), 'dsh-scan-scope-second-'))
  const stateDir = await mkdtemp(join(tmpdir(), 'dsh-scan-scope-state-'))
  const ctx = new Context()
  new SystemPrompt(ctx, {})
  new ToolRuntime(ctx, {})
  const config = { enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir }
  const fiber = await ctx.plugin({ name, inject, apply }, config)
  function call(cwd: string, name: string, args: Record<string, string>, id: string) {
    return ctx.tools.execute({
      signal: new AbortController().signal, callId: id as never, name, arguments: args,
      agent: { session: { id: cwd, header: { cwd } } } as never,
    })
  }
  try {
    await writeFile(join(first, 'app.ts'), 'export const value = 1\n')
    const created = await call(first, 'security_start_investigation', {}, 'scope-create')
    assert.equal(created.isError, false)
    const { scanId } = created.value as { scanId: string }
    const indexPath = join(stateDir, 'scan-index', `${scanId}.json`)
    const legacy = JSON.parse(await readFile(indexPath, 'utf8'))
    delete legacy.target
    await writeFile(indexPath, JSON.stringify(legacy))
    const allowed = await call(first, 'security_get_scan', { scan_id: scanId }, 'scope-own')
    assert.equal(allowed.isError, false)
    const denied = await call(second, 'security_export_scan', { scan_id: scanId, format: 'json' }, 'scope-other')
    assert.equal(denied.isError, true)
    assert.match(denied.isError ? denied.error.message : '', /inside the current workspace/)
    const ownHistory = await call(first, 'security_scan_history', {}, 'scope-own-history')
    const otherHistory = await call(second, 'security_scan_history', {}, 'scope-other-history')
    assert.ok((ownHistory.value as Array<{ id: string }>).some(scan => scan.id === scanId))
    assert.deepEqual(otherHistory.value, [])
  } finally {
    await fiber.dispose()
    await Promise.all([first, second, stateDir].map(path => rm(path, { recursive: true, force: true })))
  }
})
