import { mutateScan } from './scan-store.js'
import { readWorkspaceInputFile } from './workspace-file.js'
import { withJobLease } from './job-lease.js'
import { transitionRemediation, type RemediationState } from './remediation-state.js'
import { assertPatchPath,replaceExpectedFile } from './patch-transaction.js'
import { runSandboxedCommand, requireValidationSandbox } from './sandbox.js'
import { lstat, access, cp, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { promisify } from 'node:util'
import { createHash, randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { Finding, ScanRecord } from './contracts.js'
import { runScan, resolveSafeTarget, snapshotDigestForDirectory } from './scanner.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from './state.js'

const execFileAsync = promisify(execFile)
const MAX_COMMAND_OUTPUT = 256_000
const VALIDATION_COMMAND = /^[A-Za-z0-9_./:@=+%, -]+$/
const RUNTIME_METHODS = ['realistic_interface_reproduction', 'debugger_trace', 'sanitizer_or_memory_checker'] as const

export interface CommandReceipt { id: string; command: string; cwd: string; exitCode?: number; timedOut: boolean; durationMs: number; stdout: string; stderr: string; snapshotDigest: string; artifactRef?: string }
export type RuntimeValidationMethod = typeof RUNTIME_METHODS[number]
export interface RuntimeValidationReceipt extends CommandReceipt { method: RuntimeValidationMethod; fixturePaths: string[]; setupSummary: string; limitation: string }
export interface ValidationStrategy { method: 'isolated_project_checks' | 'realistic_interface_reproduction' | 'debugger_trace' | 'sanitizer_or_memory_checker' | 'source_trace'; status: 'runnable_with_approval' | 'requires_explicit_setup' | 'not_applicable' | 'available_without_execution'; rationale: string; requiredEvidence: string[] }
export interface CandidateValidationPlan { id: string; scanId: string; candidateId: string; snapshotDigest: string; projectFiles: string[]; commands: Array<{ command: string; reason: string }>; strategies: ValidationStrategy[]; skipped: Array<{ reason: string }>; createdAt: string }
export interface CandidateValidationPlanRun extends CandidateValidationPlan { approved: true; executedAt: string; receipts: CommandReceipt[]; artifactRef: string }
export interface RemediationReplacement { file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }
export interface RemediationFileSnapshot { file: string; sha256: string }
export interface RemediationRollbackFile extends RemediationFileSnapshot { beforeContent: string; appliedSha256: string }
export interface RemediationVerification { scanId: string; status: 'not_detected' | 'still_detected'; ruleId: string; file: string; matchingFindingIds: string[]; observedAt: string; limitation: string }
export interface RemediationVerificationRun { id: string; remediationId: string; sourceScanId: string; snapshotDigest: string; commands: Array<{ command: string; reason: string }>; receipts: CommandReceipt[]; outcome: 'passed' | 'failed'; executedAt: string; artifactRef: string; limitation: string }
export interface RemediationProposal { id: string; findingId: string; file: string; line: number; patch: string; baseSnapshotDigest: string; baseFileSha256: string; baseFiles?: RemediationFileSnapshot[]; createdAt: string; status: 'proposed' | 'applied' | 'rolled_back' | 'stale' | 'superseded'; /** codex-security remediation attempt state machine. */ state?: 'idle' | 'requested' | 'generated' | 'applied' | 'verifying' | 'verified' | 'failed' | 'superseded'; /** Optimistic-lock version. */ version?: number; requiresApproval: true; requiresReview: true; safeToApply: boolean; rationale: string; testPlan?: string; replacement?: RemediationReplacement; replacements?: RemediationReplacement[]; appliedAt?: string; verificationScanId?: string; verification?: RemediationVerification; postApplyVerification?: RemediationVerificationRun; verificationError?:string;repairReceiptId?:string; rollbackId?: string }
export interface RemediationRollback { id: string; remediationId: string; scanId: string; file: string; beforeContent: string; beforeSha256: string; appliedSha256: string; files?: RemediationRollbackFile[]; appliedSnapshotDigest: string; createdAt: string; status: 'prepared'|'recovery_required'|'available' | 'rolled_back' | 'stale'; rolledBackAt?: string; verificationScanId?: string }
export interface FixFindingResult { outcome: 'fixed' | 'no_change' | 'blocked'; scanId: string; findingId: string; remediationId?: string; verification?: RemediationVerificationRun; stages: Array<{ name: 'scope' | 'proposal' | 'apply' | 'verification'; status: 'passed' | 'failed' | 'unknown'; detail: string }>; limitation: string }

export interface BulkResult { path: string; scanId?: string; findings?: number; error?: string }
export interface BulkJob { id: string; createdAt: string; updatedAt: string; mode: 'standard' | 'deep'; threatModel: string; entries: Array<BulkResult & { status: 'pending' | 'completed' | 'failed'; attempts: number }> }

function inside(root: string, target: string): boolean { const rel = relative(root, target); return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel)) }
function safeCommand(command: string): string { const value = command.trim(); if (!value || value.length > 500 || !VALIDATION_COMMAND.test(value)) throw new Error('Validation command contains unsupported shell syntax. Use a simple executable and arguments only.'); return value }
function splitCommand(command: string): string[] { return safeCommand(command).split(/\s+/).filter(Boolean) }
function commandExecutable(command: string): string { return splitCommand(command)[0]?.split('/').at(-1)?.toLowerCase() ?? '' }
function isLoopbackUrl(value: string): boolean { try { const url = new URL(value); return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) } catch { return false } }
function safeRuntimeCommand(method: RuntimeValidationMethod, command: string): string {
  const value = safeCommand(command); const args = splitCommand(value); const executable = commandExecutable(value)
  if (args.some(argument => /^(?:https?|ftp|ssh):\/\//i.test(argument) && !isLoopbackUrl(argument))) throw new Error('Runtime validation only accepts loopback URLs as direct command arguments; the disposable copy is not a network sandbox.')
  if (method === 'debugger_trace') {
    if (executable === 'gdb' && (args.includes('-batch') || args.includes('--batch')) && args.filter(argument => argument === '-ex' || argument === '--ex').length >= 2) return value
    if (executable === 'lldb' && args.includes('-b') && args.filter(argument => argument === '-o' || argument === '--one-line').length >= 2) return value
    throw new Error('Debugger validation requires non-interactive gdb (-batch with commands) or lldb (-b with commands).')
  }
  if (method === 'sanitizer_or_memory_checker') {
    if (/(?:asan|ubsan|msan|tsan|valgrind|sanitize)/i.test(value)) return value
    throw new Error('Sanitizer validation command must explicitly invoke a sanitizer or memory checker.')
  }
  if (!['node', 'nodejs', 'npm', 'pnpm', 'yarn', 'bun', 'python', 'python3', 'pytest', 'ruby', 'php', 'java', 'dotnet', 'go', 'cargo', 'mvn', 'gradle', 'gradlew'].includes(executable)) throw new Error('Interface validation command must use a supported local runtime or test runner.')
  return value
}
function runtimeMethod(value: string): RuntimeValidationMethod { if ((RUNTIME_METHODS as readonly string[]).includes(value)) return value as RuntimeValidationMethod; throw new Error('Runtime validation method is not supported.') }
function digest(value: string): string { return createHash('sha256').update(value).digest('hex') }
function proposalPath(stateDir: string, id: string): string { if (!/^rem_[0-9a-f-]+$/.test(id)) throw new Error('Invalid remediation id.'); return join(stateDir, 'remediations', `${id}.json`) }
function rollbackPath(stateDir: string, id: string): string { if (!/^rollback_[0-9a-f-]+$/.test(id)) throw new Error('Invalid remediation rollback id.'); return join(stateDir, 'remediation-rollbacks', `${id}.json`) }
async function atomicWrite(path: string, content: string): Promise<void> { const temporary = `${path}.${randomUUID()}.tmp`; await mkdir(resolve(path, '..'), { recursive: true,mode:0o700 }); await writeFile(temporary, content, {encoding:'utf8',mode:0o600}); await rename(temporary, path) }
async function saveProposal(stateDir: string, proposal: RemediationProposal): Promise<void> { await atomicWrite(proposalPath(stateDir, proposal.id), `${JSON.stringify(proposal, null, 2)}\n`) }
export async function loadRemediationProposal(stateDir: string, id: string): Promise<RemediationProposal> { return JSON.parse(await readFile(proposalPath(stateDir, id), 'utf8')) as RemediationProposal }
async function saveRollback(stateDir: string, rollback: RemediationRollback): Promise<void> { await atomicWrite(rollbackPath(stateDir, rollback.id), `${JSON.stringify(rollback, null, 2)}\n`) }
export async function loadRemediationRollback(stateDir: string, id: string): Promise<RemediationRollback> { return JSON.parse(await readFile(rollbackPath(stateDir, id), 'utf8')) as RemediationRollback }
function bulkJobPath(stateDir: string, id: string): string { if (!/^bulk_[0-9a-f-]+$/.test(id)) throw new Error('Invalid bulk job id.'); return join(stateDir, 'bulk-jobs', `${id}.json`) }
async function saveBulkJob(stateDir: string, job: BulkJob): Promise<void> { job.updatedAt = new Date().toISOString(); await atomicWrite(bulkJobPath(stateDir, job.id), `${JSON.stringify(job, null, 2)}\n`) }
export async function loadBulkJob(stateDir: string, id: string): Promise<BulkJob> { return JSON.parse(await readFile(bulkJobPath(stateDir, id), 'utf8')) as BulkJob }

function rethrowIfCancelled(signal: AbortSignal | undefined, error?: unknown): void {
  if (signal?.aborted || (error as { name?: string } | undefined)?.name === 'AbortError') throw error ?? new DOMException('Validation was cancelled.', 'AbortError')
}

/** 宿主准备副本也有磁盘/文件数上限；目标代码尚未执行，不复制凭据、链接或特殊文件。 */
async function copyValidationSource(target:string,destination:string,signal:AbortSignal|undefined,config:Config):Promise<void>{
 let bytes=0,entries=0
 const {realpath}=await import('node:fs/promises'),canonicalTarget=await realpath(target),canonicalState=await realpath(getStateDir(config.stateDir)).catch(()=>getStateDir(config.stateDir))
 await cp(target,destination,{recursive:true,dereference:false,filter:async source=>{
  signal?.throwIfAborted();if(++entries>20000)throw new Error('Validation scratch inventory exceeds 20,000 entries; use a smaller dummy fixture.')
  const canonicalSource=join(canonicalTarget,relative(target,source));if(canonicalSource===canonicalState||canonicalSource.startsWith(canonicalState+sep))return false
  const parts=relative(target,source).split(sep)
  if(parts.some(part=>['.git','node_modules','dist','build','coverage','.artifacts','.sandbox','.dsh-edge-audit','.dsh-fonshang-audit','.dsh-security-suite','.ssh','.aws','.azure','.kube','.npmrc','.pypirc','.netrc'].includes(part)||/^\.env(?:\.|$)|^credentials(?:\.|$)|^id_(?:rsa|ed25519|ecdsa)$/.test(part)))return false
  const info=await lstat(source)
  if(info.isSymbolicLink()||(!info.isDirectory()&&!info.isFile()))return false
  if(info.isFile()){if(info.nlink!==1||info.size>10485760||bytes+info.size>67108864)throw new Error('Validation scratch copy exceeds file/link/disk limits; use a smaller dummy fixture.');bytes+=info.size;const content=await readFile(source);if(/-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----/.test(content.toString('utf8'))&&!config.validationSandbox?.allowedDummyCredentialDigests?.includes(sha256(content)))throw new Error('Private-key material was found before target execution. Use an isolated dummy fixture; only a trusted profile may allow exact non-production credential digests.')}
  return true
 }})
}

function assertNoCredentialExecution(scan:ScanRecord){if(scan.blockedCredentialContext||scan.findings.some(f=>f.cwe==='CWE-798'&&!['suppressed','not_applicable'].includes(f.disposition)))throw new Error('Unresolved embedded credentials are present. Prepare and scan a dummy-credential fixture before executing validation.')}

export async function runIsolatedValidation(workspace: string, config: Config, scanId: string, command: string, timeoutMs = 120_000, signal?: AbortSignal): Promise<CommandReceipt> {
  signal?.throwIfAborted()
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const root = resolve(workspace); const target = resolve(scan.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  requireValidationSandbox(config)
  assertNoCredentialExecution(scan)
  const args = splitCommand(command); const timeout = Math.max(1_000, Math.min(timeoutMs, 600_000)); const copyRoot = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-validation-'))
  const copyTarget = join(copyRoot, 'target')
  const started = Date.now(); let stdout = ''; let stderr = ''; let exitCode: number | undefined; let timedOut = false
  try {
    signal?.throwIfAborted()
    await copyValidationSource(target,copyTarget,signal,config)
    signal?.throwIfAborted()
    const result=await runSandboxedCommand(config,copyTarget,args,timeout,signal); ({stdout,stderr,exitCode,timedOut}=result)
    const receipt: CommandReceipt = { id: `cmd_${randomUUID()}`, command: args.join(' '), cwd: '.', exitCode, timedOut, durationMs: Date.now() - started, stdout: stdout.slice(0, MAX_COMMAND_OUTPUT), stderr: stderr.slice(0, MAX_COMMAND_OUTPUT), snapshotDigest: await snapshotDigestForDirectory(target, config) }
    const receiptPath = join(getStateDir(config.stateDir), 'validation-receipts', `${receipt.id}.json`)
    receipt.artifactRef = receiptPath
    await atomicWrite(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`)
    return receipt
  } finally { await rm(copyRoot, { recursive: true, force: true }) }
}

/**
 * Bind a disposable test/build execution to one claimed validation task.
 * A command receipt is evidence only; the reviewer still records the final
 * source/runtime conclusion with recordValidation.
 */
export async function runCandidateValidation(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, command: string, timeoutMs = 120_000, signal?: AbortSignal): Promise<CommandReceipt> {
  signal?.throwIfAborted()
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const currentSnapshot = await snapshotDigestForDirectory(scan.target, config); if (currentSnapshot !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before attaching validation evidence.')
  const receipt = await runIsolatedValidation(workspace, config, scanId, command, timeoutMs, signal)
  if (receipt.snapshotDigest !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed during isolated validation; the receipt was retained externally but was not attached to this scan.')
  return mutateScan(config, scanId, async reloaded => {
  const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while the command was running; the receipt was retained externally but was not attached.')
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/${receipt.id}.json`
  const attached = { ...receipt, artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(attached, null, 2)}\n`)
  const outcome = receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`
  currentFinding.evidence.push({ kind: 'test', detail: `Isolated validation command \`${receipt.command}\` ${outcome}; interpret this receipt with source and runtime context.`, artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Attached isolated validation receipt ${receipt.id}: ${outcome}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `test:${receipt.id}`
  await persistInvestigationArtifacts(state, reloaded)
  return attached
  })
}

/**
 * Run a reviewed local interface, debugger, or sanitizer command in a
 * disposable target copy. The receipt is runtime evidence only: it cannot
 * independently promote, suppress, or resolve the candidate.
 */
export async function runCandidateRuntimeValidation(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, methodInput: string, command: string, fixturePaths: string[], setupSummary: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<RuntimeValidationReceipt> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Runtime validation can execute a reviewed local interface, debugger, or sanitizer command. Set approved to true only after reviewing its fixture paths and command.')
  const method = runtimeMethod(methodInput); const boundedCommand = safeRuntimeCommand(method, command)
  const setup = setupSummary.trim(); if (!setup || setup.length > 20_000) throw new Error('Runtime validation requires a bounded setup summary.')
  const fixtures = [...new Set(fixturePaths.map(path => path.trim()))]
  if (!fixtures.length || fixtures.length > 20 || fixtures.some(path => !path || isAbsolute(path) || path.split(/[\\/]+/).includes('..'))) throw new Error('Runtime validation requires one to twenty workspace-relative fixture paths.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.mode === 'diff') throw new Error('Runtime validation needs a full source snapshot; create a standard or deep follow-up scan for a diff candidate.')
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const receiptPaths = new Set(scan.coverage.receipts.map(receipt => receipt.path))
  if (fixtures.some(path => !receiptPaths.has(path))) throw new Error('Every runtime validation fixture must be a scan-receipted source path.')
  const before = await snapshotDigestForDirectory(scan.target, config); if (before !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before attaching runtime evidence.')
  const commandReceipt = await runIsolatedValidation(workspace, config, scanId, boundedCommand, timeoutMs, signal)
  if (commandReceipt.snapshotDigest !== scan.targetSnapshot.snapshotDigest) throw new Error('Target changed during runtime validation; the receipt was retained externally but was not attached to this scan.')
  const reloaded = await loadScan(state, scanId); const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while runtime validation was running; the receipt was retained externally but was not attached.')
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/runtime_${commandReceipt.id}.json`
  const receipt: RuntimeValidationReceipt = { ...commandReceipt, method, fixturePaths: fixtures.sort(), setupSummary: setup, limitation: 'This controlled, disposable-copy execution is runtime evidence only. It does not establish production reachability, prove all attacker paths, or automatically decide the candidate disposition. Execution used an offline, read-only-host Docker sandbox with explicit resource limits and a sanitized environment.', artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(receipt, null, 2)}\n`)
  const outcome = receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`
  currentFinding.evidence.push({ kind: 'runtime', detail: `${method} command \`${receipt.command}\` ${outcome}; fixture paths: ${receipt.fixturePaths.join(', ')}. Interpret this receipt with source and runtime context.`, artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Attached ${method} runtime receipt ${receipt.id}: ${outcome}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `runtime:${receipt.id}`
  await persistInvestigationArtifacts(state, reloaded); await saveScan(state, reloaded)
  return receipt
}

/**
 * Create a read-only validation plan from scan-time preflight evidence. It never
 * invents commands or reads a changed target to decide what should execute.
 */
export async function planCandidateValidation(config: Config, scanId: string, candidateId: string): Promise<CandidateValidationPlan> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const commands = [...new Set(scan.preflight.suggestedCommands.map(command => safeCommand(command)))].map(command => ({ command, reason: `Suggested by scan-time project preflight for ${scan.preflight.projectFiles.join(', ')}.` }))
  const languages = new Set(scan.preflight.languages); const compiled = ['c', 'cpp', 'rust', 'go', 'java', 'csharp'].some(language => languages.has(language))
  const interfaceEvidence = finding.locations.some(location => /(?:route|handler|controller|api|server|cli|command|parser|plugin)/i.test(location.file)) || /(?:request|route|handler|http|cli|parser|plugin)/i.test(`${finding.rootCause}\n${finding.validation}`)
  const strategies: ValidationStrategy[] = [
    { method: 'isolated_project_checks', status: commands.length ? 'runnable_with_approval' : 'not_applicable', rationale: commands.length ? 'The scan-time manifest supplies bounded test/build commands that can run in a disposable copy.' : 'No scan-time manifest mapped to a bounded local test or build command.', requiredEvidence: commands.length ? ['DSH one-shot user approval', 'unchanged scan snapshot'] : ['a recognized project manifest with a bounded command'] },
    { method: 'realistic_interface_reproduction', status: interfaceEvidence ? 'requires_explicit_setup' : 'not_applicable', rationale: interfaceEvidence ? 'Source evidence suggests a user-reachable interface, but the scan does not establish a safe command, test fixture, credentials, or service configuration.' : 'The retained finding evidence does not establish a concrete user-reachable interface.', requiredEvidence: interfaceEvidence ? ['explicit local interface command', 'safe fixture or disposable environment', 'unchanged scan snapshot'] : ['source evidence of a concrete interface'] },
    { method: 'debugger_trace', status: compiled ? 'requires_explicit_setup' : 'not_applicable', rationale: compiled ? 'A compiled stack is present, but the scan does not prove that a debugger is installed or that a non-interactive trace is proportionate.' : 'No compiled stack was recorded by scan preflight.', requiredEvidence: compiled ? ['non-interactive debugger command', 'debug symbols or traceable build', 'explicit local environment authorization'] : ['compiled source language'] },
    { method: 'sanitizer_or_memory_checker', status: compiled ? 'requires_explicit_setup' : 'not_applicable', rationale: compiled ? 'A compiled stack is present, but no sanitizer, memory checker, or compatible build configuration was detected from frozen scan context.' : 'No compiled stack was recorded by scan preflight.', requiredEvidence: compiled ? ['explicit sanitizer or checker command', 'compatible instrumented build', 'safe disposable workload'] : ['compiled source language'] },
    { method: 'source_trace', status: 'available_without_execution', rationale: 'Reopen the scan-receipted source to prove attacker, entry point, boundary, control, sink, impact, counterevidence, and remaining proof gaps without asserting runtime behavior.', requiredEvidence: ['scan-receipted source', 'validation receipt with counterevidence and limitations'] },
  ]
  const skipped = commands.length ? [] : [{ reason: scan.preflight.projectFiles.length ? 'Recognized project manifests did not map to a bounded local validation command.' : 'No recognized project manifest was present during scan preflight.' }]
  return { id: `plan_${randomUUID()}`, scanId, candidateId, snapshotDigest: scan.targetSnapshot.snapshotDigest, projectFiles: [...scan.preflight.projectFiles], commands, strategies, skipped, createdAt: new Date().toISOString() }
}

async function executeValidationCommands(config: Config, target: string, commands: string[], timeoutMs: number, snapshotDigest: string, signal?: AbortSignal): Promise<CommandReceipt[]> {
  requireValidationSandbox(config)
  const timeout = Math.max(1_000, Math.min(timeoutMs, 600_000)); const copyRoot = await mkdtemp(join(tmpdir(), 'dsh-edge-audit-validation-plan-')); const copyTarget = join(copyRoot, 'target')
  try {
    signal?.throwIfAborted()
    await copyValidationSource(target,copyTarget,signal,config)
    const receipts: CommandReceipt[] = []
    for (const command of commands) {
      signal?.throwIfAborted()
      const args = splitCommand(command); const started = Date.now(); let stdout = ''; let stderr = ''; let exitCode: number | undefined; let timedOut = false
      const result=await runSandboxedCommand(config,copyTarget,args,timeout,signal);({stdout,stderr,exitCode,timedOut}=result)
      receipts.push({ id: `cmd_${randomUUID()}`, command: args.join(' '), cwd: '.', exitCode, timedOut, durationMs: Date.now() - started, stdout: stdout.slice(0, MAX_COMMAND_OUTPUT), stderr: stderr.slice(0, MAX_COMMAND_OUTPUT), snapshotDigest })
    }
    return receipts
  } finally { await rm(copyRoot, { recursive: true, force: true }) }
}

/** Execute only a persisted-preflight plan, retaining every command outcome as candidate evidence. */
export async function runCandidateValidationPlan(workspace: string, config: Config, scanId: string, candidateId: string, claimToken: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<CandidateValidationPlanRun> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Executing a validation plan can run project test/build scripts. Set approved to true only after reviewing the planned commands.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId)
  if (scan.lifecycle === 'completed') throw new Error('Completed scans cannot accept new validation evidence.')
  const finding = scan.findings.find(item => item.candidateId === candidateId); if (!finding) throw new Error('Candidate was not found in this scan.')
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === 'validation' && item.status === 'claimed')
  if (!task || task.claim?.token !== claimToken) throw new Error('Claim token does not own this candidate validation task.')
  const plan = await planCandidateValidation(config, scanId, candidateId)
  if (!plan.commands.length) throw new Error(`No bounded validation command is available: ${plan.skipped.map(item => item.reason).join(' ')}`)
  const before = await snapshotDigestForDirectory(scan.target, config); if (before !== plan.snapshotDigest) throw new Error('Target changed since this scan. Create a follow-up scan before executing validation.')
  assertNoCredentialExecution(scan)
  const receipts = await executeValidationCommands(config, resolve(scan.target), plan.commands.map(item => item.command), timeoutMs, plan.snapshotDigest, signal)
  const after = await snapshotDigestForDirectory(scan.target, config); if (after !== plan.snapshotDigest) throw new Error('Target changed during isolated validation; receipts were not attached to this scan.')
  const reloaded = await loadScan(state, scanId); const currentFinding = reloaded.findings.find(item => item.candidateId === candidateId); const currentTask = reloaded.tasks.find(item => item.id === task.id)
  if (!currentFinding || !currentTask || currentTask.status !== 'claimed' || currentTask.claim?.token !== claimToken) throw new Error('Candidate validation task changed while commands were running; receipts were not attached.')
  const attached = receipts.map(receipt => ({ ...receipt, artifactRef: `artifacts/05_findings/${candidateId}/validation_artifacts/${receipt.id}.json` }))
  for (const receipt of attached) await writeArtifact(reloaded, receipt.artifactRef!, `${JSON.stringify(receipt, null, 2)}\n`)
  const artifactRef = `artifacts/05_findings/${candidateId}/validation_artifacts/${plan.id}.json`; const run: CandidateValidationPlanRun = { ...plan, approved: true, executedAt: new Date().toISOString(), receipts: attached, artifactRef }
  await writeArtifact(reloaded, artifactRef, `${JSON.stringify(run, null, 2)}\n`)
  const outcomes = attached.map(receipt => receipt.timedOut ? `${receipt.command}: timed out` : receipt.exitCode === 0 ? `${receipt.command}: passed` : `${receipt.command}: failed`).join('; ')
  for (const receipt of attached) currentFinding.evidence.push({ kind: 'test', detail: `Planned isolated validation command \`${receipt.command}\` ${receipt.timedOut ? 'timed out' : receipt.exitCode === 0 ? 'completed successfully' : `exited with ${receipt.exitCode ?? 'an unknown status'}`}; interpret this receipt with source and runtime context.`, artifactRef: receipt.artifactRef })
  currentFinding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: 'discovered', summary: `Executed preflight-derived validation plan ${plan.id}: ${outcomes}. Final validation conclusion remains pending.`, artifactRef })
  currentTask.receipt = `validation-plan:${plan.id}`
  await persistInvestigationArtifacts(state, reloaded); await saveScan(state, reloaded)
  return run
}

export async function rerunSavedScan(workspace: string, config: Config, scanId: string): Promise<ScanRecord> {
  const previous = await loadScan(getStateDir(config.stateDir), scanId)
  if (previous.mode === 'diff') throw new Error('Diff scans must be rerun with security_review_diff so the requested base can be supplied explicitly.')
  const root = resolve(workspace); const target = resolve(previous.target)
  if (!inside(root, target)) throw new Error('Saved scan target is outside the active workspace.')
  const scan = await runScan(target, config, previous.mode, previous.threatModel, previous.recipe.scopeRequested, config.stateDir, false)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan)
  return scan
}

export async function bulkScan(workspace: string, config: Config, paths: string[], mode: 'standard' | 'deep', threatModel: string, concurrency: number): Promise<BulkResult[]> {
  const unique = [...new Set(paths)].sort()
  if (unique.length === 0) throw new Error('At least one workspace-relative path is required.')
  const capped = Math.max(1, Math.min(concurrency, 4)); const output: BulkResult[] = new Array(unique.length); let cursor = 0
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++; if (index >= unique.length) return
      const item = unique[index]
      try { const scan = await runScan(resolveSafeTarget(workspace, item), config, mode, threatModel, true, config.stateDir, false); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); await saveScan(getStateDir(config.stateDir), scan); output[index] = { path: item, scanId: scan.id, findings: scan.findings.length } } catch (error) { output[index] = { path: item, error: error instanceof Error ? error.message : String(error) } }
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, unique.length) }, worker)); return output
}

/** 解析一行 RFC 4180 风格 CSV：支持带引号字段、字段内逗号与双写引号转义。 */
export function csvFields(line: string): string[] {
  const fields: string[] = []; let current = ''; let quoted = false
  for (let index = 0; index < line.length; index++) {
    const char = line[index]
    if (quoted) {
      if (char === '"' && line[index + 1] === '"') { current += '"'; index++ }
      else if (char === '"') quoted = false
      else current += char
    } else if (char === '"' && current.trim() === '') { quoted = true; current = '' }
    else if (char === ',') { fields.push(current.trim()); current = '' }
    else current += char
  }
  fields.push(current.trim())
  return fields
}

export function csvPaths(content: string): string[] {
  const lines = content.replace(/^\uFEFF/, '').split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#')); if (!lines.length) throw new Error('CSV input contains no target paths.')
  const first = csvFields(lines[0]); const pathColumn = first.findIndex(value => /^path$/i.test(value)); const start = pathColumn >= 0 ? 1 : 0; const column = pathColumn >= 0 ? pathColumn : 0
  const paths = lines.slice(start).map(line => csvFields(line)[column] ?? '').filter(Boolean)
  if (paths.length > 500) throw new Error('CSV input lists more than 500 targets; split it into smaller bulk jobs.')
  return paths
}

async function executeBulkJob(workspace: string, config: Config, job: BulkJob, concurrency: number): Promise<BulkJob> {
  const capped = Math.max(1, Math.min(concurrency, 4)); let cursor = 0; const state = getStateDir(config.stateDir)
  const worker = async (): Promise<void> => {
    while (true) {
      const index = cursor++; const entry = job.entries[index]; if (!entry) return; if (entry.status === 'completed') continue
      entry.attempts++; entry.error = undefined
      try { const target = resolveSafeTarget(workspace, entry.path); const targetInfo = await access(target).then(() => true).catch(() => false); if (!targetInfo) throw new Error('Bulk target directory does not exist or cannot be accessed.'); const scan = await runScan(target, config, job.mode, job.threatModel, true, config.stateDir, false); await persistInvestigationArtifacts(state, scan); await saveScan(state, scan); entry.scanId = scan.id; entry.findings = scan.findings.length; entry.status = 'completed' } catch (error) { entry.status = 'failed'; entry.error = error instanceof Error ? error.message : String(error) }
      await saveBulkJob(state, job)
    }
  }
  await Promise.all(Array.from({ length: Math.min(capped, job.entries.length) }, worker)); return job
}

export async function startBulkCsvJob(workspace: string, config: Config, csvPath: string, mode: 'standard' | 'deep', threatModel: string, concurrency: number): Promise<BulkJob> {
  const root = resolve(workspace)
  // 拒绝符号链接：否则仓库内的 `targets.csv -> ~/.aws/credentials` 会把宿主文件逐行回显为 entries[].path。
  const { content } = await readWorkspaceInputFile(root, csvPath, 1024 * 1024)
  const paths = [...new Set(csvPaths(content))].sort(); const now = new Date().toISOString(); const job: BulkJob = { id: `bulk_${randomUUID()}`, createdAt: now, updatedAt: now, mode, threatModel, entries: paths.map(path => ({ path, status: 'pending', attempts: 0 })) }
  await saveBulkJob(getStateDir(config.stateDir), job); return executeBulkJob(root, config, job, concurrency)
}

export async function resumeBulkJob(workspace: string, config: Config, jobId: string, concurrency: number): Promise<BulkJob> { const job = await loadBulkJob(getStateDir(config.stateDir), jobId); return executeBulkJob(resolve(workspace), config, job, concurrency) }

export async function installPreCommitHook(workspace: string, approved: boolean): Promise<{ installed: boolean; path: string; reason?: string }> {
  if (!approved) throw new Error('Installing a Git hook changes the repository. Set approved to true only after the hook content has been reviewed.')
  const root = resolve(workspace); const hookDirectory = join(root, '.git', 'hooks'); const hookPath = join(hookDirectory, 'pre-commit')
  if (!(await lstat(join(root, '.git'))).isDirectory()) throw new Error('Hook installation requires a local .git directory.')
  await mkdir(hookDirectory, { mode: 0o755 }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== 'EEXIST') throw error
  })
  if (!(await lstat(hookDirectory)).isDirectory()) throw new Error('Hook installation requires a non-symlink hooks directory.')
  const content = `#!/bin/sh\n# Installed by dsh-edge-audit. Run DSH security review before committing.\n# dsh run uses the configured model provider and may send source context to it.\nif command -v dsh >/dev/null 2>&1; then\n  dsh run "Review the current Git diff for security findings using security_review_diff. Report high-confidence issues only." || exit $?\nfi\n`
  try {
    await writeFile(hookPath, content, { encoding: 'utf8', mode: 0o755, flag: 'wx' })
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      return { installed: false, path: hookPath, reason: 'An existing pre-commit hook was preserved.' }
    }
    throw error
  }
  return { installed: true, path: hookPath }
}

function replacementFor(finding: Finding, source: string): { content: string; rationale: string } | undefined {
  if (finding.ruleId === 'tls.verification.disabled') {
    const content = source.replace(/rejectUnauthorized\s*:\s*false/g, 'rejectUnauthorized: true').replace(/verify\s*=\s*False/g, 'verify = True').replace(/InsecureSkipVerify\s*:\s*true/g, 'InsecureSkipVerify: false').replace(/CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/g, 'CURLOPT_SSL_VERIFYPEER, 1')
    return content === source ? undefined : { content, rationale: 'This proposal changes only an explicit TLS certificate-verification disablement to its enabled boolean value.' }
  }
  if (finding.ruleId === 'jwt.verification.disabled') {
    const content = source.replace(/(["']?verify_signature["']?\s*[:=]\s*)False/g, '$1True')
    return content === source ? undefined : { content, rationale: 'This proposal changes only an explicit JWT signature-verification disablement to enabled.' }
  }
  return undefined
}

function lineReplacement(source: string, replacement: RemediationReplacement): string | undefined {
  // 奇数下标是原始换行符；逐行保留，避免改一行就把 CRLF 文件整体改成 LF。
  const parts = source.split(/(\r?\n)/); const lines = parts.filter((_, index) => index % 2 === 0); const breaks = parts.filter((_, index) => index % 2 === 1)
  const start = replacement.startLine - 1; const end = replacement.endLine
  if (start < 0 || end < replacement.startLine || end > lines.length) return undefined
  if (lines.slice(start, end).join('\n') !== replacement.expectedText) return undefined
  const eol = breaks[start] ?? breaks[start - 1] ?? '\n'
  const before = lines.slice(0, start).map((line, index) => line + breaks[index]).join('')
  const after = lines.slice(end).map((line, index) => line + (breaks[end + index] ?? '')).join('')
  return before + replacement.replacementText.split('\n').join(eol) + (end < lines.length ? breaks[end - 1] + after : '')
}

function patchFor(file: string, replacement: RemediationReplacement): string {
  return `--- a/${file}\n+++ b/${file}\n@@ lines ${replacement.startLine}-${replacement.endLine} @@\n${replacement.expectedText.split('\n').map(line => `- ${line}`).join('\n')}\n${replacement.replacementText.split('\n').map(line => `+ ${line}`).join('\n')}`
}

function proposalReplacements(proposal: RemediationProposal): RemediationReplacement[] {
  const values = proposal.replacements?.length ? proposal.replacements : proposal.replacement ? [proposal.replacement] : []
  return values.map(replacement => ({ ...replacement, file: replacement.file || proposal.file }))
}

function proposalFiles(proposal: RemediationProposal): RemediationFileSnapshot[] {
  return proposal.baseFiles?.length ? proposal.baseFiles : [{ file: proposal.file, sha256: proposal.baseFileSha256 }]
}

function rollbackFiles(rollback: RemediationRollback): RemediationRollbackFile[] {
  if (rollback.files?.length) return rollback.files
  return [{ file: rollback.file, sha256: rollback.beforeSha256, beforeContent: rollback.beforeContent, appliedSha256: rollback.appliedSha256 }]
}

function reviewedChanges(input: { changes?: Array<{ file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }>; file?: string; startLine?: number; endLine?: number; expectedText?: string; replacementText?: string }): RemediationReplacement[] {
  const changes = input.changes?.length ? input.changes : input.file !== undefined && input.startLine !== undefined && input.endLine !== undefined && input.expectedText !== undefined && input.replacementText !== undefined ? [{ file: input.file, startLine: input.startLine, endLine: input.endLine, expectedText: input.expectedText, replacementText: input.replacementText }] : []
  if (!changes.length || changes.length > 20) throw new Error('A reviewed remediation requires one to twenty bounded source changes.')
  if (new Set(changes.map(change => change.file)).size !== changes.length) throw new Error('A reviewed remediation supports one bounded replacement per file; combine adjacent changes before proposing.')
  return changes.map(change => ({ file: change.file, startLine: change.startLine, endLine: change.endLine, expectedText: change.expectedText, replacementText: change.replacementText }))
}

function remediationVerification(scan: ScanRecord, original: Finding): RemediationVerification {
  const matching = scan.findings.filter(finding => finding.ruleId === original.ruleId && finding.locations.some(location => location.file === original.locations[0]?.file))
  return { scanId: scan.id, status: matching.length ? 'still_detected' : 'not_detected', ruleId: original.ruleId, file: original.locations[0]?.file ?? '', matchingFindingIds: matching.map(finding => finding.id), observedAt: new Date().toISOString(), limitation: 'This is a post-change native-analysis observation, not proof that all exploit paths, runtime configurations, or regressions are resolved. Run the proposal test plan and complete source-backed review.' }
}

/**
 * Persist a reviewed, bounded source replacement for a reportable finding.
 * This is deliberately not an arbitrary shell patch: application requires an
 * exact snapshot and exact original source region, then performs the existing
 * rollback and verification workflow.
 */
export async function proposeReviewedRemediation(workspace: string, config: Config, scanId: string, findingId: string, input: { changes?: Array<{ file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }>; file?: string; startLine?: number; endLine?: number; expectedText?: string; replacementText?: string; rationale: string; testPlan: string }): Promise<RemediationProposal> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  if (finding.disposition !== 'reportable' || finding.validationRecord?.conclusion !== 'reportable') throw new Error('A reviewed remediation proposal requires a reportable finding with a structured reportable validation receipt.')
  if (input.rationale.trim().length < 20 || input.testPlan.trim().length < 10) throw new Error('A reviewed remediation requires a substantive rationale and test plan.')
  const replacements = reviewedChanges(input); const findingFile = finding.locations[0]?.file
  if (!findingFile || !replacements.some(replacement => replacement.file === findingFile)) throw new Error('A reviewed remediation must include a bounded replacement in the reportable finding source file.')
  const receiptPaths = new Set(scan.coverage.receipts.map(receipt => receipt.path)); const root = resolve(workspace); const snapshots: RemediationFileSnapshot[] = []
  for (const replacement of replacements) {
    if (!Number.isInteger(replacement.startLine) || !Number.isInteger(replacement.endLine) || replacement.startLine < 1 || replacement.endLine < replacement.startLine || replacement.endLine - replacement.startLine > 199) throw new Error('Replacement ranges must be inclusive source ranges of at most 200 lines.')
    if (!receiptPaths.has(replacement.file)) throw new Error(`Reviewed remediation file is outside the immutable scan receipt set: ${replacement.file}`)
    if (!replacement.expectedText || replacement.expectedText.length > 100_000 || !replacement.replacementText || replacement.replacementText.length > 100_000 || replacement.expectedText.includes('\r') || replacement.replacementText.includes('\r')) throw new Error('Replacement text must be non-empty LF text within the bounded size limit.')
    const file = resolve(scan.target, replacement.file); if (!inside(root, file)) throw new Error('Reviewed remediation file is outside the active workspace.')
    const source = await readFile(file, 'utf8'); if (lineReplacement(source, replacement) === undefined) throw new Error(`The expected source text does not exactly match ${replacement.file}:${replacement.startLine}-${replacement.endLine}.`)
    snapshots.push({ file: replacement.file, sha256: sha256(source) })
  }
  const findingReplacement = replacements.find(replacement => replacement.file === findingFile)!; const proposal: RemediationProposal = { id: `rem_${randomUUID()}`, findingId, file: findingReplacement.file, line: findingReplacement.startLine, patch: replacements.map(replacement => patchFor(replacement.file, replacement)).join('\n'), baseSnapshotDigest: scan.targetSnapshot.snapshotDigest, baseFileSha256: snapshots.find(snapshot => snapshot.file === findingReplacement.file)!.sha256, baseFiles: snapshots, createdAt: new Date().toISOString(), status: 'proposed', state: 'generated', version: 1, requiresApproval: true, requiresReview: true, safeToApply: true, rationale: input.rationale.trim().slice(0, 20_000), testPlan: input.testPlan.trim().slice(0, 20_000), replacement: findingReplacement, replacements }
  await saveProposal(state, proposal); await atomicWrite(join(state,'remediations',`${proposal.id}.patch`),proposal.patch+'\n'); return proposal
}

export async function remediationPlan(workspace: string, config: Config, scanId: string, findingId: string): Promise<RemediationProposal> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  const location = finding.locations[0]; const file = resolve(scan.target, location.file); const root = resolve(workspace)
  if (!inside(root, file)) throw new Error('Finding location is outside the active workspace.')
  const before = await readFile(file, 'utf8'); const generated = replacementFor(finding, before); const replacement = generated && { file: location.file, startLine: 1, endLine: before.split(/\r?\n/).length, expectedText: before, replacementText: generated.content }
  const patch = replacement ? patchFor(location.file, replacement) : `No mechanically safe replacement is available for ${finding.ruleId}.\nReview ${location.file}:${location.line} and implement: ${finding.remediation}`
  const proposal: RemediationProposal = { id: `rem_${randomUUID()}`, findingId: finding.id, file: location.file, line: location.line, patch, baseSnapshotDigest: scan.targetSnapshot.snapshotDigest, baseFileSha256: sha256(before), baseFiles: [{ file: location.file, sha256: sha256(before) }], createdAt: new Date().toISOString(), status: 'proposed', state: 'generated', version: 1, requiresApproval: true, requiresReview: true, safeToApply: Boolean(replacement), rationale: generated?.rationale ?? 'The finding requires application-specific review; no semantics-preserving automatic replacement is available.', replacement, replacements: replacement ? [replacement] : undefined }
  await saveProposal(getStateDir(config.stateDir), proposal)
  await atomicWrite(join(getStateDir(config.stateDir),'remediations',`${proposal.id}.patch`),proposal.patch+'\n')
  await atomicWrite(join(getStateDir(config.stateDir), 'remediations', `${proposal.id}.json`), `${JSON.stringify(proposal, null, 2)}\n`)
  return proposal
}

function advanceProposal(proposal:RemediationProposal,to:RemediationState,expectedVersion?:number,pendingAction?:'apply'|'verify'){
 const next=transitionRemediation({state:proposal.state??'generated',version:proposal.version??1,updatedAt:proposal.createdAt},to,{expectedVersion:expectedVersion??proposal.version??1,pendingAction})
 proposal.state=next.state;proposal.version=next.version
}
async function remediationLease<T>(config:Config,scanId:string,remediationId:string,run:()=>Promise<T>){
 const state=getStateDir(config.stateDir),scan=await loadScan(state,scanId)
 return withJobLease(state,`repair_${sha256(resolve(scan.target)).slice(0,32)}`,()=>withJobLease(state,remediationId,run))
}

async function applyRemediationProposalUnlocked(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean,expectedVersion?:number): Promise<RemediationProposal> {
  if (!approved) throw new Error('Applying a remediation changes source files. Set approved to true only after reviewing the exact proposal.')
  const scan = await loadScan(getStateDir(config.stateDir), scanId); const proposal = await loadRemediationProposal(getStateDir(config.stateDir), remediationId)
  if (proposal.findingId !== scan.findings.find(finding => finding.id === proposal.findingId)?.id) throw new Error('Remediation proposal does not belong to this scan.')
  if (proposal.status !== 'proposed') throw new Error(`Remediation is ${proposal.status} and cannot be applied.`)
  if(expectedVersion!==undefined&&proposal.version!==expectedVersion)throw new Error('Remediation optimistic lock failed; reread the current proposal version.')
  const root = resolve(workspace); const replacements = proposalReplacements(proposal); const snapshots = proposalFiles(proposal)
  if (!proposal.safeToApply || !replacements.length || replacements.length !== snapshots.length) throw new Error('No mechanically safe replacement is available for this proposal.')
  const [currentSnapshot, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(snapshots.map(async snapshot => { const file = await assertPatchPath(scan.target,snapshot.file); if (!inside(root, file)) throw new Error('Remediation target is outside the active workspace.'); return { snapshot, file, source: await readFile(file, 'utf8') } }))])
  if (currentSnapshot !== proposal.baseSnapshotDigest || sources.some(item => sha256(item.source) !== item.snapshot.sha256)) { proposal.status = 'stale'; await saveProposal(getStateDir(config.stateDir), proposal); throw new Error('Remediation proposal is stale because the target snapshot or a proposed file changed. Generate a new proposal.') }
  const finding = scan.findings.find(item => item.id === proposal.findingId); if (!finding) throw new Error('Finding was not found in this scan.')
  const changes = sources.map(item => { const replacement = replacements.find(value => value.file === item.snapshot.file); const content = replacement && lineReplacement(item.source, replacement); if (!content || content === item.source) throw new Error(`No mechanically safe replacement is available for ${item.snapshot.file}.`); return { ...item, content } })
  const originals:RemediationRollbackFile[]=changes.map(change=>({file:change.snapshot.file,sha256:sha256(change.source),beforeContent:change.source,appliedSha256:sha256(change.content)})),primary=originals.find(item=>item.file===proposal.file)!
  const rollback:RemediationRollback={id:`rollback_${randomUUID()}`,remediationId:proposal.id,scanId,file:primary.file,beforeContent:primary.beforeContent,beforeSha256:primary.sha256,appliedSha256:primary.appliedSha256,files:originals,appliedSnapshotDigest:'',createdAt:new Date().toISOString(),status:'prepared'}
  // 先落盘原始字节与写入意图，崩溃后仍能找到准备中的回滚。
  await saveRollback(getStateDir(config.stateDir),rollback);proposal.rollbackId=rollback.id
  advanceProposal(proposal,'generated',expectedVersion,'apply');await saveProposal(getStateDir(config.stateDir),proposal)
  try{
    for(const change of changes)await replaceExpectedFile(change.file,change.snapshot.sha256,change.content)
    rollback.appliedSnapshotDigest=await snapshotDigestForDirectory(scan.target,config);rollback.status='available';await saveRollback(getStateDir(config.stateDir),rollback)
    proposal.status='applied';proposal.appliedAt=new Date().toISOString();advanceProposal(proposal,'applied');await saveProposal(getStateDir(config.stateDir),proposal)
  }catch(error){
    const conflicts:string[]=[]
    for(const change of changes){try{const current=sha256(await readFile(change.file,'utf8'));if(current===sha256(change.content))await replaceExpectedFile(change.file,current,change.source);else if(current!==change.snapshot.sha256)conflicts.push(change.snapshot.file)}catch{conflicts.push(change.snapshot.file)}}
    proposal.status=conflicts.length?'stale':'proposed';rollback.status=conflicts.length?'recovery_required':'rolled_back';await saveRollback(getStateDir(config.stateDir),rollback)
    advanceProposal(proposal,'failed');proposal.verificationError=(error as Error).message;await saveProposal(getStateDir(config.stateDir),proposal)
    throw new Error(`Remediation application failed; ${conflicts.length?'conflicting user bytes were preserved; inspect '+rollback.id:'written files were restored from '+rollback.id}. ${(error as Error).message}`)
  }
  try{
    const verification=await runScan(scan.target,config,'standard',scan.threatModel,scan.recipe.scopeRequested,config.stateDir,false)
    await persistInvestigationArtifacts(getStateDir(config.stateDir),verification);await saveScan(getStateDir(config.stateDir),verification)
    proposal.verificationScanId=verification.id;proposal.verification=remediationVerification(verification,finding);advanceProposal(proposal,'verifying',undefined,'verify')
  }catch(error){advanceProposal(proposal,'failed');proposal.verificationError=`Patch is applied with retained rollback; post-change scan failed: ${(error as Error).message}`}
  await saveProposal(getStateDir(config.stateDir),proposal)
  return proposal
}

/**
 * Run only scan-time preflight commands against an already-applied exact patch.
 * Command success is retained as repair evidence, never as an automatic finding
 * resolution or a substitute for an attacker-path revalidation.
 */
async function runRemediationVerificationUnlocked(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal,expectedVersion?:number): Promise<RemediationVerificationRun> {
  signal?.throwIfAborted()
  if (!approved) throw new Error('Running remediation verification can execute project test/build scripts. Set approved to true only after reviewing the scan-time commands.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const proposal = await loadRemediationProposal(state, remediationId)
  if (proposal.findingId !== scan.findings.find(finding => finding.id === proposal.findingId)?.id) throw new Error('Remediation proposal does not belong to this scan.')
  if (proposal.status !== 'applied' || !proposal.rollbackId) throw new Error('Only an applied remediation with an available rollback record can be verified.')
  advanceProposal(proposal,'verifying',expectedVersion,'verify');await saveProposal(state,proposal)
  const rollback = await loadRemediationRollback(state, proposal.rollbackId)
  if (rollback.status !== 'available' || rollback.remediationId !== proposal.id || rollback.scanId !== scanId) throw new Error('The applied remediation rollback record is unavailable.')
  const root = resolve(workspace); for (const item of rollbackFiles(rollback)) if (!inside(root, resolve(scan.target, item.file))) throw new Error('Remediation target is outside the active workspace.')
  const commands = [...new Set(scan.preflight.suggestedCommands.map(command => safeCommand(command)))].map(command => ({ command, reason: `Suggested by source scan ${scan.id} preflight for ${scan.preflight.projectFiles.join(', ')}.` }))
  if (!commands.length) throw new Error('No bounded remediation verification command is available from the source scan preflight.')
  const [snapshotDigest, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(rollbackFiles(rollback).map(async item => ({ item, source: await readFile(resolve(scan.target, item.file), 'utf8') })))])
  if (snapshotDigest !== rollback.appliedSnapshotDigest || sources.some(source => sha256(source.source) !== source.item.appliedSha256)) throw new Error('Applied remediation changed since application. Create a follow-up scan before verification.')
  const currentRisk=proposal.verificationScanId?await loadScan(state,proposal.verificationScanId):scan;assertNoCredentialExecution(currentRisk)
  const receipts = await executeValidationCommands(config, scan.target, commands.map(item => item.command), timeoutMs, snapshotDigest, signal)
  const after = await snapshotDigestForDirectory(scan.target, config)
  if (after !== snapshotDigest) throw new Error('Target changed during remediation verification; receipts were not attached.')
  const id = `remverify_${randomUUID()}`; const artifactRef = join(state, 'remediation-verification', `${id}.json`)
  const run: RemediationVerificationRun = { id, remediationId: proposal.id, sourceScanId: scan.id, snapshotDigest, commands, receipts, outcome: receipts.every(receipt => !receipt.timedOut && receipt.exitCode === 0) ? 'passed' : 'failed', executedAt: new Date().toISOString(), artifactRef, limitation: 'These isolated project-check receipts do not prove that the original attacker path is closed, that production configuration is safe, or that the original finding is resolved. Revalidate the source-to-sink path and preserved behavior separately.' }
  await atomicWrite(artifactRef, `${JSON.stringify(run, null, 2)}\n`)
  proposal.postApplyVerification = run;advanceProposal(proposal,run.outcome==='failed'?'failed':'verifying',undefined,run.outcome==='failed'?undefined:'verify'); await saveProposal(state, proposal)
  return run
}

/**
 * Run the complete DSH-native fix workflow for one already reportable finding.
 * Source edits remain exact-range, snapshot-bound, approval-gated, reversible,
 * and are never described as resolved solely because a rescan passes.
 */
export async function fixFinding(workspace: string, config: Config, scanId: string, findingId: string, input: { changes: Array<{ file: string; startLine: number; endLine: number; expectedText: string; replacementText: string }>; rationale: string; testPlan: string }, approved: boolean, timeoutMs = 120_000, signal?: AbortSignal): Promise<FixFindingResult> {
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const finding = scan.findings.find(item => item.id === findingId)
  if (!finding) throw new Error('Finding was not found in this scan.')
  if (finding.disposition !== 'reportable' || !finding.validationRecord || !finding.attackPathRecord) return { outcome: 'no_change', scanId, findingId, stages: [{ name: 'scope', status: 'failed', detail: 'The finding is not a formally reportable, validated finding; no source change was attempted.' }], limitation: 'Only a reportable finding with validation and attack-path receipts can enter the standalone fix workflow.' }
  const stages: FixFindingResult['stages'] = [{ name: 'scope', status: 'passed', detail: `Validated ${finding.title} with source-bound validation and attack-path receipts.` }]
  const proposal = await proposeReviewedRemediation(workspace, config, scanId, findingId, { changes: input.changes, rationale: input.rationale, testPlan: input.testPlan })
  stages.push({ name: 'proposal', status: proposal.safeToApply ? 'passed' : 'failed', detail: proposal.safeToApply ? 'Exact replacement ranges and source snapshot are frozen.' : 'The supplied patch is not mechanically safe to apply.' })
  if (!proposal.safeToApply) return { outcome: 'blocked', scanId, findingId, remediationId: proposal.id, stages, limitation: 'The patch proposal is not mechanically safe; no source file was changed.' }
  if (!approved) return { outcome: 'blocked', scanId, findingId, remediationId: proposal.id, stages, limitation: 'Reviewed acknowledgement is required before the DSH approval gate can authorize source mutation.' }
  signal?.throwIfAborted()
  const applied = await applyRemediationProposal(workspace, config, scanId, proposal.id, true)
  stages.push({ name: 'apply', status: applied.status === 'applied' ? 'passed' : 'failed', detail: `Applied exact patch with rollback record ${applied.rollbackId ?? 'unavailable'}.` })
  if (applied.status !== 'applied') return { outcome: 'blocked', scanId, findingId, remediationId: proposal.id, stages, limitation: 'The patch did not reach applied state.' }
  try {
    const verification = await runRemediationVerification(workspace, config, scanId, proposal.id, true, timeoutMs, signal)
    const verificationPassed = verification.outcome === 'passed' && applied.verification?.status === 'not_detected'
    stages.push({ name: 'verification', status: verificationPassed ? 'passed' : 'failed', detail: verificationPassed ? 'Bounded project checks passed and the native rescan no longer detected the original rule family.' : 'Project checks or the native rescan did not establish closure.' })
    return { outcome: 'blocked', scanId, findingId, remediationId: proposal.id, verification, stages, limitation: 'Project checks and rule disappearance cannot prove a repair. Independent follow-up source/attacker-path revalidation is required; outcome remains inconclusive.' }
  } catch (error) {
    stages.push({ name: 'verification', status: 'unknown', detail: error instanceof Error ? error.message : String(error) })
    return { outcome: 'blocked', scanId, findingId, remediationId: proposal.id, stages, limitation: 'The patch is applied and rollback remains available, but the required bounded verification could not complete.' }
  }
}

/** Restore one proposal's exact pre-application content only when its applied state remains intact. */
async function rollbackRemediationProposalUnlocked(workspace: string, config: Config, scanId: string, remediationId: string, approved: boolean,expectedVersion?:number): Promise<RemediationRollback> {
  if (!approved) throw new Error('Rolling back a remediation changes source files. Set approved to true only after reviewing the rollback record.')
  const state = getStateDir(config.stateDir); const scan = await loadScan(state, scanId); const proposal = await loadRemediationProposal(state, remediationId)
  if(expectedVersion!==undefined&&proposal.version!==expectedVersion)throw new Error('Remediation optimistic lock failed; reread the current version.')
  if (!proposal.rollbackId) throw new Error('Only a remediation with a retained rollback record can be rolled back.')
  const rollback = await loadRemediationRollback(state, proposal.rollbackId); if (rollback.remediationId !== proposal.id || rollback.scanId !== scanId || !['available','prepared','recovery_required'].includes(rollback.status)) throw new Error('Rollback record is unavailable or does not belong to this remediation.')
  const root = resolve(workspace); const files = rollbackFiles(rollback); const [snapshot, sources] = await Promise.all([snapshotDigestForDirectory(scan.target, config), Promise.all(files.map(async item => { const file = await assertPatchPath(scan.target,item.file); if (!inside(root, file)) throw new Error('Rollback target is outside the active workspace.'); return { item, file, source: await readFile(file, 'utf8') } }))])
  if ((rollback.appliedSnapshotDigest&&snapshot !== rollback.appliedSnapshotDigest) || sources.some(source => ![source.item.appliedSha256,source.item.sha256].includes(sha256(source.source)))) { rollback.status = 'stale'; await saveRollback(state, rollback); throw new Error('Rollback record is stale because an applied file or target snapshot changed.') }
  const restored: typeof sources = []
  try { for (const source of sources) { await replaceExpectedFile(source.file,sha256(source.source),source.item.beforeContent); restored.push(source) } } catch (error) { await Promise.all(restored.map(source => replaceExpectedFile(source.file,source.item.sha256,source.source))); throw error }
  rollback.status = 'rolled_back'; rollback.rolledBackAt = new Date().toISOString()
  proposal.status = 'rolled_back';if(proposal.state!=='failed')advanceProposal(proposal,'failed');advanceProposal(proposal,'superseded')
  // 字节已恢复：先落盘状态，验证扫描失败也不能让记录停在 applied。
  await saveRollback(state, rollback); await saveProposal(state, proposal)
  const verification = await runScan(scan.target, config, 'standard', scan.threatModel, scan.recipe.scopeRequested, config.stateDir, false); await persistInvestigationArtifacts(state, verification); await saveScan(state, verification); rollback.verificationScanId = verification.id; await saveRollback(state, rollback)
  return rollback
}

export async function applyRemediationProposal(workspace:string,config:Config,scanId:string,remediationId:string,approved:boolean,expectedVersion?:number){return remediationLease(config,scanId,remediationId,()=>applyRemediationProposalUnlocked(workspace,config,scanId,remediationId,approved,expectedVersion))}
export async function runRemediationVerification(workspace:string,config:Config,scanId:string,remediationId:string,approved:boolean,timeoutMs=120_000,signal?:AbortSignal,expectedVersion?:number){return remediationLease(config,scanId,remediationId,()=>runRemediationVerificationUnlocked(workspace,config,scanId,remediationId,approved,timeoutMs,signal,expectedVersion))}
export async function rollbackRemediationProposal(workspace:string,config:Config,scanId:string,remediationId:string,approved:boolean,expectedVersion?:number){return remediationLease(config,scanId,remediationId,()=>rollbackRemediationProposalUnlocked(workspace,config,scanId,remediationId,approved,expectedVersion))}
