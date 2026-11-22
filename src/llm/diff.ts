import { parseUnifiedDiff } from '../diff-parse.js'
import { rankedDomains } from '../coverage.js'
import { policyContext } from '../policy-context.js'
import { boundedPage } from '../tool-pages.js'
import { redactSensitive } from '../audit-context.js'
import { withScanLease } from '../scan-lease.js'
import { mutateScan } from '../scan-store.js'
import { withJobLease } from '../job-lease.js'
import { currentAuditActor } from '../audit-context.js'
import { observeSourceRead } from '../coverage.js'
import { boundedRange, readFrozenSource } from '../source-evidence.js'
import { ingestModelCandidates } from '../candidate-ingestion.js'
import { createAuditAgent, waitForAuditAgent, auditTokenUsage } from '../runtime.js'
import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.js'
import type { ScanRecord } from '../contracts.js'
import { getStateDir, loadScan, readArtifact, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from '../state.js'
import { readScanKnowledgeBase } from './knowledge-base.js'

/**
 * Diff-scan LLM file review, aligned with the codex-security compact diff
 * workflow (Apache-2.0, adapted): one restricted file-review subagent per
 * changed source file reads it in full against the frozen diff worklist and
 * reports source-backed candidates anchored to the changed code. The
 * deterministic diff engine remains the receipt baseline.
 */

export const DIFF_REVIEW_WORKERS = 6
export const MAX_DIFF_FILE_WORKERS = 60

export type DiffDiscoveryLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'

export interface DiffReviewItem { path: string; sha256: string; language: string; mode: string }

export interface DiffCandidateInput {
  changeEvidence?:import('../diff-evidence.js').ChangeEvidence
  businessBoundary?:import('../contracts.js').Finding['businessBoundary']
  ruleId: string
  title: string
  summary: string
  cwe: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: 'high' | 'medium' | 'low'
  attacker: string
  violatedInvariant: string
  sourceToSink: string
  impact: string
  remediation: string
  counterevidence: string
  locations: Array<{ path: string; startLine: number; endLine?: number; role?: string }>
  evidence: Array<{ location: { path: string; startLine: number; role?: string }; explanation: string }>
}

export interface DiffWorkerReport { resolvedQuestions: string[]; fullyReviewedFileCount: number }

export interface DiffWorker {
  id: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  token: string
  assignedPaths: string[]
  candidateIds: string[]
  report?: DiffWorkerReport
  error?: string
  transcript?: string
  usage?:ReturnType<typeof auditTokenUsage>
}

export interface DiffDiscoveryJob {
  scanPrompt?:string
  policySnapshots?:import('../policy-context.js').PolicySnapshot[]
  id: string
  scanId: string
  target: string
  lifecycle: DiffDiscoveryLifecycle
  createdAt: string
  updatedAt: string
  worklistDigest: string
  worklist: DiffReviewItem[]
  contextWorklist?: DiffReviewItem[]
  diffArtifact?: {path:string;sha256:string}
  threatModel: string
  userContext: string
  policyGuidance: string
  knowledgeBasePromptText: string
  workers: DiffWorker[]
  candidates: Array<DiffCandidateInput & { id: string; workerId: string; fingerprint: string }>
  notes: string[]
}

function inside(workspace: string, path: string): boolean {
  const rel = relative(resolve(workspace), resolve(path))
  return rel === '' || (!rel.startsWith('..') && !resolve(rel).startsWith('..'))
}

function pathFor(state: string, id: string): string {
  if (!/^diffdiscovery_[0-9a-f-]+$/.test(id)) throw new Error('Invalid diff discovery job id.')
  return join(state, 'diff-discovery', `${id}.json`)
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const { mkdir, rename, writeFile } = await import('node:fs/promises')
  await mkdir(resolve(path, '..'), { recursive: true,mode:0o700 })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content, {encoding:'utf8',mode:0o600})
  await rename(temporary, path)
}

const jobWrites = new Map<string, Promise<unknown>>()

async function updateJob(config: Config, id: string, update: (job: DiffDiscoveryJob) => void | Promise<void>): Promise<DiffDiscoveryJob> {
  const previous = jobWrites.get(id) ?? Promise.resolve()
  const barrier = previous.catch(()=>undefined).then(async () => {
    const job = await loadDiffDiscoveryJob(config, id)
    await update(job)
    job.updatedAt = new Date().toISOString()
    await atomicWrite(pathFor(getStateDir(config.stateDir), id), `${JSON.stringify(job, null, 2)}\n`)
    return job
  })
  jobWrites.set(id, barrier)
  await previous.catch(()=>undefined)
  try { return await barrier } finally { if (jobWrites.get(id) === barrier) jobWrites.delete(id) }
}

export async function loadDiffDiscoveryJob(config: Config, id: string): Promise<DiffDiscoveryJob> {
  const { readFile: read } = await import('node:fs/promises')
  return JSON.parse(await read(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DiffDiscoveryJob
}

/** Freeze the changed-file worklist from a saved diff scan; bind each file to its current content digest. */
export async function createDiffDiscoveryJob(config: Config, scanId: string, userContext = ''): Promise<DiffDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, scanId)
  if(scan.lifecycle==='completed')throw new Error('Completed scans are immutable; create a follow-up scan.')
  await mutateScan(config,scan.id,s=>{s.auditDeadlineAt??=new Date(Date.parse(s.createdAt)+(config.maxAuditTimeHours??4)*3_600_000).toISOString()})
  const kb = await readScanKnowledgeBase(config, scan.id)
  const worklist: DiffReviewItem[] = []
  for (const receipt of scan.coverage.receipts) {
    const source = resolve(scan.evidenceRoot ?? scan.target, receipt.path)
    if (!inside(scan.evidenceRoot ?? scan.target, source)) throw new Error(`Diff receipt path ${receipt.path} is outside the scan target.`)
    const content = await readFile(source, 'utf8')
    if (!receipt.sourceSha256 || sha256(content) !== receipt.sourceSha256) throw new Error(`Diff source ${receipt.path} changed or predates source-bound receipts; create a new diff scan.`)
    worklist.push({ path: receipt.path, sha256: sha256(content), language: receipt.language, mode: scan.coverage.mode })
  }
  const now = new Date().toISOString()
  const job: DiffDiscoveryJob = {
    id: `diffdiscovery_${randomUUID()}`, scanId, target: scan.evidenceRoot ?? scan.target, lifecycle: 'queued', createdAt: now, updatedAt: now,
    worklistDigest: sha256(JSON.stringify(worklist)), worklist, threatModel: scan.threatModel, userContext, policyGuidance: scan.policyGuidance,policySnapshots:scan.policySnapshots,
    diffArtifact:scan.diffArtifact,
    contextWorklist:(scan.coverage.contextReceipts??[]).map(r=>({path:r.path,sha256:r.sourceSha256??r.sha256,language:r.language,mode:scan.coverage.mode})),
    knowledgeBasePromptText: kb.promptText,scanPrompt:config.scanPrompt??'', workers: [], candidates: [],
    notes: kb.skipped.length ? [`Knowledge base skipped ${kb.skipped.length} document(s): ${kb.skipped.map(item => `${item.path} (${item.reason})`).join('; ')}`] : [],
  }
  await atomicWrite(pathFor(state, job.id), `${JSON.stringify(job, null, 2)}\n`)
  return job
}

export function activeDiffWorker(job: DiffDiscoveryJob, workerId: string, token: string): DiffWorker {
  if (job.lifecycle !== 'running') throw new Error('Diff discovery job is not running.')
  const worker = job.workers.find(item => item.id === workerId)
  if (!worker) throw new Error('Worker is not part of this diff discovery job.')
  if (worker.status !== 'running') throw new Error('Worker is not active for this diff discovery job.')
  if (worker.token !== token) throw new Error('Worker claim token does not own this worker.')
  return worker
}

export function getDiffReviewItems(config:Config,jobId:string,workerId:string,token:string,contextOffset=0){
 const job=loadDiffDiscoveryJobSync(config,jobId),worker=activeDiffWorker(job,workerId,token)
 const scan=JSON.parse(readFileSync(join(getStateDir(config.stateDir),'scans',`${job.scanId}.json`),'utf8')) as ScanRecord
 const changedLines=Object.fromEntries(worker.assignedPaths.map(path=>[path,(scan.coverage.changedLines?.[path]??[]).slice(0,1000)]))
 const ranges=Object.fromEntries(worker.assignedPaths.map(path=>{const values=scan.coverage.changedLines?.[path]??[],pairs:Array<[number,number]>=[];for(const line of values){const last=pairs.at(-1);if(last&&line===last[1]+1)last[1]=line;else pairs.push([line,line])}return [path,pairs.slice(0,100)]}))
 const contextRefs=['threat_model','policy','user_context','knowledge_base','scan_prompt'].map(kind=>({tool:'security_diff_read_context',kind}))
 const page=boundedPage((job.contextWorklist??[]).map(r=>r.path),contextOffset,100,'contextPaths',{jobId,scanId:job.scanId,target:job.target,worklistDigest:job.worklistDigest,mode:job.worklist[0]?.mode??'diff',items:job.worklist.filter(r=>worker.assignedPaths.includes(r.path)).map(r=>({path:r.path,language:r.language})),changedLines,changedRanges:ranges,diffInventory:scan.coverage.diffInventory,changedLinesTruncated:worker.assignedPaths.some(p=>(scan.coverage.changedLines?.[p]?.length??0)>1000),contextRefs,contextTruncated:true,threatModel:redactSensitive(job.threatModel).slice(0,1000),userContext:redactSensitive(job.userContext).slice(0,1000),policyGuidance:redactSensitive(job.policyGuidance).slice(0,1000),knowledgeBasePromptText:redactSensitive(job.knowledgeBasePromptText).slice(0,1000)})
 const {nextOffset,total,...rest}=page
 return {...rest,totalContextFiles:total,...(nextOffset!==undefined?{nextContextOffset:nextOffset}:{})}
}
export async function readDiffContext(config:Config,jobId:string,workerId:string,token:string,kind:'threat_model'|'policy'|'user_context'|'knowledge_base'|'scan_prompt',offset=0){
 const job=await loadDiffDiscoveryJob(config,jobId);const worker=activeDiffWorker(job,workerId,token)
 const fields={threat_model:job.threatModel,policy:policyContext(job.policyGuidance,job.policySnapshots??[],worker.assignedPaths),user_context:job.userContext,knowledge_base:job.knowledgeBasePromptText,scan_prompt:job.scanPrompt??''}
 if(!Object.hasOwn(fields,kind))throw new Error('Unknown frozen Diff context kind.')
 const value=redactSensitive(fields[kind]),start=Math.max(0,Math.floor(offset)),end=Math.min(value.length,start+8000)
 return {kind,content:value.slice(start,end),totalCharacters:value.length,sha256:sha256(value),...(end<value.length?{nextOffset:end}:{})}
}

export async function readDiffSource(config: Config, jobId: string, workerId: string, token: string, path: string, startLine?: number, endLine?: number): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const job = await loadDiffDiscoveryJob(config, jobId)
  const worker = activeDiffWorker(job, workerId, token)
  if (!worker.assignedPaths.includes(path) && !job.contextWorklist?.some(r=>r.path===path)) throw new Error('Path is neither an assigned changed file nor frozen supporting context.')
  const item = [...job.worklist,...(job.contextWorklist??[])].find(entry => entry.path === path)
  if (!item) throw new Error('Path is not in the diff discovery worklist.')
  const source = resolve(job.target, item.path)
  if (!inside(job.target, source)) throw new Error('Path is outside the scan target.')
  const content = await readFrozenSource(job.target,{...item,bytes:0})
  const range=boundedRange(content,startLine,endLine)
  await observeSourceRead(config,job.scanId,item.path,range.startLine,range.endLine,item.sha256,`${job.id}:${workerId}`)
  return {path:item.path,sha256:item.sha256,...range}
}

function validateDiffCandidate(job: DiffDiscoveryJob, candidate: DiffCandidateInput): DiffCandidateInput {
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(candidate.ruleId)) throw new Error('ruleId must be a stable lowercase slug.')
  if (!candidate.locations.length) throw new Error('Candidate requires at least one concrete source location.')
  for (const location of candidate.locations) {
    if (![...job.worklist,...(job.contextWorklist??[])].some(item => item.path === location.path)) throw new Error(`Candidate location ${location.path} is outside the diff worklist.`)
    if (!Number.isInteger(location.startLine) || location.startLine < 1) throw new Error(`Candidate location ${location.path} has an invalid startLine.`)
  }
  return candidate
}

export async function reportDiffCandidates(config: Config, jobId: string, workerId: string, token: string, candidates: DiffCandidateInput[]): Promise<{ recorded: number; candidateIds: string[] }> {
  const job = await updateJob(config, jobId, async current => {
    const worker = activeDiffWorker(current, workerId, token)
    const validated=candidates.map(input=>validateDiffCandidate(current,input))
    for(const input of validated)if(!input.locations.some(l=>worker.assignedPaths.includes(l.path)))throw new Error('A diff candidate must anchor to an assigned changed file.')
    await ingestModelCandidates(config,current.scanId,current.id,workerId,validated,'dsh-diff')
    for (const input of candidates) {
      const candidate = validateDiffCandidate(current, input)
      if(!candidate.locations.some(l=>worker.assignedPaths.includes(l.path)))throw new Error('A diff candidate must anchor to an assigned changed file.')
      const fingerprint = sha256(`${candidate.ruleId}:${candidate.locations[0].path}:${candidate.locations[0].startLine}:${candidate.summary}`)
      const id = `diffcand_${sha256(fingerprint).slice(0, 24)}`
      if (current.candidates.some(item => item.id === id)) continue
      current.candidates.push({ ...candidate, id, workerId, fingerprint })
      worker.candidateIds.push(id)
    }
  })
  return { recorded: job.candidates.length, candidateIds: job.candidates.map(candidate => candidate.id) }
}

export async function reportDiffWorker(config: Config, jobId: string, workerId: string, token: string, report: DiffWorkerReport): Promise<void> {
  await updateJob(config, jobId, async current => {
    const worker = activeDiffWorker(current, workerId, token)
    if (!Number.isInteger(report.fullyReviewedFileCount) || report.fullyReviewedFileCount < 0) throw new Error('fullyReviewedFileCount must be a nonnegative integer.')
    const snapshot=await loadScan(getStateDir(config.stateDir),current.scanId)
    const rows=(snapshot.auditTrail??[]).filter(row=>row.kind==='source_read' && row.actorId===(currentAuditActor()?.id ?? `${current.id}:${workerId}`))
    const readFiles=new Set(rows.map(row=>row.path))
    if(report.fullyReviewedFileCount>readFiles.size)throw new Error('Reviewed file count exceeds observed source reads; report exact gaps instead.')
    worker.report = report
    worker.status = 'completed'
  })
}

export const DIFF_WORKER_TOOLS = ['security_diff_get_review_items', 'security_diff_read_context', 'security_diff_read_source', 'security_diff_report_candidates', 'security_diff_report_worker', 'security_diff_read_patch', 'security_get_coverage', 'security_record_coverage_check', 'security_read_scan_context', 'security_read_skill'] as const

type NativeAgents = { create?: unknown }

function nativeAgents(ctx: Context): NativeAgents | undefined {
  const get = (ctx as Context & { get?: (name: string) => unknown }).get
  return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: NativeAgents }).agents) as NativeAgents | undefined
}

export function diffDiscoveryCapability(ctx: Context): { available: boolean; workers: number; reason?: string } {
  const agents = nativeAgents(ctx)
  if (!agents || typeof agents.create !== 'function') return { available: false, workers: DIFF_REVIEW_WORKERS, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workers: DIFF_REVIEW_WORKERS }
}

function transcript(agent: { session: { deriveMessages(): ReadonlyArray<{ role: string; content: ReadonlyArray<{ type: string; text?: string }> }> } }): string {
  return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000)
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

async function runDiffWorker(ctx: Context, config: Config, job: DiffDiscoveryJob, worker: DiffWorker, prompt: string, signal?: AbortSignal): Promise<void> {
  const { createUserMessage } = await import('@deepseek-ai/dsh-llm')
  const { SessionId } = await import('@deepseek-ai/dsh-session')
  const sessionId = SessionId(`dsh-edge-diff-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (!record) throw new Error('Diff review worker was not created.'); record.status = 'running';record.report=undefined;record.error=undefined })
  let handle: Awaited<ReturnType<typeof ctx.agents.create>> | undefined
  let disposePromise: Promise<void> | undefined
  const dispose = (): Promise<void> => handle ? (disposePromise ??= handle.dispose().catch(() => undefined)) : Promise.resolve()
  let cancelledByCaller = cancelled(signal)
  const onAbort = (): void => { cancelledByCaller = true; void dispose() }
  signal?.addEventListener('abort', onAbort, { once: true })
  try {
    if (cancelledByCaller) return
    const agents = nativeAgents(ctx) as typeof ctx.agents | undefined
    if (!agents || typeof agents.create !== 'function') throw new Error('The active DSH profile has no native agent-creation service.')
    handle = await createAuditAgent(ctx, { sessionId, signal, meta: { cwd: resolve(job.target), origin: 'subagent', delegationDepth: 1 }, setup(agentCtx) {
      agentCtx.tools.restrict({ allow: [...DIFF_WORKER_TOOLS] })
      agentCtx.systemPrompt.section({ name: `dsh-edge-audit:diff-worker:${worker.id}`, order: 162, interpolate: false, text: prompt })
    } }, {stateDir:config.stateDir,maxConcurrentModelWorkers:config.maxConcurrentModelWorkers,workerTimeoutMs:config.workerTimeoutMs,budgetScanId:config.auditBudgetScanId,maxModelTokens:config.maxModelTokens,id:`${job.id}:${worker.id}`,role:'discoverer',scanId:job.scanId,jobId:job.id,workerId:worker.id,domains:rankedDomains(await loadScan(getStateDir(config.stateDir),job.scanId),worker.assignedPaths)})
    if (cancelledByCaller) return
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: prompt }], source: { kind: 'dsh-edge-audit', form: 'relay' } }))
    if (signal) {
      let removeAbortWait = (): void => undefined
      const aborted = new Promise<void>(resolveAbort => { const wake = (): void => resolveAbort(); signal.addEventListener('abort', wake, { once: true }); removeAbortWait = (): void => signal.removeEventListener('abort', wake) })
      try { await Promise.race([waitForAuditAgent(handle.agent, signal, config.workerTimeoutMs), aborted]) } finally { removeAbortWait() }
    } else await waitForAuditAgent(handle.agent, signal, config.workerTimeoutMs)
    if (cancelledByCaller) return
    const workerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status !== 'cancelled') { record.usage=auditTokenUsage(handle!.agent);record.transcript = workerTranscript; record.status = record.report ? 'completed' : 'failed'; if(!record.report) record.error='Worker became idle without a terminal report.' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record) { record.status = 'failed'; record.error = message } })
  } finally {
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = current.workers.find(item => item.id === worker.id); if (record && record.status !== 'completed') { record.status = 'cancelled'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

async function persistDiffArtifacts(config: Config, jobId: string): Promise<void> {
  const state = getStateDir(config.stateDir)
  const job = await loadDiffDiscoveryJob(config, jobId)
  const scan = await loadScan(state, job.scanId)
  const base = 'artifacts/02_discovery/diff'
  await writeArtifact(scan, `${base}/rank_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: 'diff', preview: '' })).join('\n')}\n`)
  await writeArtifact(scan, `${base}/deep_review_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: 'diff' })).join('\n')}\n`)
  for (const worker of job.workers) {
    if (!worker.report) continue
    const dir = `${base}/${worker.id}`
    await writeArtifact(scan, `${dir}/report.json`, `${JSON.stringify(worker.report, null, 2)}\n`)
    await writeArtifact(scan, `${dir}/candidates.jsonl`, `${job.candidates.filter(candidate => candidate.workerId === worker.id).map(candidate => JSON.stringify(candidate)).join('\n')}\n`)
    if (worker.transcript) await writeArtifact(scan, `${dir}/transcript.md`, `${worker.transcript}\n`)
  }
  await writeArtifact(scan, `${base}/discovery_ledger.md`, ['# Diff File-Review Ledger', '', `- Job: \`${job.id}\``, `- Worklist digest: \`${job.worklistDigest}\``, `- Changed files: ${job.worklist.length}`, `- Workers: ${job.workers.map(worker => `\`${worker.id}\` (${worker.status}, ${worker.assignedPaths.length} files)`).join(', ')}`, `- Candidates: ${job.candidates.length}`, ...job.notes.map(note => `- Note: ${note}`), ''].join('\n'))
  await persistInvestigationArtifacts(state, scan)
  await saveScan(state, scan)
}

/** Run one diff file-review job: one restricted worker per changed file, capped, then persist artifacts and scan candidates. */
async function runDiffDiscoveryInternal(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DiffDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  let job = await loadDiffDiscoveryJob(config, jobId)
  if (job.lifecycle==='running') {job.lifecycle='incomplete'}
  if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('Diff discovery job has already completed or failed.')
  const capability = diffDiscoveryCapability(ctx)
  if (!capability.available) {
    await updateJob(config, jobId, current => { current.lifecycle = 'failed' })
    throw new Error(capability.reason ?? 'The active DSH profile has no native agent-creation service.')
  }
  await updateJob(config, jobId, current => { current.lifecycle = 'running' })
  job = await loadDiffDiscoveryJob(config, jobId)
  const { diffFileReviewPrompt } = await import('./prompts.js')
  const slots = Math.max(1, Math.min(DIFF_REVIEW_WORKERS, job.worklist.length))
  // 单文件单 Worker 在大 PR 上成本不可控：超过上限后按排序相邻的文件成组。
  const chunk = Math.max(1, Math.ceil(job.worklist.length / MAX_DIFF_FILE_WORKERS)), sorted = [...job.worklist].sort((a, b) => a.path.localeCompare(b.path))
  const assignments = Array.from({ length: Math.ceil(sorted.length / chunk) }, (_, index) => ({ paths: sorted.slice(index * chunk, (index + 1) * chunk).map(item => item.path), workerId: `filereview_${index + 1}` }))
  await updateJob(config, jobId, current => {
    if(current.workers.length)return
    current.workers = assignments.map((assignment, index) => ({ id: assignment.workerId, status: 'pending' as const, token: randomUUID(), assignedPaths: assignment.paths, candidateIds: [] }))
  })
  job = await loadDiffDiscoveryJob(config, jobId)
  for(let batch=0;batch<job.workers.length;batch+=slots){
  await Promise.all(job.workers.slice(batch,batch+slots).filter(w=>w.status!=='completed').map(worker => {
    const assigned = job.worklist.filter(item => worker.assignedPaths.includes(item.path)).map(item => item.path)
    const prompt = diffFileReviewPrompt({ jobId: job.id, workerId: worker.id, token: worker.token, worklistDigest: job.worklistDigest, target: job.target, mode: worker.assignedPaths[0] ? (job.worklist.find(item => item.path === worker.assignedPaths[0])?.mode ?? 'diff') : 'diff', assignedPaths: assigned, threatModel: job.threatModel, userContext: job.userContext, policyGuidance: job.policyGuidance, knowledgeBasePromptText: job.knowledgeBasePromptText, scanPrompt: job.scanPrompt??config.scanPrompt })
    return runDiffWorker(ctx, config, job, worker, prompt, signal)
  }))
  if(signal?.aborted)break
  }
  job = await loadDiffDiscoveryJob(config, jobId)
  const allComplete = job.workers.length > 0 && job.workers.every(worker => worker.status === 'completed')
  const anyCancelled = cancelled(signal)
  await updateJob(config, jobId, current => { current.lifecycle = anyCancelled ? 'cancelled' : allComplete ? 'completed' : 'incomplete' })
  if(allComplete && !signal?.aborted) {
    try { if(!await (await import('../coverage-workflow.js')).closeCoverage(ctx,config,job.scanId,signal)) await updateJob(config,jobId,current=>{current.lifecycle='incomplete';current.notes.push('Coverage critic omitted its terminal receipt.')}) }
    catch(error) { await updateJob(config,jobId,current=>{current.lifecycle=signal?.aborted?'cancelled':'incomplete';current.notes.push(`Coverage critic failed: ${(error as Error).message}`)}) }
  }
  if (allComplete) await persistDiffArtifacts(config, jobId)
  return loadDiffDiscoveryJob(config, jobId)
}

function loadDiffDiscoveryJobSync(config: Config, id: string): DiffDiscoveryJob {
  return JSON.parse(readFileSync(pathFor(getStateDir(config.stateDir), id), 'utf8')) as DiffDiscoveryJob
}

/** Run a diff scan, then LLM file review over the changed files. */
export async function runDiffLlmReview(ctx: Context, config: Config, workspace: string, base: string | undefined, userContext = '', signal?: AbortSignal, requestedMode?: 'working_tree' | 'commit' | 'branch_diff', threatModel = ''): Promise<{ scan: ScanRecord; jobId: string }> {
  const { runDiffScan } = await import('../scanner.js')
  const scan = await runDiffScan(workspace, base, threatModel, config.stateDir, false, requestedMode)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan)
  await saveScan(getStateDir(config.stateDir), scan)
  if (!scan.coverage.receipts.length) return { scan, jobId: '' }
  const job = await createDiffDiscoveryJob(config, scan.id, userContext)
  await runDiffDiscovery(ctx, config, job.id, signal)
  return { scan: await loadScan(getStateDir(config.stateDir), scan.id), jobId: job.id }
}

/** 单一协调者与中断续扫；不重置预算或已完成报告。 */
async function runDiffDiscoveryUnlocked(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<DiffDiscoveryJob> {
 return withJobLease(getStateDir(config.stateDir),jobId,async()=>{
  const initial=await loadDiffDiscoveryJob(config,jobId)
  if(!['queued','cancelled','incomplete','running'].includes(initial.lifecycle))throw new Error('Discovery job is terminal; start an explicitly scoped follow-up instead.')
  await mutateScan(config,initial.scanId,scan=>{scan.discoveryStatus={driver:'diff',jobId,lifecycle:'running'}})
  try{return await runDiffDiscoveryInternal(ctx,config,jobId,signal)}finally{
    const job=await loadDiffDiscoveryJob(config,jobId)
    await mutateScan(config,job.scanId,scan=>{scan.discoveryStatus={driver:'diff',jobId,lifecycle:job.lifecycle,reason:job.notes.at(-1)}})
  }
 })
}

/** 只返回本 Worker 的变更文件 Patch，按字符游标分页；补丁内容是数据，不是指令。 */
export async function readDiffPatch(config:Config,jobId:string,workerId:string,token:string,offset=0){
 const job=await loadDiffDiscoveryJob(config,jobId),worker=activeDiffWorker(job,workerId,token),scan=await loadScan(getStateDir(config.stateDir),job.scanId)
 if(!job.diffArtifact)throw new Error('This older diff job has no frozen patch context; create a new diff scan.')
 const patch=await readArtifact(scan,job.diffArtifact.path);if(sha256(patch)!==job.diffArtifact.sha256)throw new Error('Diff artifact digest changed.')
 // 被删文件没有审阅项，由首个 Worker 负责读取其补丁，否则删除的控制无人看到。
 const firstWorker=job.workers[0]?.id===worker.id,selected=parseUnifiedDiff(patch).filter(file=>worker.assignedPaths.includes(file.path)||(file.oldPath&&worker.assignedPaths.includes(file.oldPath))||(firstWorker&&file.status==='deleted')).map(file=>file.patch).join('')
 const start=Math.max(0,Math.floor(offset)),end=Math.min(selected.length,start+12000)
 return {content:selected.slice(start,end),offset:start,totalCharacters:selected.length,...(end<selected.length?{nextOffset:end}:{}),sha256:sha256(selected)}
}

export async function runDiffDiscovery(ctx:Context,config:Config,jobId:string,signal?:AbortSignal){
 const initial=await loadDiffDiscoveryJob(config,jobId)
 return withScanLease(getStateDir(config.stateDir),initial.scanId,()=>runDiffDiscoveryUnlocked(ctx,config,jobId,signal))
}
