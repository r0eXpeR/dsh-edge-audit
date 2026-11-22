import { policyContext } from '../policy-context.js'
import { auditHistoryContext } from '../audit-history.js'
import { redactSensitive, redactValue } from '../audit-context.js'
import { withScanLease } from '../scan-lease.js'
import { mutateScan } from '../scan-store.js'
import { withJobLease } from '../job-lease.js'
import { currentAuditActor } from '../audit-context.js'
import { observeSourceRead } from '../coverage.js'
import { boundedRange, readFrozenSource, resolveSnapshotLocations } from '../source-evidence.js'
import { ingestModelCandidates } from '../candidate-ingestion.js'
import { buildInvestigationMap, observedRegion, type ReviewRegion, type BoundaryFact } from '../investigation-plan.js'
import { createAuditAgent, waitForAuditAgent, auditTokenUsage, auditExecutionEvidence } from '../runtime.js'
import { readFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { join, relative, resolve } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.js'
import type { ScanRecord } from '../contracts.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, writeArtifact } from '../state.js'
import { readScanKnowledgeBase } from './knowledge-base.js'

/**
 * Standard-scan LLM discovery, aligned with the codex-security `security-scan`
 * skill (Apache-2.0, adapted): one independent baseline auditor worker plus
 * focused investigator workers over source-backed investigation packets,
 * followed by one source-backed validation pass. Deterministic engine receipts
 * remain the immutable evidence baseline: every LLM candidate must cite a
 * receipted in-scope location.
 */

export const LLM_DISCOVERY_WORKERS_PER_SCAN = 6

export type LlmDiscoveryLifecycle = 'queued' | 'running' | 'completed' | 'incomplete' | 'cancelled' | 'failed'
export type LlmWorkerKind = 'baseline' | 'architect' | 'investigator'

export interface LlmWorkerLens {
  /** Distinct review perspective for this worker, codex-security investigator perspectives. */
  id: string
  label: string
  brief: string
}

export const INVESTIGATOR_LENSES: LlmWorkerLens[] = [
  { id: 'forward', label: 'Forward dataflow', brief: 'Follow attacker-controlled input, identity, trust boundaries, and controls toward sensitive operations.' },
  { id: 'backward', label: 'Backward from sinks', brief: 'Start at sensitive operations, parsers, execution, credential issuance, or protected assets and trace callers back to a plausible attacker.' },
  { id: 'authorization', label: 'Authorization and business logic', brief: 'Inspect ownership, tenants, permissions, sessions, capabilities, lifecycle transitions, and guard differences across sibling operations.' },
  { id: 'open-ended', label: 'Open-ended source review', brief: 'Investigate promising source-backed security evidence without restricting the search to a predefined vulnerability class or component.' },
]

export interface LlmSourceLocation { path: string; startLine: number; endLine?: number; role?: string }

export interface LlmCandidate {
  businessBoundary?:import('../contracts.js').Finding['businessBoundary']
  /** Stable lowercase vulnerability-family rule id, e.g. path-traversal.archive-extraction. */
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
  locations: LlmSourceLocation[]
  evidence: Array<{ location: LlmSourceLocation; explanation: string }>
}

export interface ProposedInvestigation { attacker:string;protectedAsset:string;expectedControls:string[];questions:string[];sourceReferences:import('../contracts.js').ReceiptSourceReference[] }
export interface ArchitectureFact {statement:string;sourceReferences:import('../contracts.js').ReceiptSourceReference[]}
export interface LlmWorkerReport {
  architectureFacts?:ArchitectureFact[]
  architectureLimitations?:string[]
  investigationPackets?: ProposedInvestigation[]
  reviewedRegionIds?: string[]
  deferredRegions?: Array<{regionId:string;reason:string}>
  findings: LlmCandidate[]
  resolvedQuestions: string[]
  fullyReviewedFileCount: number
}

export interface LlmWorkerState {
  regions?: ReviewRegion[]
  assignment?: ReviewRegion[]
  checkpoints?: Array<{report:LlmWorkerReport;actorId:string;at:string}>
  executions?: Array<{sessionId:string;status:string;error?:string;transcript:string;usage:ReturnType<typeof auditTokenUsage>;toolCalls:number}>
  coverageUnitIds?: string[]
  id: string
  kind: LlmWorkerKind
  lens?: string
  packetId?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  token: string
  candidateIds: string[]
  report?: LlmWorkerReport
  error?: string
  transcript?: string
  usage?:ReturnType<typeof auditTokenUsage>
}

export interface LlmPacket {
  regions?: ReviewRegion[]
  supportingPaths?: string[]
  sourceFacts?: BoundaryFact[]
  coverageUnitIds?: string[]
  id: string
  attacker: string
  protectedAsset: string
  expectedControls: string[]
  entryPoints: string[]
  sensitiveOperations: string[]
  paths: string[]
  questions: string[]
}

export interface LlmDiscoveryJob {
  purpose?: 'standard' | 'coverage_repair'
  coverageOnly?:boolean
  deadlineAt?: string
  scanPrompt?:string
  priorContext?:string
  policySnapshots?:import('../policy-context.js').PolicySnapshot[]
  id: string
  scanId: string
  target: string
  lifecycle: LlmDiscoveryLifecycle
  createdAt: string
  updatedAt: string
  worklistDigest: string
  /** In-scope source paths frozen from scan receipts, ordered by attack-surface signal. */
  worklist: Array<{ path: string; sha256: string; language: string; riskSignals: string[]; priority: number }>
  threatModel: string
  userContext: string
  policyGuidance: string
  knowledgeBasePromptText: string
  architect?:LlmWorkerState
  architectureFacts?:ArchitectureFact[]
  architectureLimitations?:string[]
  sourceMapRef?:string
  sourceMapDigest?:string
  baseline: LlmWorkerState
  packets: LlmPacket[]
  investigators: LlmWorkerState[]
  candidates: Array<LlmCandidate & { id: string; workerId: string; workerIds?:string[]; workerKind: LlmWorkerKind; packetId?: string; fingerprint: string }>
  notes: string[]
}

/** Risk-signal review leads (mirrors deep-discovery riskSignals). */
function riskSignals(path: string, content: string): string[] {
  const signals: string[] = []
  const value = `${path}\n${content}`
  if (/(?:^|\/)(?:routes?|controllers?|handlers?|api|server|middleware)(?:\/|\.|$)|\b(?:app|router)\.(?:get|post|put|delete|use)\b/i.test(value)) signals.push('externally reachable request surface')
  if (/\b(?:eval|Function|exec(?:File)?|spawn|system|child_process|Runtime\.getRuntime)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(value)) signals.push('execution or query sink')
  if (/\b(?:fetch|axios|request|http\.request|https\.request|urlopen|net\.Dial)\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify/i.test(value)) signals.push('outbound network or transport control')
  if (/\b(?:auth|authori[sz]|permission|role|session|jwt|token|oauth)\b/i.test(value)) signals.push('authorization or identity control')
  if (/\b(?:secret|password|api[_-]?key|private[_ -]?key|credential)\b/i.test(value)) signals.push('credential or key material')
  if (/\b(?:deserialize|pickle|yaml\.load|XMLParser|ObjectInputStream|unserialize)\b/i.test(value)) signals.push('parser or deserialization boundary')
  return [...new Set(signals)]
}

function inside(workspace: string, path: string): boolean {
  const rel = relative(resolve(workspace), resolve(path))
  return rel === '' || (!rel.startsWith('..') && !resolve(rel).startsWith('..'))
}

function pathFor(state: string, id: string): string {
  if (!/^llmdiscovery_[0-9a-f-]+$/.test(id)) throw new Error('Invalid LLM discovery job id.')
  return join(state, 'llm-discovery', `${id}.json`)
}

async function atomicWrite(path: string, content: string): Promise<void> {
  const { mkdir, rename, writeFile } = await import('node:fs/promises')
  await mkdir(resolve(path, '..'), { recursive: true,mode:0o700 })
  const temporary = `${path}.${randomUUID()}.tmp`
  await writeFile(temporary, content, {encoding:'utf8',mode:0o600})
  await rename(temporary, path)
}

const jobWrites = new Map<string, Promise<unknown>>()

async function updateJob(config: Config, id: string, update: (job: LlmDiscoveryJob) => void | Promise<void>): Promise<LlmDiscoveryJob> {
  const previous = jobWrites.get(id) ?? Promise.resolve()
  const barrier = previous.catch(()=>undefined).then(async () => {
    const job = await loadLlmDiscoveryJob(config, id)
    await update(job)
    job.updatedAt = new Date().toISOString()
    await atomicWrite(pathFor(getStateDir(config.stateDir), id), `${JSON.stringify(job, null, 2)}\n`)
    return job
  })
  jobWrites.set(id, barrier)
  await previous.catch(()=>undefined)
  try { return await barrier } finally { if (jobWrites.get(id) === barrier) jobWrites.delete(id) }
}

export async function loadLlmDiscoveryJob(config: Config, id: string): Promise<LlmDiscoveryJob> {
  const { readFile } = await import('node:fs/promises')
  return JSON.parse(await readFile(pathFor(getStateDir(config.stateDir), id), 'utf8')) as LlmDiscoveryJob
}

export async function createLlmDiscoveryJob(config: Config, scanId: string, userContext = ''): Promise<LlmDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, scanId)
  if(scan.lifecycle==='completed')throw new Error('Completed scans are immutable; create a follow-up scan.')
  if(!scan.coverage.receipts.length)throw new Error('No receipted source is available for LLM discovery; select an eligible source scope.')
  const parent=config.auditBudgetScanId?await loadScan(state,config.auditBudgetScanId):scan
  const deadlineAt=scan.auditDeadlineAt??parent.auditDeadlineAt??new Date(Date.parse(scan.createdAt)+(config.maxAuditTimeHours??4)*3_600_000).toISOString()
  await mutateScan(config,scan.id,s=>{s.auditDeadlineAt=deadlineAt;s.finalRecordReviewRequired=true})
  const kb = await readScanKnowledgeBase(config, scan.id)
  const rows = await Promise.all(scan.coverage.receipts.map(async receipt => {
    const source = resolve(scan.evidenceRoot??scan.target, receipt.path)
    if (!inside(scan.evidenceRoot??scan.target, source)) throw new Error('Scan receipt path is outside the scan target.')
    const content = await readFrozenSource(scan.evidenceRoot??scan.target,receipt)
    const signals = riskSignals(receipt.path, content)
    return { path: receipt.path, sha256: receipt.sourceSha256??receipt.sha256, language: receipt.language, riskSignals: signals, priority: signals.length * 100 + (receipt.path.includes('/') ? 0 : 10) }
  }))
  const worklist = rows.sort((left, right) => right.priority - left.priority || left.path.localeCompare(right.path))
  const map = await buildInvestigationMap(scan,config.discoveryBatchRegions??6)
  const packets = map.packets
  const now = new Date().toISOString()
  const job: LlmDiscoveryJob = {
    id: `llmdiscovery_${randomUUID()}`,
    scanId, target: scan.evidenceRoot??scan.target,
    lifecycle: 'queued', createdAt: now, updatedAt: now, deadlineAt,
    worklistDigest: sha256(JSON.stringify(worklist)),
    worklist, threatModel: scan.threatModel, userContext, policyGuidance: scan.policyGuidance,policySnapshots:scan.policySnapshots,
    knowledgeBasePromptText: kb.promptText,scanPrompt:config.scanPrompt??'',priorContext:config.auditPriorContext??await auditHistoryContext(state,scan,config.auditBudgetScanId),
    architect:{id:'architect_1',kind:'architect',status:'pending',token:randomUUID(),candidateIds:[],regions:map.regions.filter((r,i,all)=>all.findIndex(x=>x.path===r.path)===i).slice(0,12)},
    baseline: { id: `baseline_1`, kind: 'baseline', status: 'pending', token: randomUUID(), candidateIds: [], regions:map.regions },
    packets, investigators: [],
    candidates: [], notes: kb.skipped.length ? [`Knowledge base skipped ${kb.skipped.length} document(s): ${kb.skipped.map(item => `${item.path} (${item.reason})`).join('; ')}`] : [],
  }
  const historical=JSON.parse(job.priorContext??'{"records":[],"gaps":[]}') as {records:Array<{paths?:string[];semanticSourceKey?:string;fingerprint?:string;title?:string;previousDisposition?:string;currentSourceUnchanged?:boolean;previousCounterevidence?:string}>;gaps?:Array<{path:string;startLine:number;endLine:number;attackClass:string;boundary:string;priorStatus:string;priorReason:string;currentSourceUnchanged:boolean}>}
  for(const record of (historical.records??[]).filter(r=>r.paths?.some(path=>worklist.some(w=>w.path===path))).slice(0,12)){
    const paths=record.paths!.filter(path=>worklist.some(w=>w.path===path))
    const priorId=`packet_prior_${sha256(record.semanticSourceKey??record.fingerprint??JSON.stringify(record)).slice(0,20)}`;if(job.packets.some(p=>p.id===priorId))continue
    job.packets.unshift({id:priorId,attacker:'Reconstruct the current principal; a historical verdict is not current proof.',protectedAsset:record.title??'The exact historical source control.',expectedControls:[],entryPoints:[],sensitiveOperations:[],paths,regions:map.regions.filter(r=>paths.includes(r.path)),questions:[`Revalidate the exact prior claim ${record.title??record.fingerprint}. Earlier disposition ${record.previousDisposition}; current source unchanged=${record.currentSourceUnchanged}. Recheck the actual control and counterevidence: ${record.previousCounterevidence??'not established'}. Do not automatically suppress, confirm or inherit coverage.`]})
  }
  const groupedGaps=new Map<string,NonNullable<typeof historical.gaps>>()
  for(const gap of (historical.gaps??[]).filter(g=>worklist.some(w=>w.path===g.path)).slice(0,24)){
    const region=gap.currentSourceUnchanged?map.regions.find(r=>r.path===gap.path&&r.startLine<=gap.startLine&&r.endLine>=gap.startLine):undefined
    if(gap.currentSourceUnchanged&&!region)continue
    const key=region?`${gap.path}:${region.startLine}`:`${gap.path}:changed`
    groupedGaps.set(key,[...(groupedGaps.get(key)??[]),gap])
  }
  for(const [key,gaps] of groupedGaps)for(let offset=0;offset<gaps.length;offset+=8){
    const chunk=gaps.slice(offset,offset+8),[first]=chunk,regions=map.regions.filter(r=>r.path===first.path&&(!first.currentSourceUnchanged||chunk.some(g=>r.startLine<=g.startLine&&r.endLine>=g.startLine)))
    job.packets.unshift({id:`packet_prior_gap_${sha256(`${key}:${offset}`).slice(0,20)}`,attacker:'Derive the current lower-trust principal from source.',protectedAsset:'Reconstruct the resource and invariant at this prior unresolved boundary.',expectedControls:[],entryPoints:[],sensitiveOperations:[],paths:[first.path],regions,questions:chunk.map(g=>`Recheck prior ${g.priorStatus} ${g.attackClass} boundary in ${g.path}${g.currentSourceUnchanged?` at ${g.startLine}-${g.endLine}`:'; historical line numbers are stale because the source changed'}: ${g.boundary}. Earlier reason: ${g.priorReason}. Review current source independently; do not inherit its prior status.`)})
  }
  const mapText=JSON.stringify(map,null,2)+'\n';job.sourceMapRef=await writeArtifact(scan,`artifacts/01_context/maps/${job.id}.json`,mapText);job.sourceMapDigest=sha256(mapText)
  await atomicWrite(pathFor(state, job.id), `${JSON.stringify(job, null, 2)}\n`)
  return job
}

function workerFor(job:LlmDiscoveryJob,id:string):LlmWorkerState|undefined{return [job.baseline,...(job.architect?[job.architect]:[]),...job.investigators].find(w=>w.id===id)}

export function activeWorker(job: LlmDiscoveryJob, workerId: string, token: string): LlmWorkerState {
  if (job.lifecycle !== 'running') throw new Error('LLM discovery job is not running.')
  const worker = workerFor(job,workerId)
  if (!worker) throw new Error('Worker is not part of this LLM discovery job.')
  if (worker.status !== 'running') throw new Error('Worker is not active for this LLM discovery job.')
  if (worker.token !== token) throw new Error('Worker claim token does not own this worker.')
  return worker
}

export interface LlmScope {
 jobId:string;scanId:string;target:string;worklistDigest:string;totalFiles:number;nextOffset?:number;contextTruncated:boolean;
 workerKind:LlmWorkerKind;assignedRegions?:ReviewRegion[];worklist:Array<{path:string;language:string;riskSignals:string[]}>;
 contextRefs:Array<{tool:string;kind:string}>;threatModel:string;userContext:string;policyGuidance:string;knowledgeBasePromptText:string;packet?:LlmPacket;lens?:string
}
export function getLlmScope(config:Config,jobId:string,workerId:string,token:string,offset=0,limit=100):LlmScope{
 const job=loadLlmDiscoveryJobSync(config,jobId),worker=activeWorker(job,workerId,token)
 const assigned=worker.assignment,visible=assigned?job.worklist.filter(item=>assigned.some(r=>r.path===item.path)):job.worklist
 const packet=worker.kind==='investigator'?job.packets.find(p=>p.id===worker.packetId):undefined
 const brief=packet?{...packet,sourceFacts:packet.sourceFacts?.slice(0,6),questions:packet.questions.slice(0,3).map(q=>q.slice(0,500)),expectedControls:packet.expectedControls.slice(0,6).map(q=>q.slice(0,300)),regions:undefined}:undefined
 const contextRefs=['threat_model','user_context','policy','knowledge_base','scan_prompt',...(packet?['packet','architecture']:[]),...(job.sourceMapRef?['structure']:[]),...(job.priorContext?['history']:[])].map(kind=>({tool:'security_llm_read_context',kind}))
 const start=Math.max(0,Math.floor(offset)),files=visible.slice(start,start+Math.max(1,Math.min(100,Math.floor(limit))))
 const make=():LlmScope=>({workerKind:worker.kind,jobId,scanId:job.scanId,target:job.target,worklistDigest:job.worklistDigest,assignedRegions:assigned?.filter(r=>files.some(f=>f.path===r.path)),contextRefs,contextTruncated:true,threatModel:redactSensitive(job.threatModel).slice(0,1000),userContext:redactSensitive(job.userContext).slice(0,1000),policyGuidance:redactSensitive(job.policyGuidance).slice(0,1000),knowledgeBasePromptText:redactSensitive(job.knowledgeBasePromptText).slice(0,1000),packet:brief,lens:worker.lens,totalFiles:visible.length,worklist:files.map(({path,language,riskSignals})=>({path,language,riskSignals})),...(start+files.length<visible.length?{nextOffset:start+files.length}:{})})
 while(Buffer.byteLength(JSON.stringify(make()))>24576&&files.length>1)files.pop()
 const result=make()
 if(Buffer.byteLength(JSON.stringify(result))>24576&&result.packet)result.packet={...result.packet,sourceFacts:undefined,questions:['Read the full assigned packet with security_llm_read_context kind packet.'],expectedControls:[],entryPoints:[],sensitiveOperations:[],supportingPaths:undefined}
 if(Buffer.byteLength(JSON.stringify(result))>24576)throw new Error('The source assignment exceeds the safe tool context budget; reduce discoveryBatchRegions.')
 return result
}
export async function readLlmContext(config:Config,jobId:string,workerId:string,token:string,kind:'threat_model'|'user_context'|'policy'|'knowledge_base'|'scan_prompt'|'packet'|'architecture'|'structure'|'history',offset=0){
 const job=await loadLlmDiscoveryJob(config,jobId),worker=activeWorker(job,workerId,token)
 let structure=''
 if(kind==='structure'&&job.sourceMapRef){const scan=await loadScan(getStateDir(config.stateDir),job.scanId),text=await (await import('../state.js')).readArtifact(scan,job.sourceMapRef);if(sha256(text)!==job.sourceMapDigest)throw new Error('Frozen source map changed after job creation.');structure=JSON.stringify(redactValue(JSON.parse(text)))}
 const values={history:job.priorContext??'',architecture:worker.kind==='investigator'?JSON.stringify(redactValue({facts:job.architectureFacts??[],limitations:job.architectureLimitations??[]})):'',structure,threat_model:job.threatModel,user_context:job.userContext,policy:policyContext(job.policyGuidance,job.policySnapshots??[],worker.assignment?.map(r=>r.path)??[]),knowledge_base:job.knowledgeBasePromptText,scan_prompt:job.scanPrompt??'',packet:worker.kind==='investigator'?JSON.stringify(redactValue(job.packets.find(p=>p.id===worker.packetId))):''}
 if(!Object.hasOwn(values,kind))throw new Error('Unknown frozen worker context kind.')
 const value=redactSensitive(values[kind]??''),start=Math.max(0,Math.floor(offset)),end=Math.min(value.length,start+8000)
 return {kind,content:value.slice(start,end),totalCharacters:value.length,sha256:sha256(value),...(end<value.length?{nextOffset:end}:{})}
}

export async function readLlmSource(config: Config, jobId: string, workerId: string, token: string, path: string, startLine?: number, endLine?: number): Promise<{ path: string; sha256: string; startLine: number; endLine: number; content: string }> {
  const job = await loadLlmDiscoveryJob(config, jobId)
  activeWorker(job, workerId, token)
  const item = job.worklist.find(entry => entry.path === path)
  if (!item) throw new Error('Path is not in the LLM discovery in-scope worklist.')
  const source = resolve(job.target, item.path)
  if (!inside(job.target, source)) throw new Error('Path is outside the scan target.')
  const content = await readFrozenSource(job.target,{...item,bytes:0})
  const range=boundedRange(content,startLine,endLine)
  await observeSourceRead(config,job.scanId,item.path,range.startLine,range.endLine,item.sha256,`${job.id}:${workerId}`)
  return {path:item.path,sha256:item.sha256,...range}
}

/** Deterministic ripgrep-style regex search over receipted in-scope files. */
export async function searchLlmSource(config: Config, jobId: string, workerId: string, token: string, pattern: string, maxResults = 50): Promise<Array<{ path: string; line: number; text: string }>> {
  const job = await loadLlmDiscoveryJob(config, jobId)
  activeWorker(job, workerId, token)
  if(pattern.length>256 || /(?<!\\)[(){}]/.test(pattern) || /\\[1-9]/.test(pattern) || (pattern.match(/(?<!\\)[*+?]/g)??[]).length>2)throw new Error('Search uses a bounded regex subset: no groups, backreferences, counted repetition, and at most two quantifiers.')
  maxResults=Math.max(1,Math.min(200,Math.floor(maxResults)))
  let regex: RegExp
  try { regex = new RegExp(pattern, 'i') } catch { throw new Error('Search pattern is not a valid regular expression.') }
  const results: Array<{ path: string; line: number; text: string }> = []
  for (const item of job.worklist) {
    const source = resolve(job.target, item.path)
    if (!inside(job.target, source)) continue
    const content = await readFile(source, 'utf8')
    if (sha256(content) !== item.sha256) throw new Error(`Source file changed after the LLM discovery worklist was created: ${item.path}.`)
    const lines = content.split(/\r?\n/),safeLines=redactSensitive(content).split(/\r?\n/)
    for (let index = 0; index < lines.length && results.length < maxResults; index++) {
      regex.lastIndex = 0
      if (regex.test(lines[index].slice(0,2000))) results.push({ path: item.path, line: index + 1, text: safeLines[index].slice(0, 300) })
    }
    if (results.length >= maxResults) break
  }
  return results
}

export interface ReportedLlmCandidateInput {
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
  evidence: Array<{ location: { path: string; startLine: number; endLine?: number; role?: string }; explanation: string }>
}

function validateLlmCandidate(config: Config, job: LlmDiscoveryJob, candidate: ReportedLlmCandidateInput): LlmCandidate {
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(candidate.ruleId)) throw new Error('ruleId must be a stable lowercase slug, e.g. path-traversal.archive-extraction.')
  if (!candidate.locations.length) throw new Error('Candidate requires at least one concrete source location.')
  for (const location of candidate.locations) {
    const item = job.worklist.find(entry => entry.path === location.path)
    if (!item) throw new Error(`Candidate location ${location.path} is outside the in-scope worklist.`)
    if (!Number.isInteger(location.startLine) || location.startLine < 1) throw new Error(`Candidate location ${location.path} has an invalid startLine.`)
  }
  return { ...candidate, cwe:candidate.cwe??'',evidence:candidate.evidence??[],severity: candidate.severity, confidence: candidate.confidence }
}

export async function reportLlmCandidates(config: Config, jobId: string, workerId: string, token: string, candidates: ReportedLlmCandidateInput[]): Promise<{ recorded: number; candidateIds: string[] }> {
  const state = getStateDir(config.stateDir)
  const scan = await loadScan(state, (await loadLlmDiscoveryJob(config, jobId)).scanId)
  const job = await updateJob(config, jobId, async current => {
    const worker = activeWorker(current, workerId, token)
    if(worker.kind==='architect')throw new Error('Architecture review proposes source-backed questions, not vulnerability candidates.')
    const validated=candidates.map(input=>validateLlmCandidate(config,current,input))
    await ingestModelCandidates(config,current.scanId,current.id,workerId,validated,'dsh-llm')
    for (const input of candidates) {
      const candidate = validateLlmCandidate(config, current, input)
      const fingerprint = sha256(JSON.stringify([candidate.ruleId,candidate.cwe,candidate.locations.map(l=>[l.path,l.startLine,l.role]).sort()]))
      const id = `llmcand_${sha256(fingerprint).slice(0, 24)}`
      const existing=current.candidates.find(item=>item.id===id)
      if(existing){existing.workerIds=[...new Set([...(existing.workerIds??[existing.workerId]),workerId])];if(!worker.candidateIds.includes(id))worker.candidateIds.push(id);continue}
      current.candidates.push({ ...candidate, id, workerId, workerIds:[workerId], workerKind: worker.kind, packetId: worker.packetId, fingerprint })
      worker.candidateIds.push(id)
    }
  })

  return { recorded: job.candidates.length, candidateIds: job.candidates.map(candidate => candidate.id) }
}

export async function reportLlmWorker(config: Config, jobId: string, workerId: string, token: string, report: LlmWorkerReport): Promise<void> {
  await updateJob(config, jobId, async current => {
    const worker = activeWorker(current, workerId, token)
    if (!Number.isInteger(report.fullyReviewedFileCount) || report.fullyReviewedFileCount < 0) throw new Error('fullyReviewedFileCount must be a nonnegative integer.')
    const snapshot=await loadScan(getStateDir(config.stateDir),current.scanId)
    const rows=(snapshot.auditTrail??[]).filter(row=>row.kind==='source_read' && row.actorId===(currentAuditActor()?.id ?? `${current.id}:${workerId}`))
    const readFiles=new Set(rows.map(row=>row.path))
    let fullyRead=0
    for(const path of readFiles){const regions=current.baseline.regions?.filter(r=>r.path===path);if(!regions?.length){fullyRead++;continue}const full={...regions[0],startLine:1,endLine:Math.max(...regions.map(r=>r.endLine))};if(observedRegion(snapshot,currentAuditActor()?.id??`${current.id}:${workerId}`,full))fullyRead++}
    if(report.fullyReviewedFileCount>fullyRead)throw new Error('Reviewed file count exceeds observed source reads; report exact gaps instead.')
    if(worker.kind==='architect'){
      if(!(report.architectureFacts?.length)&&!report.architectureLimitations?.some(l=>l.trim().length>=20))throw new Error('Architecture review requires observed source assertions or an exact mapping limitation.')
      if((report.architectureFacts?.length??0)>32)throw new Error('An architecture checkpoint accepts at most 32 source assertions.')
      const actorId=currentAuditActor()?.id??`${current.id}:${workerId}`
      for(const fact of report.architectureFacts??[]){
        if(fact.statement.trim().length<20||fact.statement.length>2000||!fact.sourceReferences.length)throw new Error('Architecture assertions require substantive statements and exact source references.')
        const refs=await resolveSnapshotLocations(snapshot,fact.sourceReferences)
        for(const ref of refs){const source=current.worklist.find(s=>s.path===ref.file);if(!source||!observedRegion(snapshot,actorId,{id:'architecture',path:ref.file,startLine:ref.line,endLine:ref.line,sha256:source.sha256}))throw new Error('Architecture assertion cites source not actually read by this Session.')}
      }
      current.architectureFacts??=[];current.architectureFacts.push(...(report.architectureFacts??[]))
      current.architectureLimitations=[...new Set([...(current.architectureLimitations??[]),...(report.architectureLimitations??[])])]
    }
    if(report.investigationPackets?.length){
      if(!['baseline','architect'].includes(worker.kind))throw new Error('Only independent baseline or architecture review may propose source-backed investigation packets.')
      if(report.investigationPackets.length>16)throw new Error('A checkpoint accepts at most sixteen focused investigations.')
      for(const proposal of report.investigationPackets){
        if(proposal.attacker.trim().length<12||proposal.protectedAsset.trim().length<12||!proposal.questions.length)throw new Error('Investigation packets require a concrete principal, protected asset and source-backed question.')
        const locations=await resolveSnapshotLocations(snapshot,proposal.sourceReferences)
        const actorId=currentAuditActor()?.id??`${current.id}:${workerId}`
        for(const ref of locations){const source=current.worklist.find(r=>r.path===ref.file);if(!source||!observedRegion(snapshot,actorId,{id:'proposal',path:ref.file,startLine:ref.line,endLine:ref.line,sha256:source.sha256}))throw new Error('A proposed investigation must cite source actually read by this baseline Session.')}
        const paths=[...new Set(locations.map(l=>l.file))],id=`packet_model_${sha256(JSON.stringify(proposal)).slice(0,24)}`
        if(!current.packets.some(p=>p.id===id))current.packets.push({id,attacker:proposal.attacker,protectedAsset:proposal.protectedAsset,expectedControls:proposal.expectedControls,questions:proposal.questions,paths,entryPoints:locations.filter(l=>l.role==='entrypoint').map(l=>`${l.file}:${l.line}`),sensitiveOperations:locations.filter(l=>l.role==='sink').map(l=>`${l.file}:${l.line}`),regions:current.baseline.regions?.filter(r=>paths.includes(r.path))})
      }
    }
    if(worker.assignment){
      const actorId=currentAuditActor()?.id ?? `${current.id}:${workerId}`
      const reviewed=new Set(report.reviewedRegionIds ?? worker.assignment.filter(r=>observedRegion(snapshot,actorId,r)).map(r=>r.id))
      const deferred=new Map((report.deferredRegions??[]).map(r=>[r.regionId,r.reason]))
      const assigned=new Set(worker.assignment.map(r=>r.id))
      if([...reviewed,...deferred.keys()].some(id=>!assigned.has(id)))throw new Error('Checkpoint includes an unassigned region.')
      for(const region of worker.assignment){
        if(reviewed.has(region.id)&&deferred.has(region.id))throw new Error('A region cannot be both reviewed and deferred.')
        if(reviewed.has(region.id)&&!observedRegion(snapshot,actorId,region))throw new Error('Checkpoint review requires observed full source-region reads.')
        if(!reviewed.has(region.id)&&(!deferred.get(region.id)||deferred.get(region.id)!.trim().length<8))throw new Error('Checkpoint leaves an assigned region unclosed; explicitly defer it with a reason.')
      }
      report={...report,reviewedRegionIds:[...reviewed],deferredRegions:[...deferred].map(([regionId,reason])=>({regionId,reason}))}
      worker.checkpoints??=[];worker.checkpoints.push({report,actorId,at:new Date().toISOString()})
      const closed=new Set(worker.checkpoints.flatMap(c=>[...(c.report.reviewedRegionIds??[]),...(c.report.deferredRegions??[]).map(r=>r.regionId)]))
      worker.status=worker.regions!.every(r=>closed.has(r.id))?'completed':'pending'
    } else worker.status = 'completed'
    worker.report = report
  })
}

function loadLlmDiscoveryJobSync(config: Config, id: string): LlmDiscoveryJob {
  // Synchronous load for tool bodies that already hold the job in memory.
  return JSON.parse(readFileSync(pathFor(getStateDir(config.stateDir), id), 'utf8')) as LlmDiscoveryJob
}

/** Freeze worker and packet artifacts, then seal the completed discovery round. */
export async function persistLlmDiscoveryArtifacts(config: Config, jobId: string): Promise<{ artifactRefs: string[] }> {
  const state = getStateDir(config.stateDir)
  const job = await loadLlmDiscoveryJob(config, jobId)
  const scan = await loadScan(state, job.scanId)
  const refs: string[] = []
  const base = 'artifacts/02_discovery/llm'
  const write = async (path: string, content: string): Promise<void> => { refs.push(await writeArtifact(scan, path, content)) }
  await write(`${base}/rank_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: item.riskSignals[0] ?? 'general', preview: '' })).join('\n')}\n`)
  await write(`${base}/deep_review_input.jsonl`, `${job.worklist.map(item => JSON.stringify({ path: item.path, area: item.riskSignals[0] ?? 'general' })).join('\n')}\n`)
  if(job.purpose!=='coverage_repair')await write('artifacts/01_context/architecture-review.json',JSON.stringify({facts:job.architectureFacts??[],limitations:job.architectureLimitations??[],sourceMapRef:job.sourceMapRef},null,2)+'\n')
  // 生成的模板只是起点；架构审阅读过源码后的事实要进入验证者看到的威胁模型。用户提供的模型不改写。
  const facts=job.architectureFacts??[],heading='## Source-Cited Architecture Facts'
  if(job.purpose!=='coverage_repair'&&scan.threatModelGenerated&&facts.length&&!scan.threatModel.includes(heading))scan.threatModel=`${scan.threatModel.trimEnd()}\n\n${heading}\n${facts.map(fact=>`- ${fact.statement} (${fact.sourceReferences.map(ref=>`${ref.file}:${ref.line}`).join(', ')})`).join('\n')}${job.architectureLimitations?.length?`\n\n## Known Mapping Limitations\n${job.architectureLimitations.map(item=>`- ${item}`).join('\n')}`:''}\n`
  await write(`${base}/packets.json`, `${JSON.stringify(job.packets, null, 2)}\n`)
  for (const worker of [job.baseline,...(job.architect?[job.architect]:[]), ...job.investigators]) {
    if (!worker.report) continue
    const dir = `${base}/${worker.id}`
    await write(`${dir}/candidates.jsonl`, `${worker.candidateIds.map(id => JSON.stringify(job.candidates.find(candidate => candidate.id === id))).filter(Boolean).join('\n')}\n`)
    await write(`${dir}/report.json`, `${JSON.stringify(worker.report, null, 2)}\n`)
  }
  await write(`${base}/discovery_ledger.md`, ['# LLM Discovery Ledger', '', `- Job: \`${job.id}\``, `- Worklist digest: \`${job.worklistDigest}\``, `- Baseline worker: \`${job.baseline.id}\` (${job.baseline.status})`, `- Investigators: ${job.investigators.map(worker => `\`${worker.id}\` (${worker.lens ?? 'no-lens'}, ${worker.status})`).join(', ')}`, `- Candidates: ${job.candidates.length}`, ...job.notes.map(note => `- Note: ${note}`), ''].join('\n'))
  await persistInvestigationArtifacts(state, scan)
  await saveScan(state, scan)
  return { artifactRefs: refs }
}

/** The worker-bound tool view for LLM discovery workers. */
export const LLM_WORKER_TOOLS = ['security_llm_get_scope', 'security_llm_read_context', 'security_llm_read_source', 'security_llm_search', 'security_llm_report_candidates', 'security_llm_report_worker', 'security_get_coverage', 'security_record_coverage_check', 'security_read_scan_context', 'security_read_skill'] as const

type NativeAgents = { create?: unknown }

function nativeAgents(ctx: Context): NativeAgents | undefined {
  const get = (ctx as Context & { get?: (name: string) => unknown }).get
  return (typeof get === 'function' ? get.call(ctx, 'agents') : (ctx as Context & { agents?: NativeAgents }).agents) as NativeAgents | undefined
}

/** This suite delegates only through the public DSH agent registry. */
export function llmDiscoveryCapability(ctx: Context): { available: boolean; workers: number; reason?: string } {
  const agents = nativeAgents(ctx)
  if (!agents || typeof agents.create !== 'function') return { available: false, workers: LLM_DISCOVERY_WORKERS_PER_SCAN, reason: 'The active DSH profile has no native agent-creation service.' }
  return { available: true, workers: LLM_DISCOVERY_WORKERS_PER_SCAN }
}

function transcript(agent: { session: { deriveMessages(): ReadonlyArray<{ role: string; content: ReadonlyArray<{ type: string; text?: string }> }> } }): string {
  return agent.session.deriveMessages().filter(message => message.role === 'assistant').flatMap(message => message.content.filter(block => block.type === 'text' || block.type === 'reasoning').map(block => block.text ?? '')).join('\n\n').slice(-200_000)
}

function cancelled(signal: AbortSignal | undefined): boolean { return signal?.aborted === true }

async function runLlmWorker(ctx: Context, config: Config, job: LlmDiscoveryJob, worker: LlmWorkerState, prompt: string, signal?: AbortSignal): Promise<void> {
  const { createUserMessage } = await import('@deepseek-ai/dsh-llm')
  const { SessionId } = await import('@deepseek-ai/dsh-session')
  const sessionId = SessionId(`dsh-edge-llm-${randomUUID()}`)
  await updateJob(config, job.id, current => { const record = workerFor(current,worker.id); if (!record) throw new Error('LLM discovery worker was not created.'); record.status = 'running';record.report=undefined;record.error=undefined; if(record.regions){const done=new Set((record.checkpoints??[]).flatMap(c=>[...(c.report.reviewedRegionIds??[]),...(c.report.deferredRegions??[]).map(r=>r.regionId)]));record.assignment=record.regions.filter(r=>!done.has(r.id)).slice(0,config.discoveryBatchRegions??6)} })
  job=await loadLlmDiscoveryJob(config,job.id)
  const assignedWorker=workerFor(job,worker.id)!
  const scanForAssignment=await loadScan(getStateDir(config.stateDir),job.scanId)
  const unitIds=assignedWorker.coverageUnitIds??(assignedWorker.assignment?(scanForAssignment.coverage.ledger??[]).filter(u=>assignedWorker.assignment!.some(r=>r.path===u.path&&r.startLine<=u.startLine&&r.endLine>=u.endLine)).map(u=>u.id):undefined)
  if(job.coverageOnly)prompt+='\nThis is focused candidate verification: close the assigned coverage units without reporting new findings. Return separate variant observations only as unresolved questions for explicit follow-up.'
  prompt+=`\n\nRead the runtime assignment-budget section; its clock starts only after model capacity is acquired.\nThis invocation owns only the assignedRegions returned by security_llm_get_scope. Supporting reads may use any frozen in-scope source. Checkpoint reviewed_region_ids and deferred_regions through security_llm_report_worker. Coverage unit assignments: ${(assignedWorker.coverageUnitIds??[]).join(', ')||'all boundary units intersecting assignedRegions'}.`
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
      agentCtx.tools.restrict({ allow: worker.kind==='architect'?LLM_WORKER_TOOLS.filter(n=>!['security_llm_report_candidates','security_get_coverage','security_record_coverage_check'].includes(n)):job.coverageOnly?LLM_WORKER_TOOLS.filter(n=>n!=='security_llm_report_candidates'):[...LLM_WORKER_TOOLS] })
      agentCtx.systemPrompt.section({ name: `dsh-edge-audit:llm-worker:${worker.id}`, order: 162, interpolate: false, text: prompt })
    } }, {stateDir:config.stateDir,maxConcurrentModelWorkers:config.maxConcurrentModelWorkers,workerTimeoutMs:config.workerTimeoutMs,budgetScanId:config.auditBudgetScanId,maxModelTokens:config.maxModelTokens,id:`${job.id}:${worker.id}`,role:worker.kind==='architect'?'architect':'discoverer',scanId:job.scanId,jobId:job.id,workerId:worker.id,coverageUnitIds:unitIds,domains:[...new Set((scanForAssignment.coverage.ledger??[]).filter(u=>!unitIds||unitIds.includes(u.id)).map(u=>u.attackClass))]})
    if (cancelledByCaller) return
    handle.agent.followup(createUserMessage({ content: [{ type: 'text', text: prompt }], source: { kind: 'dsh-edge-audit', form: 'relay' } }))
    if (signal) {
      let removeAbortWait = (): void => undefined
      const aborted = new Promise<void>(resolveAbort => { const wake = (): void => resolveAbort(); signal.addEventListener('abort', wake, { once: true }); removeAbortWait = (): void => signal.removeEventListener('abort', wake) })
      try { await Promise.race([waitForAuditAgent(handle.agent, signal, config.workerTimeoutMs), aborted]) } finally { removeAbortWait() }
    } else await waitForAuditAgent(handle.agent, signal, config.workerTimeoutMs)
    if (cancelledByCaller) return
    const workerTranscript = transcript(handle.agent)
    await updateJob(config, job.id, current => { const record = workerFor(current,worker.id); if (record && record.status !== 'cancelled') { record.usage=auditTokenUsage(handle!.agent);record.transcript = workerTranscript; record.status = record.report ? record.status : 'failed'; if(!record.report) record.error='Worker became idle without a terminal report.' } })
  } catch (error) {
    if (cancelledByCaller) return
    const message = error instanceof Error ? error.message : String(error)
    await updateJob(config, job.id, current => { const record = workerFor(current,worker.id); if (record) { record.status = 'failed'; record.error = message } })
  } finally {
    if(handle){const evidence=auditExecutionEvidence(handle.agent);await updateJob(config,job.id,current=>{const row=workerFor(current,worker.id);if(row){row.transcript=evidence.transcript;row.usage=evidence.usage;row.executions??=[];row.executions.push({sessionId:String(sessionId),status:row.status,error:row.error,...evidence})}})}
    signal?.removeEventListener('abort', onAbort)
    if (cancelledByCaller) await updateJob(config, job.id, current => { const record = workerFor(current,worker.id); if (record && record.status !== 'completed') { record.status = 'cancelled'; record.error = 'Cancelled by the owning DSH tool call.' } })
    await dispose()
  }
}

/** 每批独立 Session，已完成区域不因后续超时或重启被抹掉。 */
async function runWorkerBatches(ctx:Context,config:Config,job:LlmDiscoveryJob,worker:LlmWorkerState,prompt:string,signal?:AbortSignal):Promise<void>{
  do {
    if(signal?.aborted)return
    if(job.deadlineAt && Date.now()>=Date.parse(job.deadlineAt))return
    await runLlmWorker(ctx,config,job,worker,prompt,signal)
    job=await loadLlmDiscoveryJob(config,job.id)
    worker=workerFor(job,worker.id)!
  } while(worker.status==='pending' && !!worker.regions)
}

/**
 * Run one standard-scan LLM discovery job: one independent baseline auditor,
 * then focused investigators per source-backed packet, then persist artifacts
 * and scan candidates. Nonterminal worker failure marks the job incomplete.
 */
async function runLlmDiscoveryInternal(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<LlmDiscoveryJob> {
  const state = getStateDir(config.stateDir)
  let job = await loadLlmDiscoveryJob(config, jobId)
  if (job.lifecycle==='running') {job.lifecycle='incomplete'}
  if (!['queued', 'cancelled', 'incomplete'].includes(job.lifecycle)) throw new Error('LLM discovery job has already completed or failed.')
  const capability = llmDiscoveryCapability(ctx)
  if (!capability.available) {
    await updateJob(config, jobId, current => { current.lifecycle = 'failed' })
    throw new Error(capability.reason ?? 'The active DSH profile has no native agent-creation service.')
  }
  await updateJob(config, jobId, current => { current.lifecycle = 'running' })
  job = await loadLlmDiscoveryJob(config, jobId)
  const { baselineAuditorPrompt, focusedInvestigatorPrompt, architectureReviewerPrompt } = await import('./prompts.js')
  const shared: Omit<Parameters<typeof baselineAuditorPrompt>[0], 'jobId' | 'workerId' | 'claimToken' | 'lens' | 'packet'> = {
    worklistDigest: job.worklistDigest, target: job.target, threatModel: job.threatModel, userContext: job.userContext,
    policyGuidance: job.policyGuidance, knowledgeBasePromptText: job.knowledgeBasePromptText, scanPrompt: job.scanPrompt??config.scanPrompt,
  }
  const baselinePrompt = baselineAuditorPrompt({ ...shared, jobId: job.id, workerId: job.baseline.id, claimToken: job.baseline.token })
  if(job.purpose!=='coverage_repair')await Promise.all([
    job.baseline.status!=='completed'?runWorkerBatches(ctx,config,job,job.baseline,baselinePrompt,signal):Promise.resolve(),
    job.architect&&job.architect.status!=='completed'?runWorkerBatches(ctx,config,job,job.architect,architectureReviewerPrompt({...shared,jobId:job.id,workerId:job.architect.id,claimToken:job.architect.token}),signal):Promise.resolve(),
  ])
  job = await loadLlmDiscoveryJob(config, jobId)
  if (job.purpose!=='coverage_repair' && (job.baseline.status !== 'completed'||(job.architect&&job.architect.status!=='completed'))) {
    await updateJob(config, jobId, current => { current.lifecycle = current.baseline.status === 'cancelled' ? 'cancelled' : 'incomplete' })
    return loadLlmDiscoveryJob(config, jobId)
  }
  // Build one investigator per packet, capped at the remaining worker slots.
  const slots = Math.max(1, Math.min(8,config.investigatorConcurrency??LLM_DISCOVERY_WORKERS_PER_SCAN - 1))
  const assignments = job.packets.map((packet, index) => {
    const lens = INVESTIGATOR_LENSES[index % INVESTIGATOR_LENSES.length]
    return { packet, lens }
  })
  await updateJob(config, jobId, current => {
    if(current.investigators.length)return
    current.investigators = assignments.map((assignment, index) => ({
      id: `investigator_${index + 1}`, kind: 'investigator' as const, lens: assignment.lens.id, packetId: assignment.packet.id,
      status: 'pending' as const, token: randomUUID(), candidateIds: [],regions:assignment.packet.regions,coverageUnitIds:assignment.packet.coverageUnitIds,
    }))
  })
  job = await loadLlmDiscoveryJob(config, jobId)
  for(let batch=0;batch<job.investigators.length;batch+=slots) {
  await Promise.all(job.investigators.slice(batch,batch+slots).filter(w=>w.status!=='completed').map(worker => {
    const assignment = assignments.find(item => item.packet.id === worker.packetId)
    const prompt = focusedInvestigatorPrompt({ ...shared, jobId: job.id, workerId: worker.id, claimToken: worker.token, lens: assignment?.lens, packet: job.packets.find(packet => packet.id === worker.packetId) ?? job.packets[0] }, job.packets.find(packet => packet.id === worker.packetId) ?? job.packets[0])
    return runWorkerBatches(ctx, config, job, worker, prompt, signal)
  }))
  if(signal?.aborted)break
  }
  job = await loadLlmDiscoveryJob(config, jobId)
  const allComplete = (job.purpose==='coverage_repair'||(job.baseline.status === 'completed'&&(!job.architect||job.architect.status==='completed'))) && job.investigators.every(worker => worker.status === 'completed')
  const anyCancelled = cancelled(signal)
  await updateJob(config, jobId, current => { current.lifecycle = anyCancelled ? 'cancelled' : allComplete ? 'completed' : 'incomplete' })
  if(allComplete && job.purpose!=='coverage_repair' && !signal?.aborted) {
    try { if(!await (await import('../coverage-workflow.js')).closeCoverage(ctx,config,job.scanId,signal)) await updateJob(config,jobId,current=>{current.lifecycle='incomplete';current.notes.push('Coverage closure has retained unresolved work.')}) }
    catch(error) { await updateJob(config,jobId,current=>{current.lifecycle=signal?.aborted?'cancelled':'incomplete';current.notes.push(`Coverage closure failed: ${(error as Error).message}`)}) }
  }
  if (allComplete) await persistLlmDiscoveryArtifacts(config, jobId)
  return loadLlmDiscoveryJob(config, jobId)
}

/** Create a scan, freeze the LLM discovery worklist, and run the full standard-scan LLM discovery. */
export async function runLlmScan(ctx: Context, config: Config, target: string, options: { threatModel?: string; scopeRequested?: boolean; userContext?: string; signal?: AbortSignal } = {}): Promise<{ scan: ScanRecord; jobId: string }> {
  const { runScan } = await import('../scanner.js')
  const scan = await runScan(target, config, 'standard', options.threatModel ?? '', options.scopeRequested ?? false, config.stateDir, false)
  await persistInvestigationArtifacts(getStateDir(config.stateDir), scan)
  await saveScan(getStateDir(config.stateDir), scan)
  const job = await createLlmDiscoveryJob(config, scan.id, options.userContext ?? '')
  await runLlmDiscovery(ctx, config, job.id, options.signal)
  return { scan: await loadScan(getStateDir(config.stateDir), scan.id), jobId: job.id }
}

/** 单一协调者与中断续扫；不重置预算或已完成报告。 */
async function runLlmDiscoveryUnlocked(ctx: Context, config: Config, jobId: string, signal?: AbortSignal): Promise<LlmDiscoveryJob> {
 return withJobLease(getStateDir(config.stateDir),jobId,async()=>{
  const initial=await loadLlmDiscoveryJob(config,jobId)
  if(!['queued','cancelled','incomplete','running'].includes(initial.lifecycle))throw new Error('Discovery job is terminal; start an explicitly scoped follow-up instead.')
  if(initial.purpose!=='coverage_repair')await mutateScan(config,initial.scanId,scan=>{scan.discoveryStatus={driver:'llm',jobId,lifecycle:'running'}})
  try{return await runLlmDiscoveryInternal(ctx,config,jobId,signal)}finally{
    const job=await loadLlmDiscoveryJob(config,jobId)
    if(job.purpose!=='coverage_repair')await mutateScan(config,job.scanId,scan=>{scan.discoveryStatus={driver:'llm',jobId,lifecycle:job.lifecycle,reason:job.notes.at(-1)}})
  }
 })
}

/** Critic 缺口复用同一发现工具和 Findings，不另建扫描或伪造 Baseline 完成。 */
export async function createCoverageRepairJob(config:Config,scanId:string,unitIds:string[]):Promise<LlmDiscoveryJob>{
 const job=await createLlmDiscoveryJob(config,scanId),scan=await loadScan(getStateDir(config.stateDir),scanId)
 const units=(scan.coverage.ledger??[]).filter(u=>unitIds.includes(u.id)),size=config.discoveryBatchRegions??6
 const packets:LlmPacket[]=[]
 for(let start=0;start<units.length;start+=size){
  const assigned=units.slice(start,start+size),regions:ReviewRegion[]=[]
  for(const u of assigned)if(!regions.some(r=>r.path===u.path&&r.startLine===u.startLine&&r.endLine===u.endLine))regions.push({id:`review_${sha256(`${u.path}:${u.sha256}:${u.startLine}:${u.endLine}`).slice(0,24)}`,path:u.path,startLine:u.startLine,endLine:u.endLine,sha256:u.sha256})
  packets.push({id:`packet_${packets.length+1}`,attacker:'Derive the concrete caller from the source-backed critic gap.',protectedAsset:'The exact object or invariant in the assigned boundary.',expectedControls:assigned.map(u=>u.boundary),entryPoints:assigned.map(u=>`${u.path}:${u.startLine}`),sensitiveOperations:[],paths:[...new Set(assigned.map(u=>u.path))],regions,coverageUnitIds:assigned.map(u=>u.id),questions:assigned.map(u=>`${u.id}: ${u.reason}; inspect ${u.attackClass} and lifecycle ${u.lifecycle}. Preserve blockers with exact missing evidence.`)})
 }
 return updateJob(config,job.id,current=>{current.purpose='coverage_repair';current.coverageOnly=!!scan.followupOf;current.packets=packets})
}

export async function runLlmDiscovery(ctx:Context,config:Config,jobId:string,signal?:AbortSignal){
 const initial=await loadLlmDiscoveryJob(config,jobId)
 return withScanLease(getStateDir(config.stateDir),initial.scanId,()=>runLlmDiscoveryUnlocked(ctx,config,jobId,signal))
}

export function llmSourceReportsComplete(job:LlmDiscoveryJob):boolean{return job.baseline.status==='completed'&&(!job.architect||job.architect.status==='completed')&&job.investigators.every(w=>w.status==='completed')}
