import { requireExecutionArtifactReview } from './candidate-artifact.js'
import { sha256 } from './state.js'
import { buildValidationRubric, proofTupleFor } from './llm/validation.js'
import { COUNTEREVIDENCE_CHECKLIST } from './llm/attack-path.js'
import { readRepairReview } from './revalidation.js'
import { mechanicalPolicyPass } from './llm/attack-path.js'
import { currentAuditActor } from './audit-context.js'
import { mutateScan } from './scan-store.js'
import { actorReadLine, refreshCoverage } from './coverage.js'
import { resolveSnapshotLocations } from './source-evidence.js'
import type { AttackPathRecord, CandidateDisposition, EvidenceKind, Finding, Location, LocationRole, ReceiptSourceReference, ScanRecord, ValidationRecord } from './contracts.js'
import { finalizeAndSaveScan, readFindingAnnotation, saveTriageAnnotation, readArtifact, getStateDir, loadScan, persistInvestigationArtifacts } from './state.js'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'

/** 覆盖、发现和验证共用同一串行写入口，避免并发覆盖彼此的状态。 */
async function updateScan<T>(config: Config, scanId: string, update: (scan: ScanRecord) => Promise<T> | T): Promise<T> {
  return mutateScan(config,scanId,async scan=>{const completed=scan.lifecycle==='completed';const result=await update(scan);if(completed)return result;await persistInvestigationArtifacts(getStateDir(config.stateDir),scan);return result})
}

export interface ValidationInput {
  validationPlan?:{local?:string;deployment?:string}
  resolvedProofGaps?:Array<{gap:string;resolution:string;sourceReferences:ReceiptSourceReference[]}>
  runtimeObservation?:import('./contracts.js').RuntimeObservation
  conclusion: CandidateDisposition
  method: 'static' | 'test' | 'runtime' | 'hybrid'
  attacker: string
  entryPoint: string
  trustBoundary: string
  rootControl: string
  sink: string
  impact: string
  directEvidence: string
  counterevidence: string
  limitations: string
  confidence: 'high' | 'medium' | 'low'
  sourceReferences: ReceiptSourceReference[]
  runtimeReceiptRefs?: string[]
  proofGaps?: string[]
}

export interface AttackPathInput {
  policyFacts: Parameters<typeof mechanicalPolicyPass>[0]
  attacker: string
  entryPoint: string
  preconditions: string
  dataflow: string
  outcome: string
  severityRationale: string
  changeConditions: string
  sourceReferences: ReceiptSourceReference[]
}

/** 复述发现者的摘录不算独立验证；只对真实 Session 生效，直接调用没有可观察的读取记录。 */
function requireObservedCitations(scan: ScanRecord, locations: Location[]): void {
  const actor=currentAuditActor();if(!actor)return
  const unread=locations.filter(location=>!actorReadLine(scan,actor.id,location.file,location.line))
  if(unread.length)throw new Error(`Independent review must read every cited source line first: ${unread.map(l=>`${l.file}:${l.line}`).join(', ')}.`)
}

function requireReportable(value: CandidateDisposition): asserts value is 'reportable' { if (value !== 'reportable') throw new Error('Attack-path analysis is only allowed for a reportable validated candidate.') }
function candidate(scan: ScanRecord, candidateId: string): Finding { const value = scan.findings.find(item => item.candidateId === candidateId); if (!value) throw new Error('Candidate was not found in this scan.'); return value }
function required(value: string, label: string): string { const text = value.trim(); if (!text) throw new Error(`${label} is required.`); return text }

function locationRole(location: Location): LocationRole { return location.role ?? 'root_control' }

/** Resolve receipt citations only against the scan's frozen, finding-local source locations. */
function resolveSourceReferences(finding: Finding, references: ReceiptSourceReference[]): Location[] {
  if (!Array.isArray(references) || references.length === 0) throw new Error('At least one source reference is required.')
  const seen = new Set<string>(); const resolved: Location[] = []
  for (const reference of references) {
    if (!reference || typeof reference.file !== 'string' || !reference.file.trim() || !Number.isInteger(reference.line) || reference.line < 1 || !['entrypoint', 'wrapper', 'propagation', 'root_control', 'sink', 'outcome', 'expected_control'].includes(reference.role)) throw new Error('Each source reference requires a snapshot file, positive line, and recognized role.')
    const key = `${reference.file}:${reference.line}:${reference.role}`
    if (seen.has(key)) throw new Error(`Duplicate source reference: ${key}.`)
    const location = finding.locations.find(item => item.file === reference.file && item.line === reference.line && locationRole(item) === reference.role)
    if (!location) throw new Error(`Source reference is not a retained location in this finding snapshot: ${key}.`)
    seen.add(key); resolved.push(location)
  }
  return resolved
}

function requireReportableValidationReferences(references: Location[]): void {
  if (!references.some(reference => locationRole(reference) === 'root_control' || locationRole(reference) === 'sink')) throw new Error('A reportable validation requires a cited root_control or sink source reference.')
}

function requireAttackPathEndpointReferences(finding: Finding, references: Location[]): void {
  const roles = new Set(finding.locations.map(locationRole))
  if (roles.has('entrypoint') && roles.has('sink')) {
    const cited = new Set(references.map(locationRole))
    if (!cited.has('entrypoint') || !cited.has('sink')) throw new Error('An attack path with retained entrypoint and sink locations must cite both endpoint roles.')
  }
}

function resolveRuntimeReceiptRefs(finding: Finding, method: ValidationInput['method'], references: string[] | undefined): string[] | undefined {
  const values = [...new Set((references ?? []).map(value => value.trim()))]
  if (values.some(value => !value || value.length > 1_000)) throw new Error('Each runtime receipt reference must be a bounded artifact path.')
  if (method !== 'runtime' && method !== 'hybrid') {
    if (values.length) throw new Error('Runtime receipt references are only valid for runtime or hybrid validation.')
    return undefined
  }
  if (!values.length) throw new Error('Runtime or hybrid validation requires at least one candidate-bound runtime receipt reference.')
  const available = new Set(finding.evidence.filter(item => item.kind === 'runtime' && item.artifactRef).map(item => item.artifactRef!))
  if (values.some(value => !available.has(value))) throw new Error('Runtime receipt reference is not retained runtime evidence for this candidate.')
  return values.sort()
}

function releaseExpiredClaims(scan: ScanRecord): number { const now = Date.now(); let released = 0; for (const task of scan.tasks) if (task.status === 'claimed' && task.claim && Date.parse(task.claim.expiresAt) <= now) { task.status = 'pending'; task.claim = undefined; released++ } return released }

export async function claimAuditTask(config: Config, scanId: string, owner: string, phase?: 'validation' | 'attack_path', leaseMs = 30 * 60_000): Promise<{ taskId: string; candidateId: string; phase: 'validation' | 'attack_path'; focus: string; claimToken: string; artifactRef: string;guidance?:Record<string,import('@deepseek-ai/dsh-util-values').JsonValue> } | null> {
  if((await loadScan(getStateDir(config.stateDir),scanId)).lifecycle==='completed')return null
  return updateScan(config, scanId, scan => {
    if(scan.lifecycle==='completed')return null
    releaseExpiredClaims(scan)
    const actor=currentAuditActor()
    const ownerId=actor?.id ?? required(owner,'owner')
    if(actor && ['discoverer','architect','reducer','coverage_critic'].includes(actor.role))throw new Error('Discovery roles cannot claim validation or attack-path tasks.')
    if(actor?.scanId && actor.scanId!==scan.id)throw new Error('Reviewer Session is bound to another scan.')
    const task = scan.tasks.find(item => {
      const finding = scan.findings.find(f => f.candidateId === item.candidateId)
      return item.status === 'pending'
        && !scan.tasks.some(t => t.id !== item.id && t.candidateId === item.candidateId && t.phase === item.phase && t.status === 'claimed')
        && (phase === undefined || item.phase === phase)
        && !finding?.discoveredBy?.includes(ownerId)
        && !((item.phase === 'attack_path' || item.reviewType === 'final_record') && finding?.validationRecord?.reviewer === ownerId)
    })
    if (!task) return null
    const claimToken = randomUUID(); const claimedAt = new Date(); task.status = 'claimed'; task.claim = { owner: ownerId, token: claimToken, claimedAt: claimedAt.toISOString(), expiresAt: new Date(claimedAt.getTime() + Math.max(60_000, Math.min(leaseMs, 4 * 60 * 60_000))).toISOString() }
    const finding=scan.findings.find(f=>f.candidateId===task.candidateId);if(finding)finding.lifecycleState=task.phase==='validation'?'validating':'investigating'
    return { taskId: task.id, candidateId: task.candidateId, phase: task.phase, focus: task.focus, claimToken, artifactRef: `artifacts/04_reconciliation/tasks/${task.id}.md`,guidance:finding?JSON.parse(JSON.stringify({proofTuple:proofTupleFor(finding.ruleId,finding.cwe),rubric:buildValidationRubric({ruleId:finding.ruleId,cwe:finding.cwe,sourceLocations:finding.locations.length}),counterevidence:COUNTEREVIDENCE_CHECKLIST})):undefined }
  })
}

export async function cancelInvestigation(config: Config, scanId: string, reason: string): Promise<ScanRecord> {
  const message = required(reason, 'reason')
  return mutateScan(config, scanId, async scan => {
    if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable.')
    for (const task of scan.tasks) if (task.status === 'pending' || task.status === 'claimed') { task.status = 'cancelled'; task.receipt = `cancelled: ${message}` }
    scan.lifecycle = 'cancelled'; scan.activity.push({ at: new Date().toISOString(), phase: 'reporting', message: `Investigation cancelled: ${message}` }); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); return scan
  })
}

export async function resumeInvestigation(config: Config, scanId: string): Promise<ScanRecord> {
  return mutateScan(config, scanId, async scan => {
    if (scan.lifecycle !== 'cancelled') throw new Error('Only cancelled investigations can be resumed.')
    for (const task of scan.tasks) if (task.status === 'cancelled' && task.receipt?.startsWith('cancelled: ')) { task.status = 'pending'; task.receipt = undefined; task.claim = undefined }
    scan.lifecycle = 'validation'; scan.activity.push({ at: new Date().toISOString(), phase: 'validation', message: 'Investigation resumed; unfinished tasks were returned to the pending queue.' }); await persistInvestigationArtifacts(getStateDir(config.stateDir), scan); return scan
  })
}

function requireTaskClaim(scan: ScanRecord, candidateId: string, phase: 'validation' | 'attack_path', token?: string): void {
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === phase && item.status==='claimed' && item.claim?.token===token) ?? scan.tasks.find(item=>item.candidateId===candidateId&&item.phase===phase&&item.status==='claimed')
  if (!task || task.status !== 'claimed' || !task.claim) throw new Error(`A ${phase} receipt requires an active claimed audit task.`)
  if (!token || task.claim.token !== token) throw new Error('Task claim token does not own this audit task.')
  if(Date.parse(task.claim.expiresAt)<=Date.now())throw new Error('Task claim lease has expired; reclaim the task before recording evidence.')
  const actor=currentAuditActor()
  if(actor && task.claim.owner!==actor.id)throw new Error('Task claim belongs to another actual reviewer Session.')
  if(scan.findings.find(f=>f.candidateId===candidateId)?.discoveredBy?.includes(task.claim.owner))throw new Error('The discoverer cannot independently validate its own candidate.')
  if(phase==='attack_path' && scan.findings.find(f=>f.candidateId===candidateId)?.validationRecord?.reviewer===task.claim.owner)throw new Error('Attack-path review requires an independent reviewer distinct from the validator.')
}

function completeTask(scan: ScanRecord, candidateId: string, phase: 'validation' | 'attack_path', token?: string): void {
  requireTaskClaim(scan, candidateId, phase, token)
  const task = scan.tasks.find(item => item.candidateId === candidateId && item.phase === phase && item.status === 'claimed' && item.claim?.token===token)!
  task.status = 'completed'; task.completedAt = new Date().toISOString(); task.receipt = phase
}

export async function pendingCandidates(config: Config, scanId: string): Promise<Array<{ candidateId: string; title: string; disposition: CandidateDisposition; stages: string[] }>> {
  const scan = await loadScan(getStateDir(config.stateDir), scanId)
  return scan.findings.filter(finding => !finding.validationRecord).map(finding => ({ candidateId: finding.candidateId, title: finding.title, disposition: finding.disposition, stages: finding.ledger.map(row => row.phase) }))
}

export async function recordValidation(config: Config, scanId: string, candidateId: string, input: ValidationInput, claimToken?: string): Promise<ScanRecord> {
  return updateScan(config, scanId, async scan => {
    if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new validation evidence.')
    const finding = candidate(scan, candidateId)
    requireTaskClaim(scan, candidateId, 'validation', claimToken)
    const claimed=scan.tasks.find(t=>t.candidateId===candidateId&&t.phase==='validation'&&t.status==='claimed'&&t.claim?.token===claimToken)!
    const prior=finding.validationRecord
    if(claimed.reviewType==='final_record'&&input.conclusion==='deferred'&&!Object.values(input.validationPlan??{}).some(v=>v.trim().length>=20))throw new Error('Final Needs Validation review requires an exact local or owner-observed deployment validation plan.')

    for (const [label, value] of Object.entries(input)) if (!['sourceReferences','proofGaps','runtimeReceiptRefs','runtimeObservation','resolvedProofGaps','validationPlan'].includes(label)) required(String(value), label)
    if (!['reportable', 'suppressed', 'deferred', 'not_applicable'].includes(input.conclusion)) throw new Error('Validation conclusion is invalid.')
    if(claimed.reviewType==='final_record'&&input.conclusion==='deferred')for(const gap of prior?.proofGaps??[]){if(!input.proofGaps?.includes(gap)&&!input.resolvedProofGaps?.some(r=>r.gap===gap&&r.resolution.trim().length>=40))throw new Error('Final review cannot silently drop an unresolved earlier proof gap.')}
    const citedLocations = resolveSourceReferences(finding, input.sourceReferences)
    if (input.conclusion === 'reportable') {
      for(const gap of [...(finding.discoveryProofGaps??[]),...(claimed.reviewType==='final_record'&&prior?.conclusion==='deferred'?(prior.proofGaps?.length?prior.proofGaps:[prior.limitations]):[])]){const resolution=input.resolvedProofGaps?.find(r=>r.gap===gap);if(!resolution||resolution.resolution.trim().length<40||!resolution.sourceReferences.length)throw new Error('An inherited independent-audit proof gap requires explicit source-backed resolution or deferred status.');resolveSourceReferences(finding,resolution.sourceReferences);await resolveSnapshotLocations(scan,resolution.sourceReferences)}
      requireReportableValidationReferences(citedLocations)
      if(!['CWE-295','CWE-347','CWE-798','CWE-330','CWE-942','CWE-611'].includes(finding.cwe) && (!citedLocations.some(l=>l.role==='entrypoint') || !citedLocations.some(l=>l.role==='sink')))throw new Error('Flow or authorization confirmation requires exact entrypoint and sink evidence. Attach independently verified locations or defer.')
      if(input.proofGaps?.length)throw new Error('Unresolved decisive proof gaps require deferred / needs_validation, not confirmation.')
    }
    const frozen=await resolveSnapshotLocations(scan,input.sourceReferences)
    for(const ref of frozen)if(!citedLocations.some(l=>l.file===ref.file&&l.line===ref.line&&l.excerpt===ref.excerpt))throw new Error('Receipt excerpt differs from frozen source.')
    const runtimeReceiptRefs = resolveRuntimeReceiptRefs(finding, input.method, input.runtimeReceiptRefs)
    if(input.conclusion==='reportable' && (input.method==='runtime'||input.method==='hybrid')){
      const observation=input.runtimeObservation
      if(!observation || !runtimeReceiptRefs?.includes(observation.receiptRef) || observation.expectedInvariant.trim().length<20 || observation.observedResult.trim().length<20 || observation.outputExcerpt.trim().length<8)throw new Error('Runtime confirmation requires an exact candidate receipt, security invariant, observed boundary failure and retained output excerpt; command success alone is insufficient.')
      const receipt=JSON.parse(await readArtifact(scan,observation.receiptRef)) as {snapshotDigest:string;stdout:string;stderr:string;timedOut:boolean;method?:string}
      if(receipt.snapshotDigest!==scan.targetSnapshot.snapshotDigest || receipt.timedOut || !`${receipt.stdout}\n${receipt.stderr}`.includes(observation.outputExcerpt))throw new Error('Runtime observation is not supported by the retained snapshot-bound command output.')
    }
    if(input.conclusion==='reportable' && input.method==='test' && !finding.evidence.some(e=>e.kind==='test'&&e.artifactRef))throw new Error('Test validation requires a retained candidate-bound test receipt.')

    const reviewer=scan.tasks.find(t=>t.candidateId===candidateId&&t.phase==='validation'&&t.status==='claimed'&&t.claim?.token===claimToken)!.claim!.owner
    // 排除、延后和补齐证明缺口同样是安全判断，不能靠复述发现者的摘录关闭任务。
    requireObservedCitations(scan,citedLocations)
    for(const resolution of input.resolvedProofGaps??[]){
      const locations=resolveSourceReferences(finding,resolution.sourceReferences)
      await resolveSnapshotLocations(scan,resolution.sourceReferences)
      requireObservedCitations(scan,locations)
    }
    const record: ValidationRecord = { ...input, reviewer, independent: true, snapshotDigest:scan.targetSnapshot.snapshotDigest, proofGaps:input.proofGaps ?? [], ...(runtimeReceiptRefs ? { runtimeReceiptRefs } : {}), conclusion: input.conclusion as ValidationRecord['conclusion'], recordedAt: new Date().toISOString() }
    const evidenceKind: EvidenceKind = input.method === 'runtime' ? 'runtime' : input.method === 'test' ? 'test' : 'validation'
    finding.lifecycleState=input.conclusion==='reportable'?'validating':input.conclusion==='deferred'?'needs_validation':'rejected'
    finding.evidenceLevel=input.conclusion==='reportable'?(input.method==='runtime'||input.method==='hybrid'?'runtime_validated':'statically_validated'):input.conclusion==='deferred'?'needs_validation':'rejected'
    if(claimed.reviewType==='final_record'){finding.priorReceipts??=[];if(prior)finding.priorReceipts.push({validationRecord:prior,reason:'Fresh independent final-record review.',at:new Date().toISOString()});finding.finalReview={reviewer,decision:prior?.conclusion===input.conclusion?'verified':'replaced',validationDigest:sha256(JSON.stringify(record)),at:new Date().toISOString()}}
    finding.validationRecord = record; finding.disposition = input.conclusion; finding.confidence = input.confidence; finding.validation = `${input.method} validation: ${input.directEvidence}`; finding.impact = input.impact; finding.counterevidence = input.counterevidence; finding.evidence.push(...citedLocations.map((location, index) => ({ kind: evidenceKind, detail: `${input.directEvidence} [receipt citation ${index + 1}/${citedLocations.length}]`, location }))); finding.ledger.push({ at: new Date().toISOString(), phase: 'validation', disposition: input.conclusion, summary: finding.validation })
    completeTask(scan, candidateId, 'validation', claimToken)
    if (input.conclusion === 'reportable') scan.tasks.push({ id: `task_${randomUUID()}`, candidateId, phase: 'attack_path', focus: `Trace the attacker-to-outcome path for ${finding.title} and calibrate severity from evidence.`, status: 'pending' })
    scan.lifecycle = input.conclusion === 'reportable' ? 'attack_path' : 'validation'
    return scan
  })
}

export async function recordAttackPath(config: Config, scanId: string, candidateId: string, input: AttackPathInput, claimToken?: string): Promise<ScanRecord> {
  return updateScan(config, scanId, async scan => {
    if (scan.lifecycle === 'completed') throw new Error('Completed scans are immutable. Create a follow-up scan for new attack-path evidence.')
    const finding = candidate(scan, candidateId); requireReportable(finding.disposition)
    requireTaskClaim(scan, candidateId, 'attack_path', claimToken)
    for (const [label, value] of Object.entries(input)) if (!['sourceReferences','policyFacts'].includes(label)) required(value as string, label)
    const citedLocations = resolveSourceReferences(finding, input.sourceReferences); requireAttackPathEndpointReferences(finding, citedLocations)
    await resolveSnapshotLocations(scan,input.sourceReferences)
    const reviewer=scan.tasks.find(t=>t.candidateId===candidateId&&t.phase==='attack_path'&&t.status==='claimed'&&t.claim?.token===claimToken)!.claim!.owner
    if(!input.policyFacts)throw new Error('Attack-path confirmation requires structured policy facts; missing facts cannot bypass mechanical reportability.')
    await requireExecutionArtifactReview(scan,finding,reviewer)
    requireObservedCitations(scan,citedLocations)
    const policy=mechanicalPolicyPass(input.policyFacts)
    if(policy?.severity && policy.severity!=='ignore')finding.severity=policy.severity
    const record: AttackPathRecord = { ...input, policyDecision:policy, reviewer,snapshotDigest:scan.targetSnapshot.snapshotDigest, recordedAt: new Date().toISOString() }; finding.lifecycleState='confirmed';finding.attackPathRecord = record; finding.attackPath = `${input.dataflow}\n\nAttacker: ${input.attacker}\nOutcome: ${input.outcome}`; finding.ledger.push({ at: new Date().toISOString(), phase: 'attack_path', disposition: 'reportable', summary: input.dataflow }); finding.evidence.push(...citedLocations.map((location, index) => ({ kind: 'attack_path' as const, detail: `${input.dataflow} [receipt citation ${index + 1}/${citedLocations.length}]`, location }))); completeTask(scan, candidateId, 'attack_path', claimToken);
    if(policy?.decision==='ignore'){finding.disposition='not_applicable';finding.lifecycleState='rejected';finding.evidenceLevel='rejected';finding.counterevidence=policy.rationale}
    if(policy.decision==='deferred'){finding.disposition='deferred';finding.lifecycleState='needs_validation';finding.evidenceLevel='needs_validation'}
    scan.lifecycle = 'reporting'
    return scan
  })
}

export async function completeScan(config: Config, scanId: string): Promise<ScanRecord> {
  const state = getStateDir(config.stateDir)
  return mutateScan(config, scanId, async scan => {
  // 已取消的调查必须由 resume 恢复，不能被任何协调链改写成 incomplete。
  if (scan.lifecycle === 'completed' || scan.lifecycle === 'cancelled') return scan
  const missing = scan.findings.filter(finding => !finding.validationRecord || (finding.disposition === 'reportable' && !finding.attackPathRecord))
  if (missing.length) throw new Error(`Cannot finalize while candidate receipts are incomplete: ${missing.map(item => item.candidateId).join(', ')}`)
  const activeTasks = scan.tasks.filter(task => task.status === 'pending' || task.status === 'claimed'); if (activeTasks.length) throw new Error(`Cannot finalize while audit tasks remain: ${activeTasks.map(task => task.id).join(', ')}`)
  refreshCoverage(scan)
  const finalRecordsClosed=!scan.finalRecordReviewRequired||scan.findings.filter(f=>f.disposition==='deferred').every(f=>f.validationRecord&&f.finalReview?.validationDigest===sha256(JSON.stringify(f.validationRecord)))
  const discoveryClosed=!scan.discoveryStatus || (scan.discoveryStatus.driver==='deep'?scan.discoveryStatus.lifecycle==='saturated':scan.discoveryStatus.lifecycle==='completed')
  scan.lifecycle = scan.coverage.complete && discoveryClosed && finalRecordsClosed ? 'completed' : 'incomplete'; scan.completedAt = new Date().toISOString(); scan.activity.push({ at: scan.completedAt, phase: 'reporting', message: 'Canonical scan bundle finalized after all candidate ledgers closed.' }); await finalizeAndSaveScan(state, scan); return scan
  })
}

/** codex-security finding_triage close reasons. */
export type TriageCloseReason = 'already_fixed' | 'wont_fix' | 'false_positive'

/**
 * Record one append-only triage decision (codex-security finding_decisions +
 * finding_triage semantics): the (status, closeReason, note) triple is
 * appended to the finding's audit log only when it changes, then the current
 * triage state is updated. closed requires a close reason; open requires none.
 */
export async function recordTriageDecision(config: Config, scanId: string, findingId: string, input: { status: 'open' | 'closed'; closeReason?: TriageCloseReason; note?: string;revalidationReceiptId?:string }): Promise<{ updated: boolean; findingId: string; decisions: number }> {
  const decide=async(scan:ScanRecord)=>{
    const finding = scan.findings.find(item => item.id === findingId)
    if (!finding) throw new Error('Finding was not found in this scan.')
    if (input.status === 'closed' && !input.closeReason) throw new Error('A closed triage decision requires a close reason: already_fixed, wont_fix, or false_positive.')
    if (input.status === 'open' && input.closeReason) throw new Error('An open triage decision cannot carry a close reason.')
    if (input.closeReason === 'false_positive' && finding.validationRecord?.conclusion !== 'suppressed' && finding.validationRecord?.conclusion !== 'not_applicable') throw new Error('A false-positive close requires a suppressed or not_applicable validation receipt.')
    if(input.closeReason==='already_fixed'){if(!input.revalidationReceiptId)throw new Error('An already_fixed close requires an independent fixed revalidation receipt.');const repair=await readRepairReview(config,input.revalidationReceiptId);if(repair.scanId!==scan.id||repair.findingId!==finding.id||repair.outcome!=='fixed')throw new Error('Revalidation receipt does not establish this finding fixed.')}
    const current = { status: input.status, closeReason: input.closeReason, note: input.note?.trim() || undefined }
    const decisions = finding.triageDecisions ?? []
    const last = decisions.at(-1)
    const changed = !last || last.status !== current.status || (last.closeReason ?? undefined) !== current.closeReason || (last.note ?? undefined) !== current.note
    if (!changed) return { updated: false, findingId, decisions: decisions.length }
    decisions.push({ ...current, at: new Date().toISOString() })
    finding.triageDecisions = decisions
    finding.status = current.status === 'closed' ? (current.closeReason === 'false_positive' ? 'false_positive' : current.closeReason === 'already_fixed' ? 'resolved' : 'resolved') : 'open'
    finding.closeReason = current.closeReason
    return { updated: true, findingId, decisions: decisions.length }
  }
  const state=getStateDir(config.stateDir),current=await loadScan(state,scanId)
  if(current.lifecycle!=='completed'&&input.closeReason!=='already_fixed')return updateScan(config,scanId,decide)
  return mutateScan(config,scanId,async original=>{
    const copy=structuredClone(original),finding=copy.findings.find(f=>f.id===findingId)
    if(!finding)throw new Error('Finding was not found in this scan.')
    const annotation=await readFindingAnnotation(state,scanId,findingId)
    if(annotation?.status)finding.status=annotation.status
    if(annotation){finding.closeReason=annotation.closeReason;finding.triageDecisions=annotation.triageDecisions}
    const result=await decide(copy)
    if(result.updated)await saveTriageAnnotation(state,original,finding,true)
    return result
  })
}

/** 验证者可补充跨文件端点和中间控制；每一引用都重新绑定当前冻结字节。 */
export async function attachEvidenceLocations(config: Config,scanId:string,candidateId:string,claimToken:string,references:ReceiptSourceReference[]):Promise<ScanRecord>{
  return updateScan(config,scanId,async scan=>{
    if(scan.lifecycle==='completed')throw new Error('Completed scans are immutable.')
    const finding=candidate(scan,candidateId)
    const task=scan.tasks.find(t=>t.candidateId===candidateId&&t.status==='claimed'&&t.claim?.token===claimToken)
    if(!task)throw new Error('A claimed candidate task is required to attach evidence.')
    requireTaskClaim(scan,candidateId,task.phase,claimToken)
    const locations=await resolveSnapshotLocations(scan,references)
    for(const location of locations)if(!finding.locations.some(l=>l.file===location.file&&l.line===location.line&&l.role===location.role))finding.locations.push(location)
    return scan
  })
}

export async function prepareFinalRecordReview(config:Config,scanId:string):Promise<number>{
 return updateScan(config,scanId,scan=>{
  if(!scan.finalRecordReviewRequired||scan.lifecycle==='cancelled'||scan.lifecycle==='completed')return 0
  let created=0
  for(const finding of scan.findings.filter(f=>f.disposition==='deferred'&&f.validationRecord).sort((a,b)=>a.fingerprint.localeCompare(b.fingerprint))){
   if(finding.finalReview?.validationDigest===sha256(JSON.stringify(finding.validationRecord)))continue
   if(scan.tasks.some(t=>t.candidateId===finding.candidateId&&t.reviewType==='final_record'&&['pending','claimed'].includes(t.status)))continue
   scan.tasks.push({id:`task_${randomUUID()}`,candidateId:finding.candidateId,phase:'validation',reviewType:'final_record',status:'pending',focus:'Fresh final-record review of Needs Validation: refute the premise, check every decisive blocker against current source, and provide an exact validation_plan.local or owner-observed validation_plan.deployment. You must not be the earlier validator. A promotion requires source-backed gap resolution and a fresh attack-path review.'});created++
  }
  return created
 })
}
