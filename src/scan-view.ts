import type { ScanRecord } from './contracts.js'
import { redactSensitive } from './audit-context.js'
import type { AuditActor } from './audit-context.js'
import { confirmedFinding, evidenceState } from './evidence-policy.js'
import { sha256 } from './state.js'

/** 宿主可能从中间截断大工具文本；先构造有界 DTO，不能截断序列化后的 JSON。 */
export function scanView(scan:ScanRecord,actor?:AuditActor,candidateId?:string):Record<string,unknown>{
  const restricted=!!actor&&['validator','attack_path'].includes(actor.role)
  const visible=scan.findings.filter(f=>(!candidateId||f.candidateId===candidateId)&&(!restricted||scan.tasks.some(t=>t.candidateId===f.candidateId&&t.status==='claimed'&&t.claim?.owner===actor!.id)))
  const findings=visible.slice(0,candidateId?1:5).map(f=>({
    id:f.id,candidateId:f.candidateId,title:f.title.slice(0,200),ruleId:f.ruleId,cwe:f.cwe,severity:f.severity,confidence:f.confidence,status:f.status,disposition:f.disposition,...evidenceState(f),
    rootCause:f.rootCause.slice(0,2000),validation:f.validation.slice(0,800),counterevidence:f.counterevidence.slice(0,800),impact:f.impact.slice(0,800),remediation:f.remediation.slice(0,800),
    locations:f.locations.slice(0,20).map(l=>({...l,excerpt:l.excerpt.slice(0,240)})),locationsTruncated:f.locations.length>20,
    discoveryProofGaps:f.discoveryProofGaps?.slice(0,12).map(g=>g.slice(0,500)),
    evidence:f.evidence.slice(0,4).map(e=>({...e,detail:e.detail.slice(0,500)})),
    detailContext:{tool:'security_read_scan_context',kind:'candidate',candidate_id:f.candidateId},detailTruncated:true,
  }))
  const view:Record<string,unknown>={id:scan.id,scanId:scan.id,mode:scan.mode,lifecycle:scan.lifecycle,target:scan.target,targetSnapshot:scan.targetSnapshot,createdAt:scan.createdAt,completedAt:scan.completedAt,
    threatModel:redactSensitive(scan.threatModel).slice(0,3000),threatModelDigest:sha256(scan.threatModel),threatModelTruncated:scan.threatModel.length>3000,
    policyGuidance:redactSensitive(scan.policyGuidance).slice(0,1500),policyGuidanceTruncated:scan.policyGuidance.length>1500,totalFindings:scan.findings.length,
    counts:{confirmed:scan.findings.filter(confirmedFinding).length,pending:scan.findings.filter(f=>!confirmedFinding(f)&&!['suppressed','not_applicable'].includes(f.disposition)).length,rejected:scan.findings.filter(f=>['suppressed','not_applicable'].includes(f.disposition)).length},
    findings,findingsTruncated:visible.length>findings.length,
    coverage:{mode:scan.coverage.mode,complete:scan.coverage.complete,auditComplete:scan.coverage.auditComplete,inventoryComplete:scan.coverage.inventoryComplete,reviewedFiles:scan.coverage.reviewedFiles,skippedFiles:scan.coverage.skippedFiles,receiptCount:scan.coverage.receipts.length,totalUnits:scan.coverage.ledger?.length??0,ledgerRef:'artifacts/03_coverage/coverage-ledger.json',auditTrailRef:'artifacts/03_coverage/audit-trail.json'},
    modelExecutionCount:scan.modelExecutions?.length??0,modelExecutionsRef:'artifacts/03_coverage/model-executions.json',
    tasks:scan.tasks.filter(t=>!restricted||t.claim?.owner===actor!.id).slice(0,12).map(t=>({id:t.id,candidateId:t.candidateId,phase:t.phase,status:t.status})),
    followupOf:scan.followupOf,discoveryStatus:scan.discoveryStatus,artifacts:scan.artifacts,seal:scan.seal,
  }
  // 多候选摘要可以缩为单条；完整候选始终通过分页上下文读取。
  while(Buffer.byteLength(JSON.stringify(view))>32768&&findings.length>1){findings.pop();view.findingsTruncated=true}
  if(Buffer.byteLength(JSON.stringify(view))>32768){view.findings=findings.map(f=>({id:f.id,candidateId:f.candidateId,title:f.title,ruleId:f.ruleId,disposition:f.disposition,lifecycleState:f.lifecycleState,detailContext:f.detailContext,detailTruncated:true}));view.threatModel='';view.threatModelTruncated=true;view.policyGuidance='';view.policyGuidanceTruncated=true}
  return view
}
