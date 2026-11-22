import { randomUUID } from 'node:crypto'
import { relative } from 'node:path'
import type { Config } from './config.js'
import { runScan,resolveSafeTarget } from './scanner.js'
import { resolveSnapshotLocations } from './source-evidence.js'
import { getStateDir,loadScan,persistInvestigationArtifacts,saveScan } from './state.js'

/** 待验证发现可显式继续核实；保留原 seal，新建一个有准确范围的当前工作树复核记录。 */
export async function createCandidateFollowup(workspace:string,config:Config,scanId:string,candidateId:string,context=''){
 const state=getStateDir(config.stateDir),before=await loadScan(state,scanId),original=before.findings.find(f=>f.candidateId===candidateId)
 if(!original)throw new Error('Retained candidate not found.')
 if(before.mode==='diff'&&before.recipe.diffMode&&before.recipe.diffMode!=='working_tree')throw new Error('This follow-up verifies the current working tree; use the reviewed revision checkout explicitly for a historical Diff candidate.')
 resolveSafeTarget(workspace,relative(workspace,before.target))
 const scan=await runScan(before.target,config,'standard',`${before.threatModel}\n\nFocused follow-up of ${before.id}/${candidateId}. Reconstruct the original claim in the current snapshot; do not inherit confirmation. ${context}`,true,config.stateDir,false)
 scan.blockedCredentialContext=scan.findings.some(f=>f.cwe==='CWE-798'&&!['suppressed','not_applicable'].includes(f.disposition))
 const finding=structuredClone(original),paths=[...new Set(original.locations.map(l=>l.file))]
 const currentLocations=await resolveSnapshotLocations(scan,original.locations.map(l=>({file:l.file,line:l.line,role:l.role??'root_control'})))
 const changed=paths.some(path=>{const a=before.coverage.receipts.find(r=>r.path===path),b=scan.coverage.receipts.find(r=>r.path===path);return !a||!b||(a.sourceSha256??a.sha256)!==(b.sourceSha256??b.sha256)})
 finding.priorReceipts??=[];if(original.validationRecord||original.attackPathRecord)finding.priorReceipts.push({validationRecord:original.validationRecord,attackPathRecord:original.attackPathRecord,reason:'Historical finding receipt; this new working-tree follow-up requires independent validation.',at:new Date().toISOString()})
 finding.locations=currentLocations;finding.validationRecord=undefined;finding.attackPathRecord=undefined;finding.finalReview=undefined;finding.writeup=undefined;finding.duplicateOf=undefined
 finding.disposition='discovered';finding.lifecycleState='candidate';finding.evidenceLevel='source_backed';finding.status='open';finding.confidence='low';finding.revalidation=undefined;finding.closeReason=undefined;finding.triageDecisions=undefined
 finding.validation='Focused current-snapshot validation pending; historical receipts do not confirm this record.';finding.attackPath='Not established for this follow-up.';finding.evidence=[{kind:'context',detail:`Historical claim retained at ${before.id}/${candidateId}; re-open current frozen source before reaching a new conclusion.`}]
 finding.discoveryProofGaps=[...new Set([...(finding.discoveryProofGaps??[]),...(original.validationRecord?.proofGaps??[]),...(changed?['Relevant source changed since the prior finding; re-locate the actual control and complete path before confirming.']:[])])]
 finding.ledger=[{at:new Date().toISOString(),phase:'discovery',disposition:'discovered',summary:`Explicit focused follow-up of ${before.id}/${candidateId}; previous verdict is historical context only.`}]
 scan.findings=[finding];scan.tasks=[{id:`task_${randomUUID()}`,candidateId:finding.candidateId,phase:'validation',status:'pending',focus:'Independently revalidate the original candidate against this exact current snapshot; use the original trigger, strongest controls, inherited proof gaps and any retained local receipts.'}]
 scan.findingIdentityVersion=before.findingIdentityVersion??1
 scan.followupOf={kind:'candidate_validation',scanId:before.id,candidateId};scan.finalRecordReviewRequired=true
 scan.coverage.mode='scoped_path';scan.coverage.ledger=scan.coverage.ledger?.filter(u=>paths.includes(u.path));scan.coverage.deferred=scan.coverage.deferred.filter(d=>d.paths?.some(p=>paths.includes(p)));scan.coverage.inventoryComplete=true;scan.coverage.auditComplete=false;scan.coverage.complete=false
 await persistInvestigationArtifacts(state,scan);await saveScan(state,scan)
 return {scanId:scan.id,sourceScanId:before.id,candidateId:finding.candidateId,sourceChanged:changed,lifecycle:scan.lifecycle,next:{tool:'security_claim_audit_task',scan_id:scan.id,phase:'validation'},limitation:'Focused current-working-tree verification, not another repository audit. The original scan remains immutable; no runtime reproduction or confirmation is implied.'}
}
