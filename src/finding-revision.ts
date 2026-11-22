import { randomUUID } from 'node:crypto'
import type { Finding, ScanRecord } from './contracts.js'

/** 证据扩大后归档旧证明，撤销旧 claim；不能用旧版本的攻击路径关闭新范围。 */
export function invalidateFindingEvidence(scan:ScanRecord,finding:Finding,reason:string):void{
  if(finding.validationRecord||finding.attackPathRecord){
    finding.priorReceipts??=[]
    finding.priorReceipts.push({validationRecord:finding.validationRecord,attackPathRecord:finding.attackPathRecord,reason,at:new Date().toISOString()})
  }
  finding.finalReview=undefined;finding.validationRecord=undefined;finding.attackPathRecord=undefined
  finding.disposition='discovered';finding.lifecycleState='candidate';finding.evidenceLevel='source_backed'
  for(const task of scan.tasks.filter(t=>t.candidateId===finding.candidateId&&['pending','claimed'].includes(t.status))){task.status='cancelled';task.claim=undefined;task.receipt=`superseded: ${reason}`}
  scan.tasks.push({id:`task_${randomUUID()}`,candidateId:finding.candidateId,phase:'validation',status:'pending',focus:reason})
}
