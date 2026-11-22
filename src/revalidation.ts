import { confirmedFinding } from './evidence-policy.js'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import type { ReceiptSourceReference } from './contracts.js'
import { currentAuditActor } from './audit-context.js'
import { getStateDir, loadScan, sha256 } from './state.js'
import { resolveSnapshotLocations } from './source-evidence.js'

export interface RepairReview {scanId:string;findingId:string;followupScanId:string;outcome:'fixed'|'still_vulnerable'|'inconclusive';originalTrigger:string;controlAnalysis:string;regressionEvidence:string;sourceReferences:ReceiptSourceReference[];proofGaps:string[]}
/** 复验是补充 Receipt，不改写已封存扫描，也不因没有规则命中或测试 exit 0 自动标记修复。 */
export async function recordRepairReview(config:Config,input:RepairReview){
  const state=getStateDir(config.stateDir),before=await loadScan(state,input.scanId),after=await loadScan(state,input.followupScanId)
  const finding=before.findings.find(f=>f.id===input.findingId);if(!finding)throw new Error('Finding not found.');if(!confirmedFinding(finding))throw new Error('Repair review requires an independently confirmed original finding.')
  if(before.id===after.id || before.targetSnapshot.targetId!==after.targetSnapshot.targetId || before.target!==after.target)throw new Error('Repair review requires a different scan of the same target.')
  const actor=currentAuditActor();if(!actor || ['discoverer','architect','reducer','coverage_critic'].includes(actor.role) || finding.discoveredBy?.includes(actor.id))throw new Error('Repair review requires an independent actual reviewer Session.')
  for(const value of [input.originalTrigger,input.controlAnalysis,input.regressionEvidence])if(value.trim().length<20)throw new Error('Repair review requires original trigger, control analysis and regression evidence.')
  if(input.outcome==='fixed' && (input.proofGaps.length || !after.coverage.inventoryComplete || after.coverage.deferred.length))throw new Error('Unresolved repair or inventory gaps require inconclusive.')
  await resolveSnapshotLocations(after,input.sourceReferences)
  const record={...input,id:`repair_${randomUUID()}`,reviewer:actor.id,beforeSeal:before.seal,afterSeal:after.seal,evidenceLevel:'independent_static_review',at:new Date().toISOString(),limitation:'A static repair review does not claim dynamic reproduction. Project checks and rule disappearance alone are insufficient.'}
  const directory=join(state,'repair-receipts');await mkdir(directory,{recursive:true})
  const path=join(directory,`${record.id}.json`),temp=`${path}.tmp`
  await writeFile(temp,JSON.stringify({...record,sha256:sha256(JSON.stringify(record))},null,2)+'\n',{mode:0o600});await rename(temp,path)
  return record
}
export async function readRepairReview(config:Config,id:string){
  if(!/^repair_[0-9a-f-]+$/.test(id))throw new Error('Invalid repair receipt id.')
  const value=JSON.parse(await readFile(join(getStateDir(config.stateDir),'repair-receipts',`${id}.json`),'utf8'))
  const {sha256:digest,...record}=value
  if(sha256(JSON.stringify(record))!==digest)throw new Error('Repair receipt failed integrity verification.')
  const [before,after]=await Promise.all([loadScan(getStateDir(config.stateDir),record.scanId),loadScan(getStateDir(config.stateDir),record.followupScanId)])
  if(before.seal!==record.beforeSeal || after.seal!==record.afterSeal)throw new Error('Repair review source scans changed; revalidate before using this lifecycle projection.')
  await resolveSnapshotLocations(after,record.sourceReferences)
  return {...record,lifecycleState:record.outcome==='fixed'?'reverified':record.outcome==='still_vulnerable'?'confirmed':'needs_validation'}
}
