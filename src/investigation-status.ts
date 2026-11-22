import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { modelPoolStatus } from './model-pool.js'
import type { Config } from './config.js'
import { getStateDir,loadScan } from './state.js'
import { loadDeepDiscoveryJob } from './deep-discovery.js'
import { loadLlmDiscoveryJob } from './llm/discovery.js'
import { loadDiffDiscoveryJob } from './llm/diff.js'
import { redactSensitive } from './audit-context.js'

/** 给主会话可操作诊断，不泄漏 worker claim token 或把执行超时误称为启动失败。 */
export async function investigationStatus(config:Config,scanId:string){
 const scan=await loadScan(getStateDir(config.stateDir),scanId),discovery=scan.discoveryStatus
 let subAudits:Array<{workerId:string;scanId?:string;jobId?:string;status:string;auditComplete?:boolean}>=[];let frozenWorkDone=false;let hardCapped=false,discoveryFailed=false,phase:string|undefined;let lifecycle=discovery?.lifecycle??scan.lifecycle,errors:string[]=[],resumeTool:string|undefined,jobId=scan.workflowRef?.jobId??discovery?.jobId
 if(discovery){
  if(discovery.driver==='deep'){
   const job=await loadDeepDiscoveryJob(config,discovery.jobId);lifecycle=job.lifecycle;hardCapped=job.lifecycle==='capped';discoveryFailed=job.lifecycle==='failed';frozenWorkDone=job.workers.length>0&&job.workers.every(w=>w.status==='completed')
   subAudits=job.workers.filter(w=>w.standardScanId).slice(-6).map(w=>({workerId:w.id,scanId:w.standardScanId,jobId:w.standardJobId,status:w.status,auditComplete:w.auditComplete}));errors=job.workers.filter(w=>w.status==='failed').slice(-6).map(w=>w.error??'Missing terminal worker report.')
   resumeTool=scan.workflowRef?'security_resume_deep_investigation':'security_resume_deep_discovery'
  }else if(discovery.driver==='llm'){
   const job=await loadLlmDiscoveryJob(config,discovery.jobId);lifecycle=job.lifecycle;frozenWorkDone=job.baseline.status==='completed'&&(!job.architect||job.architect.status==='completed')&&job.investigators.every(w=>w.status==='completed');errors=[job.baseline,...(job.architect?[job.architect]:[]),...job.investigators].filter(w=>w.status==='failed').slice(-6).map(w=>w.error??'Missing terminal worker report.');resumeTool='security_resume_standard_scan'
  }else{
   const job=await loadDiffDiscoveryJob(config,discovery.jobId);lifecycle=job.lifecycle;frozenWorkDone=job.workers.every(w=>w.status==='completed');errors=job.workers.filter(w=>w.status==='failed').slice(-6).map(w=>w.error??'Missing terminal worker report.');resumeTool='security_resume_diff_scan'
  }
 }
 // 发现阶段完成后仍可能有验证、攻击路径或封存任务；子任务终态不是整次审计终态。
 if(!scan.workflowRef && ['completed','saturated'].includes(lifecycle))lifecycle=scan.lifecycle
 if(scan.workflowRef){const flow=await (await import('./deep-workflow.js')).loadDeepInvestigationJob(config,scan.workflowRef.jobId);lifecycle=flow.lifecycle;phase=flow.phase}
 const details=[...new Set([...(discovery?.reason?[discovery.reason]:[]),...errors])].slice(0,4).map(message=>{
  const category=/timed out/i.test(message)?'timeout':/source.*changed|snapshot.*changed/i.test(message)?'source_changed':/budget|deadline|usage unavailable/i.test(message)?'budget':/terminal report|closure/i.test(message)?'missing_report':/native agent-creation/i.test(message)?'runtime_unavailable':'worker_error'
  return {category,message:redactSensitive(message).slice(0,700)}
 })
 let coordinatorActive=false
 for(const id of [scan.id,jobId,discovery?.jobId].filter((id):id is string=>!!id)){
  try{const lock=JSON.parse(await readFile(join(getStateDir(config.stateDir),'job-locks',`${id}.lock`),'utf8')) as {pid:number};if(Number.isInteger(lock.pid)&&lock.pid>0){try{process.kill(lock.pid,0);coordinatorActive=true}catch(error){if((error as NodeJS.ErrnoException).code!=='ESRCH')coordinatorActive=true}}}catch{}
 }
 const inventoryNeedsFollowup=frozenWorkDone&&(!scan.coverage.inventoryComplete||scan.coverage.deferred.length>0)&&!scan.tasks.some(t=>['pending','claimed'].includes(t.status))
 const executions=scan.modelExecutions??[],units=scan.coverage.ledger??[]
 const budgetUnreconciled=executions.some(row=>row.terminalReason==='pending'||(scan.auditBudget?.maxModelTokens!==undefined&&(!row.usage||row.usageComplete===false)))
 const terminal=hardCapped||discoveryFailed||['completed','saturated','capped','failed'].includes(lifecycle),resumable=!!resumeTool&&!terminal&&!coordinatorActive&&!budgetUnreconciled&&!inventoryNeedsFollowup&&!details.some(d=>d.category==='source_changed')
 return {scanId:scan.id,lifecycle,phase,scanLifecycle:scan.lifecycle,discovery:discovery?{...discovery,reason:discovery.reason?redactSensitive(discovery.reason).slice(0,700):undefined}:undefined,diagnostics:details,subAudits,
  profileModelPool:modelPoolStatus(),executionTrackingAvailable:scan.modelExecutions!==undefined,retainedModelExecutions:executions.length,retainedToolCalls:executions.reduce((n,e)=>n+e.toolCalls,0),unknownUsageExecutions:executions.filter(e=>!e.usage||e.usageComplete===false).length,observedSourceReads:(scan.auditTrail??[]).filter(e=>e.kind==='source_read').length,
  coverage:{total:units.length,reviewed:units.filter(u=>u.status==='reviewed').length,unresolved:units.filter(u=>!['reviewed','out_of_scope'].includes(u.status)).length,repair:scan.coverage.workflow},
  tasks:{pending:scan.tasks.filter(t=>t.status==='pending').length,claimed:scan.tasks.filter(t=>t.status==='claimed').length},deadlineAt:scan.auditDeadlineAt,
  coordinatorActive,inventoryNeedsFollowup,budgetUnreconciled,resumable,...(jobId?{retainedJobId:jobId}:{}),...(resumable?{resume:{tool:resumeTool,job_id:jobId}}:{}),nextAction:coordinatorActive?'The coordinator is active. Observe progress or cancel its owning call.':budgetUnreconciled?'An unfinished model usage receipt blocks budgeted resume. Retain this Partial record and start an explicit follow-up scan after reviewing the preserved evidence.':inventoryNeedsFollowup?'Retained bounded-source work is finished. Keep its established findings and choose an explicit follow-up scope for omitted or unsupported source.':resumable?'Resume the exact retained job; completed work and original budgets are preserved.':(hardCapped||lifecycle==='capped')?'The original budget is exhausted. Retain this Partial record; explicitly choose a follow-up scope/budget rather than pretending a fallback audit is equivalent.':details.some(d=>d.category==='source_changed')?'Create an explicitly scoped follow-up for the changed source; do not replace the frozen snapshot.':scan.lifecycle==='completed'?'Read the sealed report and retained evidence.':'Inspect the exact diagnostics and retained evidence before retrying.'}
}
