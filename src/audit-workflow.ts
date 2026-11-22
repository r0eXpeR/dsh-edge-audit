import { withScanLease } from './scan-lease.js'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from './config.js'
import { getStateDir, loadScan } from './state.js'
import { createDeepClosureJob, runDeepClosure } from './deep-discovery.js'
import { mutateScan } from './scan-store.js'
import { loadDeepClosureJob } from './deep-discovery.js'
import { completeScan,prepareFinalRecordReview } from './workbench.js'
/** 三种模式共享同一验证队列和 Receipt 系统，不存在第二份 Findings。 */
async function closeAuditFindingsUnlocked(ctx:Context,config:Config,scanId:string,signal?:AbortSignal,finalize=true){
 if((await loadScan(getStateDir(config.stateDir),scanId)).lifecycle==='cancelled')return {scan:await loadScan(getStateDir(config.stateDir),scanId),complete:false}
 for(;;){
 for(const phase of ['validation','attack_path'] as const){
  const scan=await loadScan(getStateDir(config.stateDir),scanId)
  if(!scan.tasks.some(t=>t.phase===phase&&(t.status==='pending'||t.status==='claimed')))continue
  const key=phase==='validation'?'validationJobId':'attackPathJobId'
  let jobId=scan.auditWorkflow?.[key]
  // failed 的 closure 是终态，继续复用只会反复报错，需新建。
  if(jobId && ['completed','failed'].includes((await loadDeepClosureJob(config,jobId)).lifecycle))jobId=undefined
  if(!jobId){const job=await createDeepClosureJob(config,scanId,phase);jobId=job.id;await mutateScan(config,scanId,s=>{s.auditWorkflow??={};s.auditWorkflow[key]=job.id})}
  const closed=await runDeepClosure(ctx,config,jobId,signal)
  if(closed.lifecycle!=='completed')return {scan:await loadScan(getStateDir(config.stateDir),scanId),complete:false,closureJobId:jobId}
 }
 if(await prepareFinalRecordReview(config,scanId))continue
 break
 }
 if(!finalize)return {scan:await loadScan(getStateDir(config.stateDir),scanId),complete:true}
 const scan=await completeScan(config,scanId)
 return {scan,complete:scan.lifecycle==='completed'}
}

export async function closeAuditFindings(ctx:Context,config:Config,scanId:string,signal?:AbortSignal,finalize=true){return withScanLease(getStateDir(config.stateDir),scanId,()=>closeAuditFindingsUnlocked(ctx,config,scanId,signal,finalize))}
