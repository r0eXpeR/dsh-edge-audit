import { getStateDir, loadScan } from './state.js'
import type { ScanRecord } from './contracts.js'

export class AuditBudgetExceeded extends Error {
  constructor(reason:string){super(`Audit budget exhausted: ${reason}`);this.name='AuditBudgetExceeded'}
}

function budgetSnapshot(scan:ScanRecord,configured?:number):{limit:number;measured:number;reason?:string}|undefined{
  const limit=Math.min(scan.auditBudget?.maxModelTokens??Infinity,configured??Infinity)
  if(!Number.isFinite(limit))return
  const rows=scan.modelExecutions??[]
  if(rows.some(row=>row.terminalReason==='pending'))return {limit,measured:0,reason:'A budgeted model invocation is in-flight or was interrupted before usage was retained; resume requires an explicit reconciliation of that Session.'}
  if(rows.some(row=>!row.usage||row.usageComplete===false))return {limit,measured:0,reason:'The host did not retain usage for an earlier model invocation; the configured budget cannot be guaranteed.'}
  const measured=rows.reduce((n,row)=>n+row.usage!.inputTokens+row.usage!.outputTokens+row.usage!.cacheReadTokens+row.usage!.cacheWriteTokens,0)
  return {limit,measured,...(measured>=limit?{reason:`Measured model usage ${measured} reached the retained limit ${limit}.`}:{})}
}

/** 供扫描状态原子更新使用：预算判断必须与待执行占位写入同一把锁内。 */
export function auditAdmissionReason(scan:ScanRecord,configured:number|undefined,discovery:boolean):string|undefined{
  const snapshot=budgetSnapshot(scan,configured)
  if(!snapshot||snapshot.reason)return snapshot?.reason
  if(discovery){
    const reserve=Math.max(1,Math.ceil(snapshot.limit*0.25))
    if(snapshot.measured>=snapshot.limit-reserve)return `Discovery paused at measured usage ${snapshot.measured}; ${reserve} of ${snapshot.limit} tokens are reserved for coverage critique and candidate closure. This is a soft reservation, not a guarantee for concurrent calls.`
  }
}

/** 在模型调用边界检查所有角色的实测 usage；并发在途调用仍可能超出软上限。 */
export async function auditBudgetReason(stateDir:string,scanId:string,configured?:number):Promise<string|undefined>{
  return auditAdmissionReason(await loadScan(getStateDir(stateDir),scanId),configured,false)
}

/** 新发现任务在边界处留出后续 Critic、验证与攻击路径的软预算；在途调用仍由总上限检查。 */
export async function auditDiscoveryReserveReason(stateDir:string,scanId:string,configured?:number):Promise<string|undefined>{
  return auditAdmissionReason(await loadScan(getStateDir(stateDir),scanId),configured,true)
}
