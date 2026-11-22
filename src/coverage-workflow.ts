import { withScanLease } from './scan-lease.js'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from './config.js'
import { coverageDigest, coverageGaps, refreshCoverage } from './coverage.js'
import { runCoverageCritic } from './coverage-critic.js'
import { mutateScan } from './scan-store.js'
import { getStateDir, loadScan } from './state.js'

/** 持久化补漏循环。两个不同 Critic 接受同一账本后才能闭环。 */
async function closeCoverageUnlocked(ctx:Context,config:Config,scanId:string,signal?:AbortSignal):Promise<boolean>{
  await mutateScan(config,scanId,scan=>{scan.coverage.workflow??={waves:0,phase:'post_wave'}})
  for(;;){
    if(signal?.aborted)return false
    let scan=await loadScan(getStateDir(config.stateDir),scanId),workflow=scan.coverage.workflow!
    if(workflow.phase==='completed'){if(scan.coverage.auditComplete)return true;if(!coverageGaps(scan).length)return false;await mutateScan(config,scanId,s=>{s.coverage.workflow!.phase='post_wave'});continue}
    if(workflow.phase==='post_wave'||workflow.phase==='final_clean'){
      const stage=workflow.phase
      if(!await runCoverageCritic(ctx,config,scanId,signal,stage))return false
      scan=await loadScan(getStateDir(config.stateDir),scanId)
      const last=scan.coverage.critics?.at(-1)
      if(!last||last.reassignIds.length||last.missingUnits.length||coverageGaps(scan).length){
        await mutateScan(config,scanId,s=>{s.coverage.workflow!.phase='repair';s.coverage.workflow!.repairJobId=undefined})
      }else if(stage==='post_wave'){
        await mutateScan(config,scanId,s=>{s.coverage.workflow!.phase='final_clean'})
      }else{
        const prior=scan.coverage.critics?.slice(0,-1).reverse().find(c=>c.ledgerDigest===coverageDigest(scan)&&!c.reassignIds.length&&!c.missingUnits.length)
        if(!prior||prior.actorId===last.actorId)throw new Error('Final coverage acceptance requires a distinct fresh critic over the same ledger.')
        return mutateScan(config,scanId,s=>{s.coverage.workflow!.phase='completed';s.coverage.workflow!.reason=undefined;refreshCoverage(s);if(!s.coverage.auditComplete)s.coverage.workflow!.reason='Frozen source inventory or retained exclusions remain incomplete; a new explicit scope is required for those gaps.';return s.coverage.auditComplete===true})
      }
      continue
    }
    if(workflow.waves>=(config.maxCoverageWaves??6)){
      await mutateScan(config,scanId,s=>{s.coverage.workflow!.reason='Coverage repair wave budget exhausted; remaining units are unresolved, never clean.';s.coverage.auditComplete=false;s.coverage.complete=false})
      return false
    }
    const service=await import('./llm/discovery.js')
    if(!workflow.repairJobId){
      const job=await service.createCoverageRepairJob(config,scanId,coverageGaps(scan).map(u=>u.id))
      await mutateScan(config,scanId,s=>{s.coverage.workflow!.repairJobId=job.id})
      workflow={...workflow,repairJobId:job.id}
    }
    let job=await service.loadLlmDiscoveryJob(config,workflow.repairJobId!)
    if(job.lifecycle!=='completed')job=await service.runLlmDiscovery(ctx,config,job.id,signal)
    if(job.lifecycle!=='completed')return false
    await mutateScan(config,scanId,s=>{s.coverage.workflow!.waves++;s.coverage.workflow!.phase='post_wave';s.coverage.workflow!.repairJobId=undefined})
  }
}

export async function closeCoverage(ctx:Context,config:Config,scanId:string,signal?:AbortSignal){return withScanLease(getStateDir(config.stateDir),scanId,()=>closeCoverageUnlocked(ctx,config,scanId,signal))}
