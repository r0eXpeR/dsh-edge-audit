import { auditBudgetReason, auditDiscoveryReserveReason } from './audit-budget.js'
import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from './config.js'
import type { DeepDiscoveryJob, DeepWorker, DeepCandidate } from './deep-discovery.js'
import { addCandidate, deepDiscoveryCapability, loadDeepDiscoveryJob, runDeepReducer, updateDeepJob } from './deep-discovery.js'
import { createLlmDiscoveryJob, loadLlmDiscoveryJob, runLlmDiscovery,llmSourceReportsComplete } from './llm/discovery.js'
import { runScan } from './scanner.js'
import { closeAuditFindings } from './audit-workflow.js'
import { closeCoverage } from './coverage-workflow.js'
import { coverageGaps } from './coverage.js'
import { confirmedFinding } from './evidence-policy.js'
import { mutateScan } from './scan-store.js'
import { getStateDir, loadScan, persistInvestigationArtifacts, saveScan, sha256, verifyScanBundle, writeArtifact } from './state.js'

/** 一名 Deep Worker 是一轮独立 Standard 审计，发现、验证、攻击路径均可独立恢复。 */
async function independentAudit(ctx:Context,config:Config,jobId:string,workerId:string,signal:AbortSignal):Promise<void>{
  let job=await loadDeepDiscoveryJob(config,jobId),worker=job.workers.find(w=>w.id===workerId)!
  if(worker.status==='completed')return
  await updateDeepJob(config,jobId,j=>{const w=j.workers.find(w=>w.id===workerId)!;w.status='running';w.error=undefined})
  try{
    if(!worker.standardScanId){
      const scan=await runScan(job.target,config,'standard',job.initialThreatModel??'',true,config.stateDir,false)
      scan.parentScanId=job.scanId
      const parent=await loadScan(getStateDir(config.stateDir),job.scanId)
      if(scan.targetSnapshot.snapshotDigest!==parent.targetSnapshot.snapshotDigest)throw new Error('Source changed before independent audit; preserve the scan and create an explicit follow-up.')
      await persistInvestigationArtifacts(getStateDir(config.stateDir),scan);await saveScan(getStateDir(config.stateDir),scan)
      await updateDeepJob(config,jobId,j=>{j.workers.find(w=>w.id===workerId)!.standardScanId=scan.id})
      worker={...worker,standardScanId:scan.id}
    }
    if(!worker.standardJobId){
      const discovery=await createLlmDiscoveryJob(config,worker.standardScanId!,job.userContext??'')
      await updateDeepJob(config,jobId,j=>{j.workers.find(w=>w.id===workerId)!.standardJobId=discovery.id})
      worker={...worker,standardJobId:discovery.id}
    }
    let discovery=await loadLlmDiscoveryJob(config,worker.standardJobId!)
    if(discovery.lifecycle!=='completed')discovery=await runLlmDiscovery(ctx,config,discovery.id,signal)
    if(discovery.lifecycle!=='completed'&&!llmSourceReportsComplete(discovery)){const causes=[discovery.baseline,...(discovery.architect?[discovery.architect]:[]),...discovery.investigators].filter(w=>w.status==='failed').map(w=>w.error).filter(Boolean);throw new Error(`Independent Standard discovery ${discovery.lifecycle}: ${[...new Set(causes)].slice(0,2).join('; ')||discovery.notes.at(-1)||'missing terminal evidence'}. Resume the retained job.`)}
    const closed=await closeAuditFindings(ctx,config,worker.standardScanId!,signal)
    if(!closed.complete&&closed.scan.tasks.some(t=>['pending','claimed'].includes(t.status)))throw new Error('Independent candidate validation/attack path has unfinished tasks; resume retained audit.')
    const scan=closed.scan,integrity=await verifyScanBundle(scan)
    if(!integrity.valid)throw new Error('Independent audit bundle failed integrity verification.')
    await updateDeepJob(config,jobId,j=>{
      const w=j.workers.find(w=>w.id===workerId)!
      const unclosed=j.worklist.filter(r=>(scan.coverage.ledger??[]).some(u=>u.path===r.path&&u.startLine<=r.endLine&&u.endLine>=r.startLine&&!['reviewed','out_of_scope'].includes(u.status)))
      w.auditComplete=scan.lifecycle==='completed'
      w.report={threatModel:scan.threatModel,reviewedWorkItemIds:j.worklist.filter(r=>!unclosed.some(u=>u.id===r.id)).map(r=>r.id),deferred:unclosed.map(r=>({workItemId:r.id,reason:'Independent source review retained an explicit unresolved boundary.'})),coverageSummary:`Independent Standard ${scan.id}: source review, two-stage coverage critique, independent validation and attack path completed.`,reportedAt:new Date().toISOString()}
      w.status='completed'
    })
  }catch(error){
    await updateDeepJob(config,jobId,j=>{const w=j.workers.find(w=>w.id===workerId)!;w.status=signal.aborted?'cancelled':'failed';w.error=(error as Error).message})
  }
}

/** 只聚合完整、密封且与父快照一致的独立审计；所有父候选仍走独立确认。 */
async function aggregateAudits(config:Config,job:DeepDiscoveryJob,workers:DeepWorker[]):Promise<void>{
  const parent=await loadScan(getStateDir(config.stateDir),job.scanId)
  for(const worker of workers){
    const scan=await loadScan(getStateDir(config.stateDir),worker.standardScanId!)
    if(!['completed','incomplete'].includes(scan.lifecycle)||scan.tasks.some(t=>['pending','claimed'].includes(t.status))||scan.targetSnapshot.snapshotDigest!==parent.targetSnapshot.snapshotDigest||!(await verifyScanBundle(scan)).valid)throw new Error('Cannot aggregate an incomplete, drifted or unsealed independent audit.')
    await writeArtifact(parent,`artifacts/02_discovery/deep/round-${String(worker.round).padStart(2,'0')}/${worker.id}/standard-audit.json`,JSON.stringify({scanId:scan.id,snapshotDigest:scan.targetSnapshot.snapshotDigest,seal:scan.seal,findings:scan.findings,coverage:scan.coverage},null,2))
    await mutateScan(config,job.scanId,p=>{
      // 复用的是绑定同一源码摘要的审阅证据，父级 Critic 仍须独立复核。
      for(const source of scan.coverage.ledger??[]){
        const unit=p.coverage.ledger?.find(u=>u.id===source.id&&u.sha256===source.sha256)
        if(source.status!=='reviewed')continue
        if(unit&&unit.status!=='reviewed'){unit.status='reviewed';unit.owner=source.owner;unit.reason=`Retained independent audit ${scan.id}: ${source.reason}`;unit.checks=source.checks;if(p.coverage.workflow?.phase==='completed')p.coverage.workflow.phase='post_wave'}
        else if(!unit&&p.coverage.receipts.some(r=>r.path===source.path&&(r.sourceSha256??r.sha256)===source.sha256)){p.coverage.ledger??=[];p.coverage.ledger.push(structuredClone(source));if(p.coverage.workflow?.phase==='completed')p.coverage.workflow.phase='post_wave'}
      }
      p.coverage.ledger?.sort((a,b)=>a.id.localeCompare(b.id))
      p.auditTrail??=[];for(const observation of scan.auditTrail??[])if(observation.kind==='source_read'&&!p.auditTrail.some(r=>r.actorId===observation.actorId&&r.path===observation.path&&r.startLine===observation.startLine&&r.endLine===observation.endLine))p.auditTrail.push(observation)
    })
    await updateDeepJob(config,job.id,j=>{
      for(const finding of scan.findings.filter(f=>confirmedFinding(f)||f.disposition==='deferred')){
        const primary=finding.locations.find(l=>l.role==='root_control')??finding.locations[0]
        const existing=j.candidates.find(c=>c.fingerprint===finding.fingerprint)
        const reportId=`independent_${scan.id}:${finding.id}`
        const proofGaps=finding.disposition==='deferred'?[...(finding.validationRecord?.proofGaps??[]),finding.validationRecord?.limitations??'Independent audit retained an unresolved decisive fact.']:[]
        if(existing){
          existing.workerIds=[...new Set([...existing.workerIds,worker.id])];existing.discoveredBy=[...new Set([...(existing.discoveredBy??[]),...(finding.discoveredBy??[])])]
          existing.reportIds=[...new Set([...existing.reportIds,reportId])];existing.proofGaps=[...new Set([...(existing.proofGaps??[]),...proofGaps])]
          existing.sourceLocations=[...(existing.sourceLocations??[]),...finding.locations.filter(l=>!(existing.sourceLocations??[]).some(p=>p.file===l.file&&p.line===l.line&&p.role===l.role))]
          const owner=j.workers.find(w=>w.id===worker.id)!;if(!owner.candidateIds.includes(existing.id))owner.candidateIds.push(existing.id)
          continue
        }
        const candidate:DeepCandidate={id:`deepcand_${sha256(finding.fingerprint).slice(0,24)}`,workerId:worker.id,workerIds:[worker.id],reportIds:[reportId],fingerprint:finding.fingerprint,ruleId:finding.ruleId,title:finding.title,severity:finding.severity,cwe:finding.cwe,file:primary.file,line:primary.line,excerpt:primary.excerpt,redactedExcerpt:primary.redactedExcerpt,sourceLocations:finding.locations,proofGaps,rootCause:finding.rootCause,remediationIdentity:finding.remediation,remediationSubsumption:{remediationIdentity:finding.remediation,decision:'not_merged',rationale:'Validated independently; recurrence does not replace parent verification.',absorbedReportIds:[reportId]},reportedAt:new Date().toISOString(),discoveredBy:finding.discoveredBy}
        j.candidates.push(candidate);j.workers.find(w=>w.id===worker.id)!.candidateIds.push(candidate.id)
      }
    })
  }
}

/** 把规范候选写入父账本；已独立确认的发现不会被 Reducer 降级，否则目标被否决时漏洞会凭空消失。 */
async function publishCandidates(config:Config,job:DeepDiscoveryJob):Promise<void>{
  const canonical=job.candidates.filter(c=>!c.absorbedBy)
  await mutateScan(config,job.scanId,p=>{
      for(const candidate of canonical)addCandidate(p,candidate)
      for(const candidate of job.candidates.filter(c=>c.absorbedBy)){
        let target=job.candidates.find(c=>c.id===candidate.absorbedBy);const visited=new Set<string>()
        while(target?.absorbedBy&&!visited.has(target.id)){visited.add(target.id);target=job.candidates.find(c=>c.id===target!.absorbedBy)}
        const duplicate=p.findings.find(f=>f.candidateId===`cand_${sha256(candidate.fingerprint).slice(0,24)}`)
        if(!duplicate||!target||confirmedFinding(duplicate))continue
        duplicate.duplicateOf=`cand_${sha256(target.fingerprint).slice(0,24)}`;duplicate.disposition='suppressed';duplicate.lifecycleState='rejected'
        duplicate.ledger.push({at:new Date().toISOString(),phase:'discovery',disposition:'suppressed',summary:`Equivalent report retained under ${duplicate.duplicateOf}; original evidence and receipts remain historical evidence, not a safe-code verdict.`})
        for(const task of p.tasks.filter(t=>t.candidateId===duplicate.candidateId&&['pending','claimed'].includes(t.status))){task.status='cancelled';task.claim=undefined;task.receipt=`Duplicate transferred to ${duplicate.duplicateOf}; retained evidence must remain addressable.`}
      }
    })
}

export async function runIndependentDeepDiscovery(ctx:Context,config:Config,jobId:string,signal?:AbortSignal):Promise<DeepDiscoveryJob>{
  let job=await loadDeepDiscoveryJob(config,jobId)
  if(!deepDiscoveryCapability(ctx,config).available){await updateDeepJob(config,jobId,j=>{j.lifecycle='failed';j.stopReason='The active DSH profile has no native agent-creation service.'});throw new Error('The active DSH profile has no native agent-creation service.')}
  if(!['queued','running','incomplete','cancelled'].includes(job.lifecycle))throw new Error('Independent Deep job is terminal.')
  const parentScan=await loadScan(getStateDir(config.stateDir),job.scanId)
  const deadline=new Date(Math.min(Date.parse(job.deadlineAt??parentScan.auditDeadlineAt??'9999-01-01'),Date.parse(job.createdAt)+(config.deepScan?.maxTimeHours??96)*3_600_000)).toISOString()
  await mutateScan(config,job.scanId,p=>{p.auditDeadlineAt=deadline})
  await updateDeepJob(config,jobId,j=>{j.deadlineAt=deadline;j.lifecycle='running'})
  const remaining=Date.parse(deadline)-Date.now()
  if(remaining<=0){await updateDeepJob(config,jobId,j=>{j.lifecycle='capped';j.stopReason='Wall-clock budget exhausted at the original absolute deadline; no budget reset on resume.'});return loadDeepDiscoveryJob(config,jobId)}
  const budget=AbortSignal.timeout(Math.min(remaining,2_147_483_647)),ownedSignal=signal?AbortSignal.any([signal,budget]):budget
  const count=deepDiscoveryCapability(ctx,config).workersPerRound,childConfig={...config,auditPriorContext:job.priorContext,auditBudgetScanId:job.scanId,investigatorConcurrency:Math.max(1,config.deepScan?.subagents??3)}
  const seen=new Set(job.acceptedFingerprints??[])
  for(;;){
    job=await loadDeepDiscoveryJob(config,jobId)
    const reason=await auditDiscoveryReserveReason(config.stateDir,job.scanId,config.maxModelTokens)
    if(reason){await updateDeepJob(config,jobId,j=>{j.lifecycle='capped';j.stopReason=reason});break}
    const complete=job.rounds.filter(r=>r.status==='complete').length
    if(complete>=job.maxRounds){await updateDeepJob(config,jobId,j=>{j.lifecycle='capped';j.stopReason='Independent audit review cap reached; cap is not convergence.'});break}
    if(ownedSignal.aborted){await updateDeepJob(config,jobId,j=>{j.lifecycle=signal?.aborted?'cancelled':'capped';j.stopReason='Owning cancellation or absolute time budget interrupted independent audits.'});break}
    let round=job.rounds.find(r=>r.status!=='complete')
    if(!round){
      const number=Math.max(0,...job.rounds.map(r=>r.number))+1
      await updateDeepJob(config,jobId,j=>{const workers=Array.from({length:count},(_,i):DeepWorker=>({id:`worker_${number}_${i+1}`,round:number,status:'pending',token:randomUUID(),candidateIds:[]}));j.workers.push(...workers);j.rounds.push({number,workerIds:workers.map(w=>w.id),candidateCount:0,novelty:0,status:'running'})})
      job=await loadDeepDiscoveryJob(config,jobId);round=job.rounds.at(-1)!
    }
    const number=round.number
    await Promise.all(round.workerIds.map(id=>independentAudit(ctx,childConfig,jobId,id,ownedSignal)))
    job=await loadDeepDiscoveryJob(config,jobId)
    const workers=job.workers.filter(w=>round!.workerIds.includes(w.id))
    const atBoundary=await auditBudgetReason(config.stateDir,job.scanId,config.maxModelTokens)
    if(atBoundary){
      // 预算耗尽不能丢弃已完成子审计的成果：候选进入父账本继续接受独立确认。
      const finished=workers.filter(w=>w.status==='completed')
      if(finished.length){await aggregateAudits(config,job,finished);job=await loadDeepDiscoveryJob(config,jobId);await publishCandidates(config,job)}
      await updateDeepJob(config,jobId,j=>{j.lifecycle='capped';j.stopReason=atBoundary;j.rounds.find(r=>r.number===number)!.status='incomplete'});break
    }

    if(workers.some(w=>w.status!=='completed')){
      const budgetReason=await auditBudgetReason(config.stateDir,job.scanId,config.maxModelTokens)
      await updateDeepJob(config,jobId,j=>{j.rounds.find(r=>r.number===number)!.status='incomplete';j.lifecycle=signal?.aborted?'cancelled':budget.aborted||budgetReason?'capped':'incomplete';j.stopReason=budgetReason??`Independent audit unfinished; retained subordinate jobs: ${[...new Set(workers.filter(w=>w.error).map(w=>w.error!))].slice(0,2).join('; ')}`})
      break
    }
    await aggregateAudits(config,job,workers)
    job=await loadDeepDiscoveryJob(config,jobId)
    let reducer=job.reducers?.find(r=>r.round===number)
    if(!reducer){reducer={id:`reducer_${number}`,round:number,status:'pending',token:randomUUID(),merges:[]};const created=reducer;await updateDeepJob(config,jobId,j=>{j.reducers??=[];j.reducers.push(created)})}
    if(reducer.status!=='completed')await runDeepReducer(ctx,config,job,reducer,ownedSignal)
    job=await loadDeepDiscoveryJob(config,jobId)
    if(job.reducers?.find(r=>r.round===number)?.status!=='completed'){await updateDeepJob(config,jobId,j=>{j.lifecycle='incomplete';j.rounds.find(r=>r.number===number)!.status='incomplete'});break}
    const canonical=job.candidates.filter(c=>!c.absorbedBy)
    // 子审计通常沿用同一模型；只合入确有差异的内容，避免随轮数线性膨胀。
    const initialModel=(job.initialThreatModel??'').trim()
    const distinct=[...new Set(job.workers.filter(w=>w.status==='completed').map(w=>w.report!.threatModel.trim()))].filter(text=>text&&text!==initialModel)
    const model=[initialModel,...distinct.map((text,index)=>`## Independent audit model ${index+1}\n${text}`)].filter(Boolean).join('\n\n')
    const contextScan=await loadScan(getStateDir(config.stateDir),job.scanId)
    const modelRef=await writeArtifact(contextScan,'artifacts/01_context/deep_canonical_threat_model.md',model)
    await mutateScan(config,job.scanId,p=>{p.threatModel=model})
    await publishCandidates(config,job)
    const closure=await closeAuditFindings(ctx,config,job.scanId,ownedSignal,false)
    if(!closure.complete){const reason=await auditBudgetReason(config.stateDir,job.scanId,config.maxModelTokens);await updateDeepJob(config,jobId,j=>{j.lifecycle=ownedSignal.aborted?(signal?.aborted?'cancelled':'capped'):reason?'capped':'incomplete';j.stopReason=reason??'Independent candidate/final-record review has retained work.';j.rounds.find(r=>r.number===number)!.status='incomplete'});return loadDeepDiscoveryJob(config,jobId)}
    const clean=await closeCoverage(ctx,config,job.scanId,ownedSignal)
    const scan=await loadScan(getStateDir(config.stateDir),job.scanId)
    const accepted=canonical.filter(c=>scan.findings.some(f=>f.candidateId===`cand_${sha256(c.fingerprint).slice(0,24)}`&&confirmedFinding(f)))
    const knownTargets=new Set(job.candidates.filter(c=>seen.has(c.fingerprint)).map(c=>{let current=c;const visited=new Set<string>();while(current.absorbedBy&&!visited.has(current.id)){visited.add(current.id);current=job.candidates.find(candidate=>candidate.id===current.absorbedBy)??current}return current.id}))
    const novelty=accepted.filter(c=>!knownTargets.has(c.id)).length
    accepted.forEach(c=>seen.add(c.fingerprint))

    await updateDeepJob(config,jobId,j=>{
      const r=j.rounds.find(r=>r.number===number)!;r.candidateCount=canonical.length;r.novelty=novelty
      j.canonicalThreatModel={artifactRef:modelRef,digest:sha256(model),workerIds:j.workers.filter(w=>w.status==='completed').map(w=>w.id),createdAt:new Date().toISOString()}
      if(clean)j.consecutiveNoNew=novelty?0:(j.consecutiveNoNew??0)+1
      j.progress??=[];j.progress.push({round:number,novelty,coverageGaps:coverageGaps(scan).length,validationBacklog:scan.tasks.filter(t=>['pending','claimed'].includes(t.status)).length,duplicateRatio:canonical.length?1-novelty/canonical.length:0})
      if(!clean){j.lifecycle='incomplete';r.status='incomplete';j.stopReason='Parent coverage repair retained unresolved work.'}
      else {r.status='complete';j.acceptedFingerprints=[...seen]}
      if(clean && (j.consecutiveNoNew??0)>=(config.deepScan?.stopAfterNoNew??6)){j.lifecycle='saturated';j.stopReason=undefined}
    })
    job=await loadDeepDiscoveryJob(config,jobId)
    if(job.lifecycle!=='running')break
  }
  return loadDeepDiscoveryJob(config,jobId)
}
