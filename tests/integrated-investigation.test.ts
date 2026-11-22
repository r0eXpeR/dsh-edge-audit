import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'
import { runScan } from '../src/scanner.ts'
import { loadScan, saveScan, verifyScanBundle } from '../src/state.ts'
import { createLlmDiscoveryJob, loadLlmDiscoveryJob, readLlmSource, reportLlmWorker, runLlmDiscovery } from '../src/llm/discovery.ts'
import { buildInvestigationMap } from '../src/investigation-plan.ts'
import { closeCoverage } from '../src/coverage-workflow.ts'
import { createDeepInvestigationJob, runDeepInvestigation } from '../src/deep-workflow.ts'
import { loadDeepDiscoveryJob } from '../src/deep-discovery.ts'
import { nativeAuditFixture } from './native-audit-fixture.ts'
import { reviewFixtureCoverage } from './coverage-fixture.ts'
import { mechanicalPolicyPass } from '../src/llm/attack-path.ts'
import { fixturePolicyFacts } from './coverage-fixture.ts'
import { scanView } from '../src/scan-view.ts'

async function fixture(){
  const root=await mkdtemp(join(tmpdir(),'dsh-integrated-source-')),state=await mkdtemp(join(tmpdir(),'dsh-integrated-state-'))
  const config={enabled:true,maxFiles:30,maxFileBytes:65_536,stateDir:state,discoveryBatchRegions:1,maxCoverageWaves:3,deepScan:{workers:1 as const,subagents:2,stopAfterNoNew:1,stopAfterConsecutiveErrors:3,maxDiscoveryRuns:3,maxTimeHours:1}}
  return {root,state,config,async cleanup(){await rm(root,{recursive:true,force:true});await rm(state,{recursive:true,force:true})}}
}

test('Investigation packets retain source-local guards, sinks, import links and lifecycle facts without asserting reachability',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'route.ts'),"import { run } from './service.js'\nrouter.post('/refund', requireAuth, req => run(req.body))\n")
    await writeFile(join(f.root,'service.ts'),"export function run(input) { if (input.tenantId) return fetch(input.url); else throw Error('retry') }\n")
    const scan=await runScan(f.root,f.config,'standard','',false,f.state,false),map=await buildInvestigationMap(scan,1)
    assert.ok(map.links.some(l=>l.from==='route.ts'&&l.to==='service.ts'&&l.line===1))
    assert.ok(map.facts.some(f=>f.kind==='control'&&f.file==='route.ts'&&f.line===2))
    assert.ok(map.facts.some(f=>f.kind==='sink'&&f.file==='service.ts'&&f.line===1))
    assert.ok(map.packets.some(p=>p.supportingPaths?.includes('service.ts')))
    assert.ok(map.packets.every(p=>p.questions.some(q=>q.includes('not execution edges'))))
  }finally{await f.cleanup()}
})

test('Standard resumes only unfinished source batches and retains failed execution evidence',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'app.ts'),Array.from({length:430},(_,i)=>`const item${i}=${i};`).join('\n'))
    const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
    const job=await createLlmDiscoveryJob(f.config,scan.id)
    const broken=nativeAuditFixture(f.config,{failInvocation:(id,n)=>id==='baseline_1'&&n===2})
    const interrupted=await runLlmDiscovery(broken.ctx as never,f.config,job.id)
    assert.equal(interrupted.lifecycle,'incomplete');assert.equal(interrupted.baseline.checkpoints?.length,1)
    assert.match(interrupted.baseline.executions?.at(-1)?.error??'',/Fixture interruption/)
    assert.ok(interrupted.baseline.executions?.at(-1)?.usage)
    const done=new Set(interrupted.baseline.checkpoints![0].report.reviewedRegionIds)
    const resumed=nativeAuditFixture(f.config)
    assert.equal((await runLlmDiscovery(resumed.ctx as never,f.config,job.id)).lifecycle,'completed')
    assert.ok(resumed.calls.filter(c=>c.workerId==='baseline_1').every(c=>c.regions?.every(r=>!done.has(r))))
    assert.equal(resumed.calls.filter(c=>c.kind==='final_critic').length,1)
    assert.equal(resumed.disposed(),resumed.calls.length)
  }finally{await f.cleanup()}
})

test('Critic gaps cause a fresh owned repair wave followed by distinct post-wave and final-clean critics',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'app.ts'),'export const safeValue=1;\n')
    const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
    await reviewFixtureCoverage(f.config,scan.id)
    const runtime=nativeAuditFixture(f.config,{reassignOnce:true})
    assert.equal(await closeCoverage(runtime.ctx as never,f.config,scan.id),true)
    const persisted=await loadScan(f.state,scan.id)
    assert.equal(persisted.coverage.workflow?.waves,1)
    assert.equal(persisted.coverage.workflow?.phase,'completed')
    assert.equal(persisted.coverage.auditComplete,true)
    assert.equal(new Set(persisted.coverage.critics?.map(c=>c.actorId)).size,3)
    assert.ok(persisted.coverage.ledger?.some(u=>u.attempts.length>0))
    assert.ok(runtime.calls.some(c=>c.workerId==='investigator_1'))
  }finally{await f.cleanup()}
})

test('Deep runs independent complete Standard audits, aggregates validated evidence and converges on validated novelty',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'app.ts'),'export function route(req) { return eval(req.query.code) }\n')
    const flow=await createDeepInvestigationJob(f.root,f.config,'Review only the declared fixture execution boundary.',false)
    const runtime=nativeAuditFixture(f.config,{candidate:true})
    const result=await runDeepInvestigation(runtime.ctx as never,f.config,flow.id)
    const job=await loadDeepDiscoveryJob(f.config,flow.discoveryJobId)
    assert.equal(result.lifecycle,'completed',JSON.stringify({flow:result,reason:job.stopReason,workers:job.workers.map(w=>({status:w.status,error:w.error}))}))
    assert.equal(job.strategy,'independent_standard')
    assert.equal(job.rounds.length,2)
    assert.ok(job.rounds[0].novelty>0);assert.equal(job.rounds[1].novelty,0)
    assert.equal(new Set(job.workers.map(w=>w.standardScanId)).size,2)
    for(const worker of job.workers){
      const child=await loadScan(f.state,worker.standardScanId!)
      assert.equal(child.lifecycle,'completed')
      assert.ok(child.findings.some(f=>f.validationRecord?.independent&&f.attackPathRecord))
      assert.equal((await loadLlmDiscoveryJob(f.config,worker.standardJobId!)).lifecycle,'completed')
    }
    const parent=await loadScan(f.state,flow.scanId)
    assert.equal((await verifyScanBundle(parent)).valid,true)
    assert.ok(parent.findings.some(f=>f.lifecycleState==='confirmed'&&f.attackPathRecord?.policyDecision?.decision==='reportable'))
    assert.equal(runtime.disposed(),runtime.calls.length)
  }finally{await f.cleanup()}
})

test('Unknown decisive facts defer without lowering severity, unknown deployment facts stay reportable',()=>{
  for(const field of ['impact','preconditions','attackerInputControl']){const result=mechanicalPolicyPass({...fixturePolicyFacts,[field]:'unknown'} as never);assert.equal(result.decision,'deferred');assert.equal(result.severity,undefined)}
  for(const field of ['vector','authScope'])assert.equal(mechanicalPolicyPass({...fixturePolicyFacts,[field]:'unknown'} as never).decision,'reportable')
  assert.equal(mechanicalPolicyPass({...fixturePolicyFacts,likelihood:'unknown'} as never).severity,'medium')
})

test('Baseline investigation proposals require actually observed source and supplement the original inventory',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'app.ts'),'export const value=1;\n')
    await writeFile(join(f.root,'service.ts'),'export function protectedOperation(input) { return input.ownerId }\n')
    const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
    const job=await createLlmDiscoveryJob(f.config,scan.id)
    job.lifecycle='running';job.baseline.status='running';job.baseline.assignment=job.baseline.regions!.filter(r=>r.path==='app.ts')
    await writeFile(join(f.state,'llm-discovery',`${job.id}.json`),JSON.stringify(job))
    await readLlmSource(f.config,job.id,job.baseline.id,job.baseline.token,'app.ts')
    const report={findings:[],fullyReviewedFileCount:0,resolvedQuestions:[],investigationPackets:[{attacker:'A caller whose identity and input must be derived from actual callers.',protectedAsset:'The protected object addressed by input.ownerId in the declared operation.',expectedControls:['Object ownership must be checked at the actual operation.'],questions:['Which caller reaches this object operation, and where is ownership enforced?'],sourceReferences:[{file:'service.ts',line:1,role:'root_control' as const}]}]}
    await assert.rejects(()=>reportLlmWorker(f.config,job.id,job.baseline.id,job.baseline.token,report),/actually read/)
    await readLlmSource(f.config,job.id,job.baseline.id,job.baseline.token,'service.ts')
    await reportLlmWorker(f.config,job.id,job.baseline.id,job.baseline.token,report)
    const planned=await loadLlmDiscoveryJob(f.config,job.id)
    assert.equal(planned.packets.length,job.packets.length+1)
    assert.ok(planned.packets.some(p=>p.id.startsWith('packet_model_')&&p.paths.includes('service.ts')))
  }finally{await f.cleanup()}
})

test('Deep resume reuses completed independent audits and the unfinished subordinate job IDs',async()=>{
  const f=await fixture();try{
    f.config.deepScan.workers=2 as never
    await writeFile(join(f.root,'app.ts'),'export const safeValue=1;\n')
    const flow=await createDeepInvestigationJob(f.root,f.config,'Review the finite safe fixture.',false)
    const interrupted=nativeAuditFixture(f.config,{failInvocation:(id,n)=>id==='baseline_1'&&n===2})
    assert.equal((await runDeepInvestigation(interrupted.ctx as never,f.config,flow.id)).lifecycle,'incomplete')
    const before=await loadDeepDiscoveryJob(f.config,flow.discoveryJobId),finished=before.workers.find(w=>w.status==='completed')!
    assert.ok(finished.standardScanId)
    const resumed=nativeAuditFixture(f.config)
    const result=await runDeepInvestigation(resumed.ctx as never,f.config,flow.id)
    const after=await loadDeepDiscoveryJob(f.config,flow.discoveryJobId)
    assert.equal(result.lifecycle,'completed',JSON.stringify(after.workers.map(w=>w.error)))
    assert.equal(after.rounds.length,1)
    assert.equal(after.workers.length,2)
    assert.deepEqual(after.workers.map(w=>w.standardJobId),before.workers.map(w=>w.standardJobId))
    assert.ok(resumed.calls.every(c=>c.scanId!==finished.standardScanId))
    assert.equal(after.deadlineAt,before.deadlineAt)
  }finally{await f.cleanup()}
})

test('Deep token budget includes independent critics and caps before further model creation',async()=>{
  const f=await fixture();try{
    const config={...f.config,maxModelTokens:425}
    await writeFile(join(f.root,'app.ts'),'export const safeValue=1;\n')
    const flow=await createDeepInvestigationJob(f.root,config,'Review the finite safe fixture.',false)
    const runtime=nativeAuditFixture(config)
    assert.equal((await runDeepInvestigation(runtime.ctx as never,config,flow.id)).lifecycle,'incomplete')
    const job=await loadDeepDiscoveryJob(config,flow.discoveryJobId),parent=await loadScan(f.state,flow.scanId)
    assert.equal(job.lifecycle,'capped')
    assert.match(job.stopReason!,/Measured model usage/)
    assert.ok(parent.modelExecutions?.some(e=>e.role==='coverage_critic'))
    assert.equal(runtime.calls.length,4)
    assert.equal(parent.modelExecutions?.length,4)
  }finally{await f.cleanup()}
})

test('Claimed scan DTO stays valid and bounded even when independent audit history exceeds host output limits',async()=>{
  const f=await fixture();try{
    await writeFile(join(f.root,'app.ts'),'export function route(req) { return eval(req.query.code) }\n')
    const scan=await runScan(f.root,f.config,'standard','',false,f.state,false)
    scan.modelExecutions=Array.from({length:1000},(_,i)=>({sessionId:`large-history-${i}`,actorId:`session:large-history-${i}`,role:'discoverer',at:new Date().toISOString(),usage:null,toolCalls:25}))
    scan.threatModel='Source-backed context '.repeat(5000)
    const finding=scan.findings[0],actor={id:'session:fixture-validator',role:'validator' as const}
    scan.tasks[0].status='claimed';scan.tasks[0].claim={owner:actor.id,token:'not-a-public-token',claimedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+60_000).toISOString()}
    const encoded=JSON.stringify(scanView(scan,actor,finding.candidateId)),view=JSON.parse(encoded)
    assert.ok(Buffer.byteLength(encoded)<=32768)
    assert.equal(view.findings[0].candidateId,finding.candidateId)
    assert.equal(view.findings[0].detailContext.kind,'candidate')
    assert.equal(view.modelExecutionCount,1000)
    assert.equal(view.threatModelTruncated,true)
    assert.equal(encoded.includes('not-a-public-token'),false)
    assert.equal(encoded.includes('large-history-'),false)
    assert.equal((scanView(scan,{id:'another-session',role:'validator'},finding.candidateId).findings as unknown[]).length,0)
  }finally{await f.cleanup()}
})
