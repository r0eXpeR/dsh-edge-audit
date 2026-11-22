import assert from 'node:assert/strict'
import { mkdtemp,mkdir,readFile,rm,writeFile,chmod,stat } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import test from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import { registerSecuritySkills,listPackagedSkills,readPackagedSkill,skillGuidance } from '../src/skills.ts'
import { proofTupleFor } from '../src/llm/validation.ts'
import { runScan,runDiffScan } from '../src/scanner.ts'
import { saveScan,loadScan,readArtifact,writeArtifact,sha256 } from '../src/state.ts'
import { createLlmDiscoveryJob,getLlmScope,readLlmContext,runLlmScan,searchLlmSource,loadLlmDiscoveryJob,llmSourceReportsComplete } from '../src/llm/discovery.ts'
import { closeCoverage } from '../src/coverage-workflow.ts'
import { invalidateFindingEvidence } from '../src/finding-revision.ts'
import { claimAuditTask,recordValidation,recordAttackPath } from '../src/workbench.ts'
import { withScanLease } from '../src/scan-lease.ts'
import { attachFixtureEndpoints,fixturePolicyFacts } from './coverage-fixture.ts'
import { validateFixtureFindings,reviewFixtureCoverage } from './coverage-fixture.ts'
import { nativeAuditFixture } from './native-audit-fixture.ts'
import { closeAuditFindings } from '../src/audit-workflow.ts'
import { collectSourceStructure } from '../src/source-structure.ts'
import { ingestModelCandidates } from '../src/candidate-ingestion.ts'
import { proposeReviewedRemediation,applyRemediationProposal,rollbackRemediationProposal,runIsolatedValidation } from '../src/operations.ts'
import { replaceExpectedFile } from '../src/patch-transaction.ts'
import { withAuditActor,redactValue } from '../src/audit-context.ts'
import { redactSensitive } from '../src/audit-context.ts'
import { scanView } from '../src/scan-view.ts'
import { mechanicalPolicyPass } from '../src/llm/attack-path.ts'
import { resolveSnapshotLocations } from '../src/source-evidence.ts'
import { coverageDigest,observeCoveragePage,observeCoverageUnitContext,recordCoverageCritic } from '../src/coverage.ts'
import { coverageUnitContext } from '../src/coverage-view.ts'
import { readScanSource,createDeepDiscoveryJob,getDeepReducerInput,reportDeepReducer,addCandidate } from '../src/deep-discovery.ts'
import { compareScans } from '../src/comparison.ts'
import { createDeepInvestigationJob } from '../src/deep-workflow.ts'
import { investigationStatus } from '../src/investigation-status.ts'
import { acquireModelSlot,modelPoolStatus } from '../src/model-pool.ts'
import { runAuditTool,bindAuditSession,unbindAuditSession } from '../src/audit-context.ts'
import { workspaceDirectory } from '../src/runtime.ts'
import { createCandidateFollowup } from '../src/candidate-followup.ts'
import { readCandidateArtifact,requireExecutionArtifactReview } from '../src/candidate-artifact.ts'
import { testSandbox } from './coverage-fixture.ts'

async function fixture(){const root=await mkdtemp(join(tmpdir(),'dsh-refine-source-')),state=await mkdtemp(join(tmpdir(),'dsh-refine-state-'));return {root,state,config:{enabled:true,maxFiles:20,maxFileBytes:65536,stateDir:state},async cleanup(){await rm(root,{recursive:true,force:true});await rm(state,{recursive:true,force:true})}}}

test('Packaged skills register through the real native registry and disappear with plugin disposal',async()=>{
 const ctx=new Context();await ctx.plugin(SkillRegistry)
 const fiber=await ctx.plugin({apply(c:Context){registerSecuritySkills(c)}})
 const skills=ctx.get('skills')!,catalog=await skills.list()
 assert.equal(catalog.filter(s=>s.provider==='dsh-edge-audit').length,8)
 const skill=await skills.get('dsh-edge-validation');assert.equal(skill?.source,'bundled');assert.match(skill!.content,/proof tuple/)
 await fiber.dispose();assert.equal((await skills.list()).filter(s=>s.provider==='dsh-edge-audit').length,0)
})

test('Trusted skill reads use a fixed asset allowlist and selected domain guidance retains its proof discipline',()=>{
 assert.equal(listPackagedSkills().length,8)
 assert.throws(()=>readPackagedSkill('dsh-edge-discovery','../../package.json'),/Unknown packaged/)
 assert.throws(()=>readPackagedSkill('repository-instructions'),/Unknown packaged/)
 const text=skillGuidance('discovery',['tenant-lifecycle','ai-agent'])
 assert.match(text,/cache/);assert.match(text,/dispatcher/);assert.equal(text.includes('sanitizer 标签'),false)
 assert.match(skillGuidance('validation',['tenant-lifecycle','ai-agent']),/## 验证与反证/)
 assert.equal(proofTupleFor('cors.policy','CWE-942').id,'auth-token-protocol')
 assert.equal(proofTupleFor('custom','CWE-798').id,'secret-data-exposure')
})

test('Missing native Session cannot bypass worker identity or silently scan the host process directory',()=>{
 assert.throws(()=>runAuditTool('security_llm_read_source',{job_id:'copied-job',claim_token:'copied-token'},undefined,()=>true),/natively bound/)
 assert.throws(()=>runAuditTool('security_record_validation',{owner:'forged-reviewer'},undefined,()=>true),/actual reviewer Session/)
 assert.throws(()=>workspaceDirectory(new Context()),/actual Session working directory/)
 bindAuditSession('fixture-architect',{id:'ignored',role:'architect',scanId:'fixture-scan'})
 try{assert.throws(()=>runAuditTool('security_read_scan_context',{scan_id:'fixture-scan',kind:'candidate'},'fixture-architect',()=>true),/current candidate conclusions/)}finally{unbindAuditSession('fixture-architect')}
})

test('Reportability preserves a proved limited-admin privilege delta and really calibrates constrained exposure',()=>{
 const constrained={...fixturePolicyFacts,authScope:'admin-only' as const,privilegedOnly:true}
 assert.equal(mechanicalPolicyPass(constrained).decision,'ignore')
 assert.throws(()=>mechanicalPolicyPass({...constrained,privilegeDelta:true}),/concrete additional authority/)
 assert.equal(mechanicalPolicyPass({...constrained,privilegeDelta:true,privilegeDeltaEvidence:'A limited tenant administrator crosses the actual object guard into another tenant with additional resource authority.',criticalCriteria:{privilegeGain:true}}).decision,'reportable')
 assert.equal(mechanicalPolicyPass({...fixturePolicyFacts,authScope:'internal-only'}).severity,'medium')
 assert.equal(mechanicalPolicyPass({...fixturePolicyFacts,authScope:'admin-only'}).severity,'low')
 assert.equal(mechanicalPolicyPass({...fixturePolicyFacts,preconditions:'unlikely'}).severity,'low')
})

test('Credential projections protect common nested names without breaking native claim-token contracts',()=>{
 const token='synthetic-operational-claim',secret='synthetic-credential-value'
 const projected=redactValue({claimToken:token,DB_PASSWORD:secret,clientSecret:secret,token_endpoint:'https://identity.invalid/token'}) as Record<string,string>
 assert.equal(projected.claimToken,token);assert.equal(projected.DB_PASSWORD,'[REDACTED]');assert.equal(projected.clientSecret,'[REDACTED]');assert.equal(projected.token_endpoint,'https://identity.invalid/token')
 assert.equal(redactSensitive(`const clientSecret = "${secret}"`).includes(secret),false)
})

test('Large frozen worker context is paged, complete and does not corrupt the scope JSON',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'export const safe=1;\n')
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);scan.threatModel='model/context '.repeat(6000);scan.policyGuidance='policy/context '.repeat(6000);await saveScan(f.state,scan)
  const job=await createLlmDiscoveryJob(f.config,scan.id,'user/context '.repeat(6000));job.lifecycle='running';job.baseline.status='running'
  await writeFile(join(f.state,'llm-discovery',`${job.id}.json`),JSON.stringify(job))
  const scope=getLlmScope(f.config,job.id,job.baseline.id,job.baseline.token)
  assert.ok(Buffer.byteLength(JSON.stringify(scope))<=24576);assert.ok(scope.contextRefs.some(r=>r.kind==='user_context'))
  let value='',offset=0;for(;;){const page=await readLlmContext(f.config,job.id,job.baseline.id,job.baseline.token,'user_context',offset);value+=page.content;if(page.nextOffset===undefined)break;offset=page.nextOffset}
  assert.equal(value,job.userContext)
 }finally{await f.cleanup()}
})

test('Expanded evidence cancels old claims and permits a fresh receipt after an earlier completed task',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n')
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
  const finding=scan.findings[0],first=await claimAuditTask(f.config,scan.id,'first-independent','validation');assert.ok(first)
  const refs=await attachFixtureEndpoints(f.config,scan.id,finding.candidateId,first.claimToken)
  const validation={method:'static' as const,conclusion:'reportable' as const,attacker:'The declared caller controls the request expression.',entryPoint:'The declared function accepts a request.',trustBoundary:'Request text enters dynamic evaluation.',rootControl:'The expression reaches the retained eval operation.',sink:'The actual eval in source.',impact:'Caller-controlled expression evaluation.',directEvidence:'The exact frozen argument is consumed directly by eval.',counterevidence:'No additional enforcing layer exists in this finite fixture.',limitations:'Static finite fixture review, not a runtime reproduction.',confidence:'medium' as const,sourceReferences:refs}
  await recordValidation(f.config,scan.id,finding.candidateId,validation,first.claimToken)
  const attack=await claimAuditTask(f.config,scan.id,'old-path-reviewer','attack_path');assert.ok(attack)
  const current=await loadScan(f.state,scan.id);invalidateFindingEvidence(current,current.findings.find(f=>f.candidateId===finding.candidateId)!,'Additional affected evidence requires a fresh independent review.');await saveScan(f.state,current)
  await assert.rejects(()=>recordAttackPath(f.config,scan.id,finding.candidateId,{policyFacts:fixturePolicyFacts} as never,attack.claimToken),/reportable|claimed/)
  const second=await claimAuditTask(f.config,scan.id,'new-independent','validation');assert.ok(second)
  assert.notEqual(second.taskId,first.taskId)
  await recordValidation(f.config,scan.id,finding.candidateId,validation,second.claimToken)
  const result=await loadScan(f.state,scan.id)
  assert.equal(result.findings[0].validationRecord?.reviewer,'new-independent');assert.equal(result.findings[0].priorReceipts?.length,1)
 }finally{await f.cleanup()}
})

test('One scan admits only one coordinator chain while allowing its internal phases to reenter',async()=>{
 const f=await fixture();try{
  let release!:()=>void,entered!:()=>void;const started=new Promise<void>(resolve=>{entered=resolve}),gate=new Promise<void>(resolve=>{release=resolve})
  const id='scan_00000000-0000-0000-0000-000000000000'
  const active=withScanLease(f.state,id,async()=>{await withScanLease(f.state,id,async()=>undefined);entered();await gate})
  await started;await assert.rejects(()=>withScanLease(f.state,id,async()=>undefined),/active coordinator/)
  release();await active;await withScanLease(f.state,id,async()=>undefined)
 }finally{await f.cleanup()}
})

test('Shared model capacity is FIFO, cancellable while queued and releases exactly once',async()=>{
 const first=await acquireModelSlot(1),order:number[]=[]
 const controller=new AbortController(),cancelled=acquireModelSlot(1,controller.signal)
 const cancelledAssertion=assert.rejects(()=>cancelled,/queued fixture cancellation/)
 const second=acquireModelSlot(1).then(release=>{order.push(2);return release})
 assert.equal(modelPoolStatus().active,1);assert.equal(modelPoolStatus().queued,2)
 controller.abort(new Error('queued fixture cancellation'));await cancelledAssertion
 assert.equal(modelPoolStatus().queued,1);first();first()
 const release=await second;assert.deepEqual(order,[2]);assert.equal(modelPoolStatus().active,1)
 release();assert.deepEqual(modelPoolStatus(),{active:0,queued:0})
 await assert.rejects(()=>acquireModelSlot(Number.NaN),/finite/)
})

test('Status resumes the incomplete parent workflow after discovery converges and blocks exhausted discovery budgets',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'export const safe=1;\n')
  const flow=await createDeepInvestigationJob(f.root,f.config,'Review the finite safe fixture.',false)
  const deepPath=join(f.state,'deep-discovery',`${flow.discoveryJobId}.json`),deep=JSON.parse(await readFile(deepPath,'utf8'));deep.lifecycle='saturated';await writeFile(deepPath,JSON.stringify(deep))
  flow.lifecycle='incomplete';flow.phase='validation';await writeFile(join(f.state,'deep-investigations',`${flow.id}.json`),JSON.stringify(flow))
  const scan=await loadScan(f.state,flow.scanId);scan.discoveryStatus={driver:'deep',jobId:deep.id,lifecycle:'saturated'};await saveScan(f.state,scan)
  const status=await investigationStatus(f.config,scan.id)
  assert.equal(status.resumable,true);assert.equal(status.resume?.tool,'security_resume_deep_investigation');assert.equal(status.resume?.job_id,flow.id);assert.equal(status.executionTrackingAvailable,false)
  deep.lifecycle='capped';await writeFile(deepPath,JSON.stringify(deep))
  assert.equal((await investigationStatus(f.config,scan.id)).resumable,false)
 }finally{await f.cleanup()}
})

test('JS/TS architecture facts distinguish syntax from comments and string examples',()=>{
 const result=collectSourceStructure('route.ts',`// import fake from './not-real.js'\nconst example="router.get eval requireAuth";\nimport {run} from './service.js';\nrouter.post('/run',requireAuth,req=>run(req.body));\nfetch(destination);\n`)
 assert.deepEqual(result.imports.map(i=>i.specifier),['./service.js'])
 assert.ok(result.facts.every(f=>f.line>=4&&f.evidence==='syntax'))
 assert.ok(result.facts.some(f=>f.kind==='entrypoint'));assert.ok(result.facts.some(f=>f.kind==='control'));assert.ok(result.facts.some(f=>f.kind==='sink'))
})

test('Credential-bearing configuration and private-key formats remain source-readable without requiring executable code',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'.env.local'),'API_KEY=DEMONSTRABLE_PLACEHOLDER_ONLY\n')
  await writeFile(join(f.root,'private.pem'),'-----BEGIN PRIVATE KEY-----\nDEMONSTRABLE_PLACEHOLDER_ONLY\n-----END PRIVATE KEY-----\n')
  await writeFile(join(f.root,'service.properties'),'credential=DEMONSTRABLE_PLACEHOLDER_ONLY\n')
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false),paths=new Set(scan.coverage.receipts.map(r=>r.path))
  for(const path of ['.env.local','private.pem','service.properties'])assert.ok(paths.has(path))
  assert.ok(scan.findings.every(f=>f.lifecycleState!=='confirmed'))
 }finally{await f.cleanup()}
})

test('Private-key body is redacted in search, source facts and public location views while raw evidence identity remains internal',async()=>{
 const f=await fixture();try{
  const material='exec+SYNTHETIC_PRIVATE_BODY_ONLY';await writeFile(join(f.root,'private.pem'),`-----BEGIN PRIVATE KEY-----\n${material}\n-----END PRIVATE KEY-----\n`)
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
  const job=await createLlmDiscoveryJob(f.config,scan.id);job.lifecycle='running';job.baseline.status='running';await writeFile(join(f.state,'llm-discovery',`${job.id}.json`),JSON.stringify(job))
  const matches=await searchLlmSource(f.config,job.id,job.baseline.id,job.baseline.token,'SYNTHETIC_PRIVATE_BODY')
  assert.equal(matches.length,1);assert.equal(matches[0].line,2);assert.equal(matches[0].text.includes(material),false)
  const refs=await resolveSnapshotLocations(scan,[{file:'private.pem',line:2,role:'root_control'}]);assert.equal(refs[0].excerpt,material);assert.equal(JSON.stringify(redactValue(refs)).includes(material),false)
  assert.equal(JSON.stringify(collectSourceStructure('private.pem',await readFile(join(f.root,'private.pem'),'utf8'))).includes(material),false)
 }finally{await f.cleanup()}
})

test('Private blocks are redacted before scope/summary truncation, including encrypted and PGP formats',async()=>{
 const f=await fixture();try{
  const marker='SYNTHETIC_LONG_PRIVATE_BLOCK_BODY';await writeFile(join(f.root,'app.ts'),'export const safe=1;\n')
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);scan.threatModel=`-----BEGIN ENCRYPTED PRIVATE KEY-----\n${marker.repeat(1000)}\n-----END ENCRYPTED PRIVATE KEY-----`;await saveScan(f.state,scan)
  const job=await createLlmDiscoveryJob(f.config,scan.id);job.lifecycle='running';job.baseline.status='running';await writeFile(join(f.state,'llm-discovery',`${job.id}.json`),JSON.stringify(job))
  assert.equal(JSON.stringify(getLlmScope(f.config,job.id,job.baseline.id,job.baseline.token)).includes(marker),false)
  assert.equal(JSON.stringify(scanView(scan)).includes(marker),false)
  assert.equal(redactSensitive(`-----BEGIN PGP PRIVATE KEY BLOCK-----\n${marker}\n-----END PGP PRIVATE KEY BLOCK-----`).includes(marker),false)
 }finally{await f.cleanup()}
})

test('Private-key material stops execution before invoking even a configured runtime binary',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'probe.js'),'console.log("must not execute");\n');await writeFile(join(f.root,'private.pem'),'-----BEGIN PRIVATE KEY-----\nSYNTHETIC_FIXTURE_BODY\n-----END PRIVATE KEY-----\n')
  const config={...f.config,validationSandbox:{executable:'/private/tmp/nonexistent-dsh-fixture-runtime',image:'sha256:'+'f'.repeat(64)}}
  const scan=await runScan(f.root,config,'standard','',false,f.state,false);await saveScan(f.state,scan)
  await assert.rejects(()=>runIsolatedValidation(f.root,config,scan.id,'node probe.js'),/Private-key material/)
 }finally{await f.cleanup()}
})

test('Only an exact trusted dummy-key digest enters scratch and configured retained state stays outside both inventory and runtime copy',{skip:!testSandbox?'Explicit pinned local Docker toolchain required.':false},async()=>{
 const f=await fixture();try{
  const body='-----BEGIN PRIVATE KEY-----\nSYNTHETIC_FIXTURE_BODY\n-----END PRIVATE KEY-----\n',state=join(f.root,'retained-output')
  await mkdir(state);await writeFile(join(state,'unrelated-private.json'),'{}');await writeFile(join(f.root,'private.pem'),body)
  await writeFile(join(f.root,'probe.js'),'const fs=require("fs");console.log(JSON.stringify({keyPresent:fs.existsSync("private.pem"),statePresent:fs.existsSync("retained-output")}));\n')
  const config={...f.config,stateDir:state,validationSandbox:{...testSandbox!,allowedDummyCredentialDigests:[sha256(body)]}}
  const scan=await runScan(f.root,config,'standard','',false,state,false);await saveScan(state,scan);assert.ok(scan.coverage.receipts.every(r=>!r.path.startsWith('retained-output/')))
  const receipt=await runIsolatedValidation(f.root,config,scan.id,'node probe.js');assert.equal(receipt.exitCode,0,receipt.stderr);assert.deepEqual(JSON.parse(receipt.stdout),{keyPresent:true,statePresent:false})
 }finally{await f.cleanup()}
})

test('Execution-backed final reviewers must actually read every candidate-bound artifact page',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n');const scan=await runScan(f.root,f.config,'standard','',false,f.state,false),finding=scan.findings[0]
  const ref='artifacts/05_findings/fixture/runtime.json';await writeArtifact(scan,ref,JSON.stringify({snapshotDigest:scan.targetSnapshot.snapshotDigest,stdout:'Finite fixture observation. '.repeat(1000),stderr:'',timedOut:false}))
  finding.evidence.push({kind:'runtime',detail:'Synthetic retained artifact for a read-observation contract test.',artifactRef:ref});finding.validationRecord={method:'runtime',runtimeReceiptRefs:[ref]} as never;await saveScan(f.state,scan)
  await assert.rejects(()=>requireExecutionArtifactReview(scan,finding,'fresh-reviewer'),/every retained candidate artifact page/)
  await assert.rejects(()=>readCandidateArtifact(f.config,scan.id,finding.candidateId,'../../outside'),/not bound/)
  let offset=0;for(;;){const page=await readCandidateArtifact(f.config,scan.id,finding.candidateId,ref,offset,'fresh-reviewer');if(page.nextOffset===undefined)break;offset=page.nextOffset}
  const current=await loadScan(f.state,scan.id);await requireExecutionArtifactReview(current,current.findings[0],'fresh-reviewer')
 }finally{await f.cleanup()}
})

test('Needs Validation gets a fresh final reviewer and an exact owner-observed plan before complete delivery',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n')
  const runtime=nativeAuditFixture(f.config,{deferCandidate:true})
  const started=await runLlmScan(runtime.ctx as never,f.config,f.root)
  const closed=await closeAuditFindings(runtime.ctx as never,f.config,started.scan.id)
  assert.equal(closed.complete,true)
  const pending=closed.scan.findings.filter(f=>f.disposition==='deferred');assert.ok(pending.length)
  for(const finding of pending){assert.ok(finding.finalReview);assert.ok(finding.validationRecord?.validationPlan?.deployment);assert.notEqual(finding.finalReview!.reviewer,finding.priorReceipts?.at(-1)?.validationRecord?.reviewer)}
 }finally{await f.cleanup()}
})

test('A retained candidate can get an explicit focused follow-up without rewriting its original seal or inheriting old runtime receipts',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n')
  const before=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,before);await validateFixtureFindings(f.config,before.id)
  const original=await loadScan(f.state,before.id),seal=original.seal,finding=original.findings[0]
  const follow=await createCandidateFollowup(f.root,f.config,original.id,finding.candidateId,'The owner requests focused current-source verification only.')
  assert.notEqual(follow.scanId,original.id);assert.equal((await loadScan(f.state,original.id)).seal,seal)
  const current=await loadScan(f.state,follow.scanId)
  assert.equal(current.followupOf?.scanId,original.id);assert.equal(current.findings.length,1);assert.equal(current.findings[0].validationRecord,undefined);assert.equal(current.findings[0].evidence.some(e=>e.kind==='runtime'),false)
  assert.equal(current.coverage.mode,'scoped_path');assert.ok(current.tasks.some(t=>t.phase==='validation'&&t.status==='pending'))
  await assert.rejects(()=>ingestModelCandidates(f.config,current.id,'fixture','worker',[{ruleId:'unrelated.issue'} as never],'dsh-llm'),/unrelated discovery/)
 }finally{await f.cleanup()}
})

test('Nested repository policy is frozen for assigned paths and does not bleed into sibling scope',async()=>{
 const f=await fixture();try{
  await mkdir(join(f.root,'module'));await mkdir(join(f.root,'sibling'))
  await writeFile(join(f.root,'SECURITY.md'),'Root policy marker.\n');await writeFile(join(f.root,'module/SECURITY.md'),'Module policy marker.\n');await writeFile(join(f.root,'sibling/SECURITY.md'),'Sibling policy marker.\n')
  await writeFile(join(f.root,'module/app.ts'),'export const safe=1;\n')
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan)
  const job=await createLlmDiscoveryJob(f.config,scan.id);job.lifecycle='running';job.baseline.status='running';job.baseline.assignment=job.baseline.regions!.filter(r=>r.path==='module/app.ts')
  await writeFile(join(f.state,'llm-discovery',`${job.id}.json`),JSON.stringify(job));await writeFile(join(f.root,'module/SECURITY.md'),'Changed after freeze.\n')
  const policy=await readLlmContext(f.config,job.id,job.baseline.id,job.baseline.token,'policy')
  assert.match(policy.content,/Module policy marker/);assert.match(policy.content,/Root policy marker/);assert.equal(policy.content.includes('Sibling policy marker'),false);assert.equal(policy.content.includes('Changed after freeze'),false)
 }finally{await f.cleanup()}
})

test('Prior verdicts become revalidation questions and corrupt history cannot poison a current scan',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n')
  const before=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,before);await validateFixtureFindings(f.config,before.id)
  await writeFile(join(f.state,'scans',`scan_${randomUUID()}.json`),'{invalid retained history')
  const current=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,current)
  const job=await createLlmDiscoveryJob(f.config,current.id),history=JSON.parse(job.priorContext!)
  assert.ok(history.records.some((r:any)=>r.currentSourceUnchanged===true));assert.ok(history.issues.length)
  assert.ok(job.packets.some(p=>p.id.startsWith('packet_prior_')));assert.ok(current.findings.every(f=>!f.validationRecord))
 }finally{await f.cleanup()}
})

test('Deep identities exclude volatile report provenance and unique source signatures survive line movement',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'export const safe=1;\n');const scan=await runScan(f.root,f.config,'deep','',false,f.state,false),a=structuredClone(scan),b=structuredClone(scan)
  const candidate={id:'stable-candidate',workerId:'worker_1_1',workerIds:['worker_1_1'],reportIds:['random-report-one'],fingerprint:'stable-control-fingerprint',ruleId:'fixture.control',title:'Finite source control',severity:'low' as const,cwe:'CWE-95',file:'app.ts',line:1,excerpt:'export const safe=1;',rootCause:'A finite fixture control is under review.',remediationSubsumption:{remediationIdentity:'Review the exact fixture control.',decision:'not_merged' as const,rationale:'Retained independently.',absorbedReportIds:[]},reportedAt:new Date().toISOString()}
  addCandidate(a,candidate);addCandidate(b,{...candidate,workerIds:['worker_3_2'],reportIds:['different-random-report']})
  assert.equal(a.findings[0].fingerprint,b.findings[0].fingerprint);assert.equal(a.findings[0].id,b.findings[0].id)
  b.findings[0].fingerprint='dsh-deep:new-location-key';b.findings[0].id='moved-finding';b.findings[0].locations[0].line=9;b.coverage.auditComplete=true
  assert.deepEqual(compareScans(a,b).persisting,['moved-finding']);assert.deepEqual(compareScans(a,b).resolved,[])
  b.findings=[];assert.deepEqual(compareScans(a,b).unknown,[a.findings[0].id]);assert.deepEqual(compareScans(a,b).resolved,[])
 }finally{await f.cleanup()}
})

test('Diff removal claims require the real frozen hunk and an explicit causal change explanation',async()=>{
 const f=await fixture();try{
  const git=async(args:string[])=>promisify(execFile)('git',['-c','core.hooksPath=/dev/null',...args],{cwd:f.root})
  await git(['init']);await git(['config','user.email','fixture@example.invalid']);await git(['config','user.name','Fixture'])
  await writeFile(join(f.root,'app.ts'),"function route(req) {\n if (!req.user) throw Error('denied');\n return eval(req.query.code);\n}\n")
  await git(['add','.']);await git(['commit','-m','guarded fixture']);await writeFile(join(f.root,'app.ts'),'function route(req) {\n return eval(req.query.code);\n}\n')
  const scan=await runDiffScan(f.root,undefined,'',f.state,false,'working_tree');await saveScan(f.state,scan)
  const input={ruleId:'fixture.removed-guard',title:'Removed guard reaches evaluator',cwe:'CWE-95',severity:'high' as const,confidence:'medium' as const,violatedInvariant:'The lower-trust caller must not reach the evaluator.',sourceToSink:'The exact removed guard no longer blocks the request expression.',impact:'Caller expression evaluation in the fixture.',remediation:'Enforce the invariant before evaluation.',counterevidence:'No replacement guard is visible in the finite patch.',locations:[{path:'app.ts',startLine:2,role:'root_control'}],evidence:[]}
  await assert.rejects(()=>ingestModelCandidates(f.config,scan.id,'fixture','worker',[input],'dsh-diff'),/change evidence/)
  const retained=await loadScan(f.state,scan.id),patch=await readArtifact(retained,retained.diffArtifact!.path),hunk=patch.split('\n').find(l=>l.startsWith('@@'))!
  await ingestModelCandidates(f.config,scan.id,'fixture','worker',[{...input,changeEvidence:{file:'app.ts',hunk,explanation:'The exact request-user rejection was removed, allowing request text to reach the unchanged evaluation operation.'}}],'dsh-diff')
  assert.ok((await loadScan(f.state,scan.id)).findings.some(f=>f.ruleId===input.ruleId&&f.changeEvidence?.patchSha256===retained.diffArtifact!.sha256))
 }finally{await f.cleanup()}
})

test('Reviewed repair uses versioned serialization, keeps a durable rollback and preserves file permissions',async()=>{
 const f=await fixture();try{
  const source='function route(req) { return eval(req.query.code) }\n';await writeFile(join(f.root,'app.ts'),source);await chmod(join(f.root,'app.ts'),0o640)
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan);await validateFixtureFindings(f.config,scan.id)
  const finding=(await loadScan(f.state,scan.id)).findings[0]
  const proposal=await proposeReviewedRemediation(f.root,f.config,scan.id,finding.id,{file:'app.ts',startLine:1,endLine:1,expectedText:source.trim(),replacementText:'function route(req) { return 0 }',rationale:'The finite fixture replacement removes dynamic evaluation for this protocol test.',testPlan:'Inspect the retained source and exact rollback bytes.'})
  await assert.rejects(()=>applyRemediationProposal(f.root,f.config,scan.id,proposal.id,true,999),/optimistic lock/)
  const results=await Promise.allSettled([applyRemediationProposal(f.root,f.config,scan.id,proposal.id,true,proposal.version),applyRemediationProposal(f.root,f.config,scan.id,proposal.id,true,proposal.version)])
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1)
  const applied=(results.find(r=>r.status==='fulfilled') as PromiseFulfilledResult<any>).value
  assert.ok(applied.rollbackId);assert.ok(applied.version>proposal.version!);assert.equal((await stat(join(f.root,'app.ts'))).mode&0o777,0o640)
  await rollbackRemediationProposal(f.root,f.config,scan.id,proposal.id,true,applied.version);assert.equal(await readFile(join(f.root,'app.ts'),'utf8'),source)
 }finally{await f.cleanup()}
})

test('Prepared rollback recovers a crash between durable intent and applied proposal persistence',async()=>{
 const f=await fixture();try{
  const before='function route(req) { return eval(req.query.code) }\n',after='function route(req) { return 0 }\n';await writeFile(join(f.root,'app.ts'),before)
  const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan);await validateFixtureFindings(f.config,scan.id)
  const finding=(await loadScan(f.state,scan.id)).findings[0],proposal=await proposeReviewedRemediation(f.root,f.config,scan.id,finding.id,{file:'app.ts',startLine:1,endLine:1,expectedText:before.trim(),replacementText:after.trim(),rationale:'The exact finite fixture changes only its evaluator operation.',testPlan:'Check source and restore the original bytes.'})
  const rollbackId=`rollback_${randomUUID()}`;proposal.rollbackId=rollbackId;proposal.version=2
  await mkdir(join(f.state,'remediation-rollbacks'),{recursive:true});await writeFile(join(f.state,'remediations',`${proposal.id}.json`),JSON.stringify(proposal))
  await writeFile(join(f.state,'remediation-rollbacks',`${rollbackId}.json`),JSON.stringify({id:rollbackId,remediationId:proposal.id,scanId:scan.id,file:'app.ts',beforeContent:before,beforeSha256:sha256(before),appliedSha256:sha256(after),appliedSnapshotDigest:'',createdAt:new Date().toISOString(),status:'prepared'}))
  await writeFile(join(f.root,'app.ts'),after)
  assert.equal((await rollbackRemediationProposal(f.root,f.config,scan.id,proposal.id,true,2)).status,'rolled_back')
  assert.equal(await readFile(join(f.root,'app.ts'),'utf8'),before)
  await writeFile(join(f.root,'app.ts'),'concurrent user edit\n');await assert.rejects(()=>replaceExpectedFile(join(f.root,'app.ts'),sha256(before),after),/changed/);assert.equal(await readFile(join(f.root,'app.ts'),'utf8'),'concurrent user edit\n')
 }finally{await f.cleanup()}
})

test('A clean coverage critic must read all pages of a large current check, not just its summary or final page',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'export const safe=1;\n');const scan=await runScan(f.root,f.config,'standard','',false,f.state,false);await saveScan(f.state,scan);await reviewFixtureCoverage(f.config,scan.id)
  const current=await loadScan(f.state,scan.id),unit=current.coverage.ledger![0];unit.checks[0].conclusion='Long exact source-backed fixture conclusion. '.repeat(1500);await saveScan(f.state,current)
  await withAuditActor({id:'fixture-large-critic',role:'coverage_critic'},async()=>{
   await readScanSource(f.config,scan.id,'app.ts');await observeCoveragePage(f.config,scan.id,current.coverage.ledger!.map(u=>u.id))
   const input={ledgerDigest:coverageDigest(current),reassignIds:[],missingUnits:[],rationale:'The finite source and all actual ledger evidence must be observed before a clean coverage assessment.'}
   await assert.rejects(()=>recordCoverageCritic(f.config,scan.id,input),/truncated/)
   const text=coverageUnitContext(unit),digest=sha256(text);await observeCoverageUnitContext(f.config,scan.id,unit.id,text.length-100,text.length,digest)
   await assert.rejects(()=>recordCoverageCritic(f.config,scan.id,input),/truncated/)
   for(let start=0;start<text.length;start+=8000){assert.ok(text.slice(start,start+8000));await observeCoverageUnitContext(f.config,scan.id,unit.id,start,Math.min(text.length,start+8000),digest)}
   await recordCoverageCritic(f.config,scan.id,input)
  })
 }finally{await f.cleanup()}
})

test('Incomplete frozen inventory stays Partial while independently established candidates remain available',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'function route(req) { return eval(req.query.code) }\n');await writeFile(join(f.root,'other.ts'),'export const extra=1;\n')
  const config={...f.config,maxFiles:1},runtime=nativeAuditFixture(config)
  const opened=await runLlmScan(runtime.ctx as never,config,f.root),job=await loadLlmDiscoveryJob(config,opened.jobId)
  assert.equal(llmSourceReportsComplete(job),true);assert.equal(job.lifecycle,'incomplete')
  const result=await closeAuditFindings(runtime.ctx as never,config,opened.scan.id)
  assert.equal(result.complete,false);assert.ok(result.scan.findings.some(f=>f.lifecycleState==='confirmed'))
  assert.equal(await closeCoverage(runtime.ctx as never,config,result.scan.id),false)
  assert.equal((await investigationStatus(config,result.scan.id)).inventoryNeedsFollowup,true)
 }finally{await f.cleanup()}
})

test('Reducer reads every bounded canonical page before closure and large evidence remains available in detail pages',async()=>{
 const f=await fixture();try{
  await writeFile(join(f.root,'app.ts'),'export const safe=1;\n');const scan=await runScan(f.root,f.config,'deep','',false,f.state,false);await saveScan(f.state,scan)
  const job=await createDeepDiscoveryJob(f.config,scan.id);job.lifecycle='running';job.workers=[{id:'worker_1_1',round:1,status:'completed',token:'worker',candidateIds:[]}];job.rounds=[{number:1,workerIds:['worker_1_1'],status:'complete',candidateCount:65,novelty:65}];job.reducers=[{id:'reducer_1',round:1,status:'running',token:'reducer',merges:[]}]
  job.candidates=Array.from({length:65},(_,i)=>({id:`candidate-${i}`,workerId:'worker_1_1',workerIds:['worker_1_1'],reportIds:[`report-${i}`],fingerprint:`fingerprint-${i}`,ruleId:'fixture.control',title:`Fixture ${i}`,severity:'low',cwe:'CWE-95',file:'app.ts',line:1,excerpt:'export const safe=1;',rootCause:'A source-backed fixture explanation. '.repeat(300),remediationSubsumption:{remediationIdentity:'Review the exact fixture control.',decision:'not_merged',rationale:'Independent fixture record.',absorbedReportIds:[]},reportedAt:new Date().toISOString()})) as typeof job.candidates
  await writeFile(join(f.state,'deep-discovery',`${job.id}.json`),JSON.stringify(job))
  await assert.rejects(()=>reportDeepReducer(f.config,job.id,'reducer_1','reducer',[]),/every canonical candidate page/)
  let offset=0,total=0;for(;;){const page=await getDeepReducerInput(f.config,job.id,'reducer_1','reducer',offset);assert.ok(Buffer.byteLength(JSON.stringify(page))<=24576);total+=(page.candidates as unknown[]).length;if(page.nextOffset===undefined)break;offset=page.nextOffset as number}
  assert.equal(total,65);assert.deepEqual(await reportDeepReducer(f.config,job.id,'reducer_1','reducer',[]),{merged:0,absorbed:0})
 }finally{await f.cleanup()}
})
