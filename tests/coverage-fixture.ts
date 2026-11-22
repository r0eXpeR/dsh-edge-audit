export const fixturePolicyFacts={impact:'high',likelihood:'high',vector:'remote',authScope:'public',preconditions:'plausible',attackerInputControl:'yes',selfOnly:false,privilegedOnly:false,operatorOnly:false,developerOnly:false,physicalAccessOnly:false,unreachable:false,unrealisticPreconditions:false} as const
import { randomUUID } from 'node:crypto'
// 仅供协议回归：固定样本的脚本审阅/critic，不能作为真实模型效果证据。
import { withAuditActor } from '../src/audit-context.ts'
import { coverageDigest, observeCoveragePage, recordCoverageCheck, recordCoverageCritic } from '../src/coverage.ts'
import { readScanSource } from '../src/deep-discovery.ts'
import { loadScan } from '../src/state.ts'
export const testSandbox = process.env.DSH_TEST_SANDBOX_IMAGE && process.env.DSH_TEST_SANDBOX_EXECUTABLE ? {image:process.env.DSH_TEST_SANDBOX_IMAGE,executable:process.env.DSH_TEST_SANDBOX_EXECUTABLE} : undefined
export async function reviewFixtureCoverage(config:{stateDir:string},scanId:string,owner='fixture-reviewer'){
  await withAuditActor({id:owner,role:'reviewer',scanId},async()=>{
    const scan=await loadScan(config.stateDir,scanId)
    for(const unit of scan.coverage.ledger??[]){
      const source=await readScanSource(config as never,scanId,unit.path,unit.startLine,unit.endLine)
      const lines=source.content.split(/\r?\n/),index=lines.findIndex(l=>l.trim())
      if(index<0)continue
      await recordCoverageCheck(config,scanId,{unitId:unit.id,status:'reviewed',question:`Does the scripted fixture exercise boundary ${unit.boundary}?`,conclusion:'Fixed regression fixture inspected for its declared source-to-operation path; no additional fixture scope is claimed.',sourceReferences:[{file:unit.path,line:unit.anchorLine??unit.startLine+index,role:'root_control'}],limitations:[]})
    }
  })
}
export async function critiqueFixtureCoverage(config:{stateDir:string},scanId:string,stage='post_wave'){
  return withAuditActor({id:`fixture-critic-${scanId}-${randomUUID()}`,phase:stage,role:'coverage_critic',scanId},async()=>{
    const scan=await loadScan(config.stateDir,scanId)
    const citations=new Set((scan.coverage.ledger??[]).filter(u=>u.status==='reviewed').flatMap(u=>u.checks.flatMap(check=>check.sourceReferences.map(ref=>`${ref.file}:${ref.line}`))))
    for(const citation of citations){const split=citation.lastIndexOf(':'),path=citation.slice(0,split),line=Number(citation.slice(split+1));await readScanSource(config as never,scanId,path,line,line)}
    if(!citations.size&&scan.coverage.receipts[0])await readScanSource(config as never,scanId,scan.coverage.receipts[0].path,1,200)
    await observeCoveragePage(config,scanId,(scan.coverage.ledger??[]).map(u=>u.id))
    await recordCoverageCritic(config,scanId,{ledgerDigest:coverageDigest(scan),reassignIds:[],missingUnits:[],rationale:'The scripted fixture coverage is checked against its explicit finite test scope; this is protocol evidence, not a model security audit.'})
  })
}
export async function handleFixtureCritic(config:{stateDir:string},prompt:string){
  if(!prompt.includes('independent coverage critic'))return false
  const scanId=/scan_id (scan_[0-9a-f-]+)/.exec(prompt)?.[1]
  if(!scanId)throw new Error('Critic prompt omitted scan id.')
  await critiqueFixtureCoverage(config,scanId,prompt.includes('Critic stage: final_clean')?'final_clean':'post_wave');return true
}
export async function attachFixtureEndpoints(config:{stateDir:string},scanId:string,candidateId:string,token:string){
 const scan=await loadScan(config.stateDir,scanId),finding=scan.findings.find(f=>f.candidateId===candidateId)!
 const root=finding.locations[0]
 const refs=[{file:root.file,line:root.line,role:'entrypoint' as const},{file:root.file,line:root.line,role:'sink' as const}]
 await (await import('../src/workbench.ts')).attachEvidenceLocations(config as never,scanId,candidateId,token,refs)
 const current=await loadScan(config.stateDir,scanId),task=current.tasks.find(t=>t.candidateId===candidateId&&t.status==='claimed'&&t.claim?.token===token),record=current.findings.find(f=>f.candidateId===candidateId)!
 if(task?.phase==='attack_path'&&record.validationRecord&&['runtime','hybrid','test'].includes(record.validationRecord.method)){
  const refs=record.validationRecord.method==='test'?record.evidence.filter(e=>e.kind==='test'&&e.artifactRef).map(e=>e.artifactRef!):record.validationRecord.runtimeReceiptRefs??[]
  for(const ref of refs){let offset=0;for(;;){const page=await (await import('../src/candidate-artifact.ts')).readCandidateArtifact(config as never,scanId,candidateId,ref,offset,task.claim!.owner);if(page.nextOffset===undefined)break;offset=page.nextOffset}}
 }
 return (await loadScan(config.stateDir,scanId)).findings.find(f=>f.candidateId===candidateId)!.locations.map(l=>({file:l.file,line:l.line,role:l.role??'root_control'}))
}

export async function validateFixtureFindings(config:{stateDir:string},scanId:string){
 const bench=await import('../src/workbench.ts')
 for(const phase of ['validation','attack_path'] as const)while(true){
  const claim=await bench.claimAuditTask(config as never,scanId,`fixture-independent-${phase}`,phase);if(!claim)break
  const refs=await attachFixtureEndpoints(config,scanId,claim.candidateId,claim.claimToken)
  if(phase==='validation')await bench.recordValidation(config as never,scanId,claim.candidateId,{conclusion:'reportable',method:'static',attacker:'The caller controls data crossing the fixed fixture boundary.',entryPoint:'The fixed fixture exposes the declared caller operation.',trustBoundary:'Untrusted input or server response crosses the declared sensitive control.',rootControl:'The exact control and operation are retained in frozen source.',sink:'The operation under examination in this finite fixture.',impact:'The declared fixture security boundary is bypassed.',directEvidence:'The exact finite source fixture was reopened and its invariant inspected.',counterevidence:'The fixture has no additional enforcing upstream layer.',limitations:'Static scripted fixture protocol; no real model or deployment result is claimed.',confidence:'medium',sourceReferences:refs},claim.claimToken)
  else await bench.recordAttackPath(config as never,scanId,claim.candidateId,{ policyFacts:fixturePolicyFacts,attacker:'A caller at the documented fixture boundary.',entryPoint:'The source-backed fixture input.',preconditions:'Only the finite declared fixture context is asserted.',dataflow:'The fixture caller reaches the retained operation across its declared control boundary.',outcome:'The fixture invariant is violated at the declared operation.',severityRationale:'Severity is limited to this fixture path and its documented control.',changeConditions:'An additional enforcing layer would require a different conclusion.',sourceReferences:refs},claim.claimToken)
 }
}
