// 脚本模型只验证协议与编排；不代表真实模型的漏洞发现能力。
import { runAuditTool } from '../src/audit-context.ts'
import { coverageDigest, observeCoveragePage, recordCoverageCheck, recordCoverageCritic } from '../src/coverage.ts'
import { getLlmScope, readLlmSource, reportLlmCandidates, reportLlmWorker } from '../src/llm/discovery.ts'
import { getDeepReducerInput, readScanSource, reportDeepReducer } from '../src/deep-discovery.ts'
import { attachEvidenceLocations, claimAuditTask, recordAttackPath, recordValidation } from '../src/workbench.ts'
import { loadScan } from '../src/state.ts'
import { fixturePolicyFacts } from './coverage-fixture.ts'
import type { Config } from '../src/config.ts'

export function nativeAuditFixture(config:Config,options:{reassignOnce?:boolean;failInvocation?:(workerId:string,invocation:number)=>boolean;candidate?:boolean;deferCandidate?:boolean}={}){
  const calls:Array<{kind:string;sessionId:string;workerId?:string;regions?:string[];scanId?:string}>=[]
  const invocations=new Map<string,number>()
  let reassigned=false,disposed=0
  const ctx={agents:{async create(opts:any){
    let prompt='',allowed:string[]=[]
    opts.setup?.({tools:{restrict(f:any){allowed=f.allow}},systemPrompt:{section(){}}})
    const sessionId=String(opts.sessionId),events:any[]=[]
    async function call<T>(name:string,args:Record<string,unknown>,action:()=>T):Promise<Awaited<T>>{
      events.push({type:'tool/call',data:{name}})
      return await runAuditTool(name,args,sessionId,action)
    }
    return {agent:{followup(m:any){prompt=m.content[0].text},session:{id:sessionId,deriveMessages:()=>[{role:'assistant',content:[{type:'text',text:'Finite fixture source review.'}]}],snapshotEvents:()=>events},async whenIdle(){
      events.push({type:'assistant/message',data:{usage:{inputTokens:100,outputTokens:25,cacheReadTokens:0,cacheWriteTokens:0}}})
      if(prompt.includes('independent coverage critic')){
        const scanId=/scan_id (scan_[0-9a-f-]+)/.exec(prompt)![1]
        calls.push({kind:prompt.includes('final_clean')?'final_critic':'critic',sessionId,scanId})
        const scan=await loadScan(config.stateDir,scanId)
        const citations=new Set((scan.coverage.ledger??[]).filter(u=>u.status==='reviewed').flatMap(u=>u.checks.flatMap(check=>check.sourceReferences.map(ref=>`${ref.file}:${ref.line}`))))
        for(const citation of citations){const split=citation.lastIndexOf(':'),path=citation.slice(0,split),line=Number(citation.slice(split+1));await call('security_read_scan_source',{scan_id:scanId},()=>readScanSource(config,scanId,path,line,line))}
        if(!citations.size&&scan.coverage.receipts[0])await call('security_read_scan_source',{scan_id:scanId},()=>readScanSource(config,scanId,scan.coverage.receipts[0].path,1,200))
        await call('security_get_coverage',{scan_id:scanId},()=>observeCoveragePage(config,scanId,(scan.coverage.ledger??[]).map(u=>u.id)))
        const reassign=options.reassignOnce&&!reassigned?(scan.coverage.ledger??[]).slice(0,1).map(u=>u.id):[]
        if(reassign.length)reassigned=true
        await call('security_report_coverage_critic',{scan_id:scanId},()=>recordCoverageCritic(config,scanId,{ledgerDigest:coverageDigest(scan),missingUnits:[],reassignIds:reassign,rationale:reassign.length?'The finite fixture requires one fresh independent rereview of this exact source-backed boundary.':'The finite fixture boundaries and their exact reviewed source evidence cover the declared local fixture scope.'}))
      }else if(allowed.includes('security_llm_get_scope')){
        const [,jobId,workerId,token]=/Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)!
        const invocation=(invocations.get(workerId)??0)+1;invocations.set(workerId,invocation)
        const scope=await call('security_llm_get_scope',{job_id:jobId,worker_id:workerId},()=>getLlmScope(config,jobId,workerId,token))
        calls.push({kind:'discovery',sessionId,workerId,regions:scope.assignedRegions?.map(r=>r.id),scanId:scope.scanId})
        if(options.failInvocation?.(workerId,invocation))throw new Error('Fixture interruption after preserved prior batches.')
        const regions=scope.assignedRegions??[]
        for(const region of regions)await call('security_llm_read_source',{job_id:jobId,worker_id:workerId},()=>readLlmSource(config,jobId,workerId,token,region.path,region.startLine,region.endLine))
        if(scope.workerKind==='architect'){
          await call('security_llm_report_worker',{job_id:jobId,worker_id:workerId},()=>reportLlmWorker(config,jobId,workerId,token,{findings:[],fullyReviewedFileCount:0,resolvedQuestions:['Representative architecture mapping is limited to the finite fixture.'],reviewedRegionIds:regions.map(r=>r.id),deferredRegions:[],architectureFacts:regions.map(r=>({statement:`The declared source region ${r.path}:${r.startLine}-${r.endLine} contains the finite fixture code; its callers and deployment require independent review.`,sourceReferences:[{file:r.path,line:r.startLine,role:'root_control' as const}]})),architectureLimitations:['Representative source mapping is not complete security coverage.']}))
          events.push({type:'turn/end',data:{reason:{kind:'completed'}}})
          return
        }
        const scan=await loadScan(config.stateDir,scope.scanId)
        for(const unit of scan.coverage.ledger??[]){
          if(!regions.some(r=>r.path===unit.path&&r.startLine<=unit.startLine&&r.endLine>=unit.endLine))continue
          if(scope.packet?.coverageUnitIds&&!scope.packet.coverageUnitIds.includes(unit.id))continue
          const text=await call('security_llm_read_source',{job_id:jobId,worker_id:workerId},()=>readLlmSource(config,jobId,workerId,token,unit.path,unit.startLine,unit.endLine))
          const offset=text.content.split('\n').findIndex(l=>l.trim())
          await call('security_record_coverage_check',{scan_id:scope.scanId,unit_id:unit.id},()=>recordCoverageCheck(config,scope.scanId,{unitId:unit.id,status:'reviewed',question:`Does the finite fixture enforce its declared ${unit.boundary} boundary?`,conclusion:'The finite source fixture was inspected through its declared input, actual control, operation and lifecycle; no other target is asserted.',limitations:[],sourceReferences:[{file:unit.path,line:unit.anchorLine??unit.startLine+Math.max(0,offset),role:'root_control'}]}))
        }
        if(options.candidate&&regions.some(r=>r.path==='app.ts'&&r.startLine===1))await call('security_llm_report_candidates',{job_id:jobId,worker_id:workerId},()=>reportLlmCandidates(config,jobId,workerId,token,[{ruleId:'fixture.dynamic-code',title:'Fixture caller input reaches eval',summary:'The declared fixture caller supplies the evaluated expression.',cwe:'CWE-95',severity:'high',confidence:'medium',attacker:'Caller of the finite fixture function.',violatedInvariant:'Untrusted expressions must not execute in the fixture process.',sourceToSink:'req.query.code -> eval(req.query.code)',impact:'Expression execution in the fixture process.',remediation:'Replace evaluation with a fixed operation allowlist.',counterevidence:'No upstream guard exists in this finite fixture.',locations:[{path:'app.ts',startLine:1,role:'entrypoint'},{path:'app.ts',startLine:1,role:'root_control'},{path:'app.ts',startLine:1,role:'sink'}],evidence:[]}]))
        await call('security_llm_report_worker',{job_id:jobId,worker_id:workerId},()=>reportLlmWorker(config,jobId,workerId,token,{findings:[],fullyReviewedFileCount:0,resolvedQuestions:['The assigned finite source regions were examined.'],reviewedRegionIds:regions.map(r=>r.id),deferredRegions:[]}))
      }else if(allowed.includes('security_deep_get_reducer_input')){
        const jobId=/job_id (deep_[0-9a-f-]+)/.exec(prompt)![1],reducerId=/reducer_id (reducer_\d+)/.exec(prompt)![1],token=/claim_token ([0-9a-f-]+)/.exec(prompt)![1]
        calls.push({kind:'reducer',sessionId})
        await call('security_deep_get_reducer_input',{job_id:jobId,reducer_id:reducerId},()=>getDeepReducerInput(config,jobId,reducerId,token))
        await call('security_deep_report_reducer',{job_id:jobId,reducer_id:reducerId},()=>reportDeepReducer(config,jobId,reducerId,token,[]))
      }else{
        const scanId=/scan_id (scan_[0-9a-f-]+)/.exec(prompt)![1],owner=/owner (closure_[a-z_]+_\d+_\d+)/.exec(prompt)![1]
        const phase=allowed.includes('security_record_validation')?'validation':'attack_path'
        calls.push({kind:phase,sessionId,scanId})
        for(;;){
          const task=await call('security_claim_audit_task',{scan_id:scanId,phase},()=>claimAuditTask(config,scanId,owner,phase))
          if(!task)break
          const scan=await loadScan(config.stateDir,scanId),finding=scan.findings.find(f=>f.candidateId===task.candidateId)!,root=finding.locations[0]
          await call('security_read_scan_source',{scan_id:scanId},()=>readScanSource(config,scanId,root.file,root.line,root.line))
          const refs=[{file:root.file,line:root.line,role:'entrypoint' as const},{file:root.file,line:root.line,role:'sink' as const}]
          await call('security_attach_evidence_locations',{scan_id:scanId},()=>attachEvidenceLocations(config,scanId,task.candidateId,task.claimToken,refs))
          const sourceReferences=(await loadScan(config.stateDir,scanId)).findings.find(f=>f.candidateId===task.candidateId)!.locations.map(l=>({file:l.file,line:l.line,role:l.role??'root_control'}))
          if(phase==='validation')await call('security_record_validation',{scan_id:scanId},()=>recordValidation(config,scanId,task.candidateId,{method:'static',conclusion:options.deferCandidate?'deferred':'reportable',proofGaps:options.deferCandidate?['The deployment route attachment is not established in this finite source.']:[],validationPlan:options.deferCandidate?{deployment:'The owner checks whether this exact fixture route is attached in the approved deployment without sending audit traffic.'}:undefined,attacker:'The finite fixture caller controls its request parameter.',entryPoint:'The declared fixture function receives req.query.code.',trustBoundary:'The fixture request expression crosses into evaluation.',rootControl:'The exact evaluated argument is retained in source.',sink:'The eval operation in the fixture.',impact:'Caller-controlled expression execution in the fixture.',directEvidence:'The exact source argument is read directly at the evaluation operation.',counterevidence:'No additional enforcing guard exists in the finite fixture.',limitations:'Static scripted fixture; no deployment or runtime exploit is asserted.',confidence:'medium',sourceReferences},task.claimToken))
          else await call('security_record_attack_path',{scan_id:scanId},()=>recordAttackPath(config,scanId,task.candidateId,{policyFacts:fixturePolicyFacts,attacker:'The declared fixture request caller.',entryPoint:'The source-backed request expression.',preconditions:'The fixture function is called with the declared request.',dataflow:'The request expression flows directly into eval in the same function.',outcome:'The fixture evaluates caller-supplied code.',severityRationale:'The finite fixture crosses its declared execution boundary.',changeConditions:'An effective upstream guard would require a different conclusion.',sourceReferences},task.claimToken))
        }
      }
      events.push({type:'turn/end',data:{reason:{kind:'completed'}}})
    }},async dispose(){disposed++}}
  }}}
  return {ctx,calls,disposed:()=>disposed}
}
