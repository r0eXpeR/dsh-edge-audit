import { bindDiffEvidence, type ChangeEvidence } from './diff-evidence.js'
import { invalidateFindingEvidence } from './finding-revision.js'
import type { Finding, LocationRole } from './contracts.js'
import { currentAuditActor } from './audit-context.js'
import { assignFindingIdentity, sha256 } from './state.js'
import { mutateScan } from './scan-store.js'
import { resolveSnapshotLocations } from './source-evidence.js'

interface CandidateInput {changeEvidence?:ChangeEvidence;businessBoundary?:Finding['businessBoundary'];ruleId:string;title:string;cwe:string;severity:Finding['severity'];confidence:Finding['confidence'];violatedInvariant:string;sourceToSink:string;impact:string;remediation:string;counterevidence:string;locations:Array<{path:string;startLine:number;role?:string}>;evidence:Array<{location:{path:string;startLine:number;role?:string};explanation:string}>}
const roles=new Set(['entrypoint','wrapper','propagation','root_control','sink','outcome','expected_control'])
function role(value?:string):LocationRole { if(value && !roles.has(value))throw new Error('Unknown candidate location role.');return (value??'root_control') as LocationRole }
export async function ingestModelCandidates(config:{stateDir:string},scanId:string,jobId:string,workerId:string,inputs:CandidateInput[],prefix:'dsh-llm'|'dsh-diff'):Promise<void>{
  if(inputs.length>100||Buffer.byteLength(JSON.stringify(inputs))>524288)throw new Error('Candidate batches must stay within 100 entries and 512 KiB.')
  const actor=currentAuditActor()?.id ?? `${jobId}:${workerId}`
  await mutateScan(config,scanId,async scan=>{
    if(scan.lifecycle==='completed')throw new Error('Completed scans cannot accept candidates.')
    if(scan.followupOf&&inputs.length)throw new Error('Focused candidate follow-up cannot create unrelated discovery findings; record only coverage evidence for the retained candidate.')
    scan.findingIdentityVersion=2
    for(const value of inputs){
      const input={...value,evidence:value.evidence??[],cwe:value.cwe??''}
      if(!Array.isArray(input.locations)||!input.locations.length)throw new Error('Candidate requires concrete source locations.')
      if(input.locations.length>100||input.evidence.length>100||[input.title,input.violatedInvariant,input.sourceToSink,input.impact,input.remediation,input.counterevidence].some(v=>typeof v!=='string'||v.length>20000))throw new Error('Candidate evidence fields exceed their bounded contract.')
      const locations=await resolveSnapshotLocations(scan,input.locations.map(l=>({file:l.path,line:l.startLine,role:role(l.role)})))
      const evidenceLocations=input.evidence.length ? await resolveSnapshotLocations(scan,input.evidence.map(e=>({file:e.location.path,line:e.location.startLine,role:role(e.location.role)}))) : []
      const changeEvidence=await bindDiffEvidence(scan,locations,input.changeEvidence)
      const primary=locations.find(l=>l.role==='root_control'||l.role==='sink') ?? locations[0]
      const entryAnchors=locations.filter(l=>l.role==='entrypoint').map(l=>`${l.file}:${l.line}:${l.excerpt}`).sort().join('\n')
      const sinks=locations.filter(l=>l.role==='sink').map(l=>`${l.file}:${l.line}:${l.excerpt}`).sort().join('\n')
      const key=sha256(`${scan.targetSnapshot.targetId}:${input.ruleId}:${input.cwe}:${primary.file}:${primary.line}:${primary.excerpt}:${entryAnchors}:${sinks}`)
      const fingerprint=`${scan.mode==='diff'?'dsh-diff':prefix}:${key}`
      const existing=scan.findings.find(f=>f.fingerprint===fingerprint)
      if(existing){
        existing.discoveredBy=[...new Set([...(existing.discoveredBy??[]),actor])]
        existing.discoveryProvenance??=[]
        if(!existing.discoveryProvenance.some(p=>p.actorId===actor&&p.jobId===jobId&&p.workerId===workerId))existing.discoveryProvenance.push({actorId:actor,jobId,workerId,at:new Date().toISOString()})
        const extra=[...locations,...evidenceLocations].filter(l=>!existing.locations.some(p=>p.file===l.file&&p.line===l.line&&p.role===l.role))
        if(extra.length){
          existing.locations.push(...extra)
          if(existing.validationRecord||existing.attackPathRecord)invalidateFindingEvidence(scan,existing,'New source evidence expanded the candidate; independently revalidate the complete affected scope.')
        }
        continue
      }
      const candidateId=`cand_${key.slice(0,24)}`
      const finding:Finding={id:'',candidateId,fingerprint,changeEvidence,ruleId:input.ruleId,identity:{anchor:''},title:input.title,cwe:input.cwe??'',severity:input.severity,confidence:input.confidence,status:'open',disposition:'discovered',lifecycleState:'candidate',evidenceLevel:'source_backed',discoveredBy:[actor],discoveryProvenance:[{actorId:actor,jobId,workerId,at:new Date().toISOString()}],locations:[...locations,...evidenceLocations.filter(e=>!locations.some(l=>l.file===e.file&&l.line===e.line&&l.role===e.role))],rootCause:`${input.violatedInvariant}\n\n${input.sourceToSink}`,validation:'Independent validation pending; source-backed discovery is not confirmation.',attackPath:'Not established.',impact:input.impact,remediation:input.remediation,counterevidence:input.counterevidence,evidence:input.evidence.map((e,i)=>({kind:'context',detail:e.explanation,location:evidenceLocations[i]})),ledger:[{at:new Date().toISOString(),phase:'discovery',disposition:'discovered',summary:`${actor} reported a source-backed candidate. Independent validation pending.`}]}
      assignFindingIdentity(finding,scan.targetSnapshot.targetId,new Set(scan.findings.map(f=>`${f.ruleId}:${f.identity.anchor}:${f.identity.instance??''}`)))
      // 保留原 LLM 前缀以兼容历史消费者，但摘要已绑定实际控制和修复身份。
      finding.fingerprint=fingerprint;finding.id=`dsf_${sha256(fingerprint).slice(0,24)}`;finding.businessBoundary=input.businessBoundary
      scan.findings.push(finding);scan.tasks.push({id:`task_${sha256(`${scan.id}:${candidateId}:validation`).slice(0,24)}`,candidateId,phase:'validation',focus:`Independently disprove ${finding.title}: trace source, effective controls, sink and impact; retain exact proof gaps.`,status:'pending'})
    }
  })
}
