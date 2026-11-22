import type { Config } from './config.js'
import { currentAuditActor,redactValue } from './audit-context.js'
import { getStateDir,loadScan,readArtifact,sha256 } from './state.js'
import { mutateScan } from './scan-store.js'
import type { Finding,ScanRecord } from './contracts.js'
export async function artifactContext(scan:ScanRecord,finding:Finding,reference:string){
 const allowed=[...finding.evidence.map(e=>e.artifactRef),...(finding.validationRecord?.runtimeReceiptRefs??[])].filter(Boolean)
 if(!allowed.includes(reference))throw new Error('Artifact is not bound to this candidate.')
 const raw=await readArtifact(scan,reference)
 if(Buffer.byteLength(raw)>1048576)throw new Error('Candidate artifact exceeds the bounded review limit; retain a smaller reviewed output receipt.')
 try{return JSON.stringify(redactValue(JSON.parse(raw)))}catch{return String(redactValue(raw))}
}
export async function readCandidateArtifact(config:Config,scanId:string,candidateId:string,reference:string,offset=0,libraryOwner?:string){
 const scan=await loadScan(getStateDir(config.stateDir),scanId),finding=scan.findings.find(f=>f.candidateId===candidateId),actor=currentAuditActor()
 if(!finding)throw new Error('Candidate not found.')
 if(actor&&['validator','attack_path'].includes(actor.role)&&!scan.tasks.some(t=>t.candidateId===candidateId&&t.status==='claimed'&&t.claim?.owner===actor.id))throw new Error('Candidate artifact requires the actual active task owner.')
 const value=await artifactContext(scan,finding,reference),start=Math.max(0,Math.floor(offset)),end=Math.min(value.length,start+8000),who=actor?.id??libraryOwner
 if(who)await mutateScan(config,scanId,s=>{if(s.lifecycle==='completed')return;s.auditTrail??=[];s.auditTrail.push({at:new Date().toISOString(),actorId:who,role:actor?.role??'reviewer',kind:'artifact_context_read',candidateId,artifactRef:reference,contextStart:start,contextEnd:end,contextSha256:sha256(value),summary:'Observed a candidate-bound retained execution artifact page.'})})
 return {artifactRef:reference,content:value.slice(start,end),sha256:sha256(value),totalCharacters:value.length,...(end<value.length?{nextOffset:end}:{})}
}
export async function requireExecutionArtifactReview(scan:ScanRecord,finding:Finding,reviewer:string){
 const validation=finding.validationRecord
 if(!validation||!['runtime','hybrid','test'].includes(validation.method))return
 const refs=validation.method==='test'?finding.evidence.filter(e=>e.kind==='test').map(e=>e.artifactRef).filter((r):r is string=>!!r):validation.runtimeReceiptRefs??[]
 for(const ref of refs){
  const value=await artifactContext(scan,finding,ref),digest=sha256(value),ranges=(scan.auditTrail??[]).filter(r=>r.kind==='artifact_context_read'&&r.actorId===reviewer&&r.candidateId===finding.candidateId&&r.artifactRef===ref&&r.contextSha256===digest).sort((a,b)=>(a.contextStart??0)-(b.contextStart??0))
  let next=0;for(const range of ranges){if((range.contextStart??Infinity)>next)break;next=Math.max(next,range.contextEnd??0)}
  if(next<value.length)throw new Error('Independent execution-backed attack-path review must read every retained candidate artifact page, not just a quoted output excerpt.')
 }
}
