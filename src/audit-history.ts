import type { ScanRecord } from './contracts.js'
import { listScanSummaries,loadScan,sha256 } from './state.js'
import { redactValue } from './audit-context.js'

/** 历史仅提供可复核线索，绝不继承确认、覆盖或排除权限。当前 Deep 同波子审计不会互相泄漏结论。 */
export async function auditHistoryContext(state:string,current:ScanRecord,excludeRoot?:string){
 const issues:string[]=[]
 const summaries=(await listScanSummaries(state,issues)).filter(s=>s.id!==current.id&&s.id!==excludeRoot&&!s.parentScanId&&s.targetId===current.targetSnapshot.targetId&&s.discoveryLifecycle!=='running').slice(0,3)
 const records:Array<Record<string,unknown>>=[]
 const gaps:Array<Record<string,unknown>>=[]
 let omittedGaps=0
 for(const summary of summaries){
  if(summary.recordBytes>16*1024*1024){records.push({scanId:summary.id,limitation:'Historical record exceeds bounded recall size; no clean coverage or prior verdict is assumed.'});continue}
  let prior:ScanRecord;try{prior=await loadScan(state,summary.id)}catch{issues.push(`${summary.id}: source record unavailable or failed integrity checks.`);continue}
  if(prior.targetSnapshot.targetId!==current.targetSnapshot.targetId||prior.parentScanId||prior.discoveryStatus?.lifecycle==='running')continue
  for(const finding of prior.findings.filter(f=>f.validationRecord||f.triageDecisions?.length).slice(0,20)){
   const paths=[...new Set(finding.locations.map(l=>l.file))],unchanged=paths.every(path=>{const before=prior.coverage.receipts.find(r=>r.path===path),after=current.coverage.receipts.find(r=>r.path===path);return before&&after&&(before.sourceSha256??before.sha256)===(after.sourceSha256??after.sha256)})
   const primary=finding.locations.find(l=>l.role==='root_control')??finding.locations.find(l=>l.role==='sink')??finding.locations[0]
   const semanticSourceKey=sha256(JSON.stringify([finding.cwe,primary?.file,primary?.line,primary?.excerpt,finding.locations.filter(l=>l.role==='entrypoint'||l.role==='sink').map(l=>[l.role,l.file,l.line]).sort()]))
   records.push({semanticSourceKey,scanId:prior.id,fingerprint:finding.fingerprint,title:finding.title,ruleId:finding.ruleId,cwe:finding.cwe,paths,currentSourceUnchanged:unchanged,previousDisposition:finding.disposition,previousCounterevidence:finding.counterevidence.slice(0,1200),proofGaps:finding.validationRecord?.proofGaps??[],limitations:finding.validationRecord?.limitations,triage:finding.triageDecisions?.slice(-1),instruction:'Recheck this exact claim and prior reason against current source. Changed or unresolved evidence is current work, never an exclusion.'})
  }
  const priority=(status:string)=>({blocked:0,deferred:1,investigating:2,out_of_scope:3} as Record<string,number>)[status]??4
  for(const unit of [...(prior.coverage.ledger??[])].filter(u=>['blocked','deferred','investigating','out_of_scope'].includes(u.status)&&current.coverage.receipts.some(r=>r.path===u.path)).sort((a,b)=>priority(a.status)-priority(b.status))){
   const before=prior.coverage.receipts.find(r=>r.path===unit.path),after=current.coverage.receipts.find(r=>r.path===unit.path)
   if(!after||gaps.some(g=>g.path===unit.path&&g.startLine===unit.startLine&&g.surface===unit.surface&&g.attackClass===unit.attackClass&&g.boundary===unit.boundary))continue
   if(gaps.length>=24){omittedGaps++;continue}
   gaps.push({scanId:prior.id,unitId:unit.id,path:unit.path,startLine:unit.startLine,endLine:unit.endLine,surface:unit.surface,anchorLine:unit.anchorLine,anchorColumn:unit.anchorColumn,attackClass:unit.attackClass,boundary:unit.boundary,priorStatus:unit.status,priorReason:unit.reason.slice(0,600),currentSourceUnchanged:!!before&&(before.sourceSha256??before.sha256)===(after.sourceSha256??after.sha256),instruction:'Assign this unresolved boundary as current work; historical status does not close or exclude it.'})
  }
 }
 if(omittedGaps)issues.push(`${omittedGaps} additional prior unresolved coverage units exceeded the bounded history context; current coverage must be reviewed independently.`)
 return JSON.stringify(redactValue({records,gaps,issues,limitation:'Bounded prior-run evidence, not proof of current correctness. No prior confirmation or reviewed coverage is automatically carried.'}))
}
