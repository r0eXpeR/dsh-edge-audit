import type { CoverageUnit } from './contracts.js'
import { redactValue } from './audit-context.js'
export function coverageUnitNeedsDetails(unit:CoverageUnit):boolean{
 return unit.reason.length>500||Buffer.byteLength(JSON.stringify({...unit,attempts:undefined}))>12000||unit.checks.some(c=>c.question.length>400||c.conclusion.length>1000||c.sourceReferences.length>3||c.limitations.some(l=>l.length>300))
}
export function coverageUnitContext(unit:CoverageUnit):string{return JSON.stringify(redactValue({...unit,attempts:undefined}))}
export function coverageUnitView(unit:CoverageUnit,ownActor?:string){
 const peer=!!ownActor&&unit.owner&&unit.owner!==ownActor
 const view={id:unit.id,path:unit.path,startLine:unit.startLine,endLine:unit.endLine,anchorLine:unit.anchorLine,anchorColumn:unit.anchorColumn,surface:unit.surface,attackClass:unit.attackClass,lifecycle:unit.lifecycle,boundary:unit.boundary.slice(0,500),sha256:unit.sha256,snapshotDigest:unit.snapshotDigest,status:unit.status,owner:unit.owner,
  reason:peer?'Review this assigned boundary independently; prior review text is retained by the coordinator.':unit.reason.slice(0,500),
  checks:peer?[]:unit.checks.slice(0,2).map(c=>({...c,question:c.question.slice(0,400),conclusion:c.conclusion.slice(0,1000),sourceReferences:c.sourceReferences.slice(0,3),limitations:c.limitations.slice(0,4).map(l=>l.slice(0,300))})),
  detailsTruncated:coverageUnitNeedsDetails(unit),detailsRef:{tool:'security_read_scan_context',kind:'coverage_unit',unit_id:unit.id}}
 if(Buffer.byteLength(JSON.stringify(view))>12000){view.checks=[];view.detailsTruncated=true}
 return view
}
