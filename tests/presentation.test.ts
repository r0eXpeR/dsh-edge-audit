import assert from 'node:assert/strict'
import test from 'node:test'
import { securityPresentCall,securityPresentResult,securityPresentationMeta } from '../src/presentation.ts'

test('native tool presenters omit credentials and preserve machine-readable stage distinctions',()=>{
 const call=securityPresentCall('security_scan',{path:'api',token:'synthetic-private-token',approved:true})
 assert.equal(call?.card,'generic');assert.ok(!JSON.stringify(call).includes('synthetic-private-token'))
 const meta=securityPresentationMeta('security_scan',{scanId:'scan-fixture',findings:8,confirmedFindings:2,pendingCandidates:3,complete:false,lifecycle:'validation'})
 const view=securityPresentResult('security_scan',{}, {isError:false,content:[{type:'text',text:'{"machine":"unchanged"}'}],meta})
 assert.equal(view?.card,'generic');assert.match(JSON.stringify(view),/审计未完成/);assert.match(JSON.stringify(view),/确认 2/)
 const phase=securityPresentResult('security_start_deep_closure',{}, {isError:false,content:[],meta:securityPresentationMeta('security_start_deep_closure',{lifecycle:'completed',phase:'validation'})})
 assert.doesNotMatch(JSON.stringify(phase),/审计流程已完成/)
})
test('large source and hypotheses do not get duplicated into presentation metadata',()=>{
 const value={id:'job-fixture',findings:[{title:'candidate',rootCause:'x'.repeat(50000)}],content:'y'.repeat(50000),token:'synthetic-secret'}
 const meta=JSON.stringify(securityPresentationMeta('security_get_scan',value));assert.ok(meta.length<1000);assert.ok(!meta.includes('synthetic-secret'))
 const read=securityPresentResult('security_read_scan_source',{}, {isError:false,content:[{type:'text',text:'eval(req.query.code)'}],meta:securityPresentationMeta('security_read_scan_source',{path:'app.ts',startLine:7,endLine:7,sha256:'abc'})})
 assert.match(JSON.stringify(read),/7–7/)
})
test('failed and cancelled work is actionable but never represented as complete',()=>{
 const error=securityPresentResult('security_scan',{}, {isError:true,content:[{type:'text',text:'tool call aborted'}]})
 assert.match(JSON.stringify(error),/已中断/);assert.doesNotMatch(JSON.stringify(error),/审计流程已完成/)
 assert.doesNotThrow(()=>securityPresentCall('security_scan',null))
})

test('malformed pending arguments cannot smuggle credentials through normally safe fields',()=>{
 const view=securityPresentCall('security_import_ticket_findings',{path:{token:'nested-secret'},job_id:{token:'another-secret'},token:'direct-secret'})
 assert.ok(!JSON.stringify(view).includes('secret'));assert.equal(view?.card,'generic')
})
