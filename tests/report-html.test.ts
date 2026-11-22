import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp,rm,writeFile,readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { renderHtmlReport } from '../src/report-html.ts'
import { runScan } from '../src/scanner.ts'
import { saveScan,loadScan,finalizeAndSaveScan,verifyScanBundle,regenerateScanProjections } from '../src/state.ts'
import { reviewFixtureCoverage,critiqueFixtureCoverage,validateFixtureFindings } from './coverage-fixture.ts'

test('offline report separates pending evidence, escapes hostile repository content and loads no external resources',async()=>{
 const root=await mkdtemp('/private/tmp/dsh-html-'),state=await mkdtemp('/private/tmp/dsh-html-state-')
 try{await writeFile(join(root,'app.ts'),'eval(req.query.code)\n');const scan=await runScan(root,{maxFiles:10,maxFileBytes:4096},'standard','',false,state)
 scan.findings[0].title='<img src=x onerror=alert(1)>';scan.findings[0].rootCause='</script><script>alert(1)</script>';const html=renderHtmlReport(scan)
 assert.match(html,/&lt;img/);assert.ok(!html.includes('<img src=x'));assert.ok(!html.includes('</script><script>alert(1)'))
 assert.match(html,/待验证/);assert.match(html,/Content-Security-Policy/);assert.doesNotMatch(html,/<script\s+src|<link\s+[^>]*https?:|<img\s+[^>]*https?:/i)
 assert.match(html,/没有.*|尚未|等待|未闭合/);assert.match(html,/data-kind="pending"/)
 }finally{await rm(root,{recursive:true,force:true});await rm(state,{recursive:true,force:true})}
})
test('HTML is a regeneratable same-source projection and does not invalidate sealed evidence',async()=>{
 const root=await mkdtemp('/private/tmp/dsh-html-'),state=await mkdtemp('/private/tmp/dsh-html-state-'),config={enabled:true,maxFiles:10,maxFileBytes:4096,stateDir:state}
 try{await writeFile(join(root,'app.ts'),'eval(req.query.code)\n');let scan=await runScan(root,config,'standard','',false,state);await saveScan(state,scan);await validateFixtureFindings(config,scan.id);await reviewFixtureCoverage(config,scan.id);await critiqueFixtureCoverage(config,scan.id);scan=await loadScan(state,scan.id);scan.lifecycle='completed';scan.completedAt=new Date().toISOString();await finalizeAndSaveScan(state,scan)
 assert.match(await readFile(join(scan.artifacts.directory,'report.html'),'utf8'),/独立静态确认/);assert.equal((await verifyScanBundle(await loadScan(state,scan.id))).valid,true)
 await regenerateScanProjections(scan);assert.equal((await verifyScanBundle(await loadScan(state,scan.id))).valid,true)
 }finally{await rm(root,{recursive:true,force:true});await rm(state,{recursive:true,force:true})}
})
