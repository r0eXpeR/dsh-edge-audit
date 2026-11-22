import assert from 'node:assert/strict'
import test from 'node:test'
import { cp, mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { runSandboxedCommand } from '../src/sandbox.ts'
import { testSandbox } from './coverage-fixture.ts'

test('Runnable tenant boundary oracle proves cross-file object authorization failure and repair with dummy accounts', {skip:!testSandbox?'Explicit pinned local Docker toolchain required.':false},async()=>{
 const scratch=await mkdtemp('/private/tmp/dsh-tenant-oracle-'),results=[]
 try{
  for(const variant of ['vulnerable','fixed']){
   const source=join(scratch,variant);await cp(new URL(`./golden/tenant-runtime/${variant}`,import.meta.url),source,{recursive:true});await writeFile(join(source,'repro.mjs'),await readFile(new URL('./golden/tenant-runtime/repro.mjs',import.meta.url)))
   const result=await runSandboxedCommand({enabled:true,maxFiles:10,maxFileBytes:4096,stateDir:'',validationSandbox:testSandbox},source,['node','repro.mjs'],10000)
   assert.equal(result.exitCode,0,result.stderr);const observed=JSON.parse(result.stdout)
   assert.equal(observed.crossTenantVisible,variant==='vulnerable');assert.equal(observed.ownTenantStillWorks,true)
   results.push({variant,observed,command:'node repro.mjs',sandbox:'offline/read-only-host/non-root/resource-limited',durationMs:undefined})
  }
  await mkdir(new URL('../.artifacts/',import.meta.url),{recursive:true});await writeFile(new URL('../.artifacts/tenant-runtime-oracle.json',import.meta.url),JSON.stringify({kind:'runtime-ground-truth-oracle',results,limitation:'This verifies a known synthetic business vulnerability and repair. It is not autonomous model discovery or a validated-recall measurement.'},null,2)+'\n')
 }finally{await rm(scratch,{recursive:true,force:true})}
})
