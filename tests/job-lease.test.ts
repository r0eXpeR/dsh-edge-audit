import assert from 'node:assert/strict'
import test from 'node:test'
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {withJobLease} from '../src/job-lease.ts'

test('concurrent stale-job recovery never replaces a new live coordinator lease',async()=>{
 const state=await mkdtemp(join(tmpdir(),'dsh-lease-race-')),id='deep_1234-abcd',locks=join(state,'job-locks')
 try{
  await mkdir(locks)
  for(let round=0;round<10;round++){
   await writeFile(join(locks,id+'.lock'),JSON.stringify({pid:2147483647}))
   let active=0,maxActive=0,executions=0
   const run=()=>withJobLease(state,id,async()=>{assert.equal(JSON.parse(await readFile(join(locks,id+'.lock'),'utf8')).pid,process.pid);active++;executions++;maxActive=Math.max(active,maxActive);await new Promise(resolve=>setTimeout(resolve,20));active--})
   const results=await Promise.allSettled([run(),run(),run()])
   assert.equal(executions,1);assert.equal(maxActive,1);assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.deepEqual(await readdir(locks),[])
  }
 }finally{await rm(state,{recursive:true,force:true})}
})

test('malformed job lease fails closed and retains evidence instead of stealing ownership',async()=>{
 const state=await mkdtemp(join(tmpdir(),'dsh-lease-invalid-')),id='deep_1234-abcd',locks=join(state,'job-locks')
 try{await mkdir(locks);await writeFile(join(locks,id+'.lock'),JSON.stringify({pid:0}));let ran=false;await assert.rejects(withJobLease(state,id,async()=>{ran=true}),/malformed/);assert.equal(ran,false);assert.deepEqual(await readdir(locks),[id+'.lock'])}finally{await rm(state,{recursive:true,force:true})}
})
