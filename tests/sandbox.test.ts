import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSandboxedCommand } from '../src/sandbox.ts'
import { testSandbox } from './coverage-fixture.ts'

test('failed sandbox image preflight cleans its temporary configuration', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'dsh-sandbox-preflight-'))
  const previous = process.env.TMPDIR
  process.env.TMPDIR = scratch
  try {
    const config = {
      enabled: true, maxFiles: 10, maxFileBytes: 4096, stateDir: '',
      validationSandbox: { executable: '/usr/bin/true', image: `sha256:${'a'.repeat(64)}` },
    }
    await assert.rejects(runSandboxedCommand(config, scratch, [], 1000), /sandbox unavailable/)
    assert.deepEqual(await readdir(scratch), [])
  } finally {
    if (previous === undefined) delete process.env.TMPDIR
    else process.env.TMPDIR = previous
    await rm(scratch, { recursive: true, force: true })
  }
})

test('Offline validation sandbox blocks host writes and ambient credentials and exposes only isolated loopback', {skip:!testSandbox?'Explicit pinned local Docker toolchain required.':false},async()=>{
 const directory=await mkdtemp('/private/tmp/dsh-sandbox-proof-')
 try{
  const content=`const fs=require('fs'),os=require('os');const report={};for(const path of ['/source/probe.js','/blocked-host-write']){try{fs.writeFileSync(path,'changed');report[path]='writable'}catch(e){report[path]=e.code}}report.ambientSecret=process.env.DSH_TEST_AMBIENT_SECRET===undefined;report.interfaces=Object.keys(os.networkInterfaces());report.home=process.env.HOME;console.log(JSON.stringify(report));`
  await writeFile(join(directory,'probe.js'),content)
  process.env.DSH_TEST_AMBIENT_SECRET='synthetic-secret-must-not-enter-container'
  const result=await runSandboxedCommand({enabled:true,maxFiles:10,maxFileBytes:4096,stateDir:'',validationSandbox:testSandbox},directory,['node','probe.js'],10000)
  delete process.env.DSH_TEST_AMBIENT_SECRET
  assert.equal(result.exitCode,0,result.stderr);const proof=JSON.parse(result.stdout)
  assert.notEqual(proof['/source/probe.js'],'writable');assert.notEqual(proof['/blocked-host-write'],'writable');assert.equal(proof.ambientSecret,true);assert.deepEqual(proof.interfaces,['lo']);assert.equal(proof.home,'/scratch/home')
  assert.equal(await readFile(join(directory,'probe.js'),'utf8'),content)
 }finally{delete process.env.DSH_TEST_AMBIENT_SECRET;await rm(directory,{recursive:true,force:true})}
})
