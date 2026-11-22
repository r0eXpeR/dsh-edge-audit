import assert from 'node:assert/strict'
import test from 'node:test'
import { resolveCredential,scopedFetch,withRequestSignal } from '../src/credentials.ts'
import { securityPresentCall,securityPresentationMeta } from '../src/presentation.ts'
const config={enabled:true,maxFiles:10,maxFileBytes:4096,stateDir:'',credentialRefs:[{id:'github-test',environment:'DSH_SYNTHETIC_CREDENTIAL',origins:['https://api.github.com']}]}

test('opaque credential references read only explicit origin-bound host values',()=>{
 process.env.DSH_SYNTHETIC_CREDENTIAL='synthetic-only-not-a-real-key'
 try{assert.equal(resolveCredential(config,{credential_ref:'github-test'},'https://api.github.com/repos/example/repo'),process.env.DSH_SYNTHETIC_CREDENTIAL)
 assert.throws(()=>resolveCredential(config,{credential_ref:'github-test'},'https://attacker.invalid'),/not authorized/)
 assert.throws(()=>resolveCredential(config,{credential_ref:'unknown'},'https://api.github.com'),/not uniquely configured/)
 assert.throws(()=>resolveCredential(config,{credential_ref:'github-test',token:'x'},'https://api.github.com'),/not both/)
 assert.equal(resolveCredential(config,{},'https://api.github.com',true),undefined)
 }finally{delete process.env.DSH_SYNTHETIC_CREDENTIAL}
})
test('authenticated pagination or readback cannot forward credentials across origins',async()=>{
 let calls=0;const original=globalThis.fetch;globalThis.fetch=async()=>{calls++;return new Response('{}')}
 try{await assert.rejects(()=>scopedFetch('https://attacker.invalid/next',{headers:{authorization:'Bearer synthetic'}},'https://api.github.com'),/cross-origin/);assert.equal(calls,0)
 await scopedFetch('https://api.github.com/next',{headers:{authorization:'Bearer synthetic'}},'https://api.github.com');assert.equal(calls,1)
 }finally{globalThis.fetch=original}
})
test('provider requests are redirect-free, cancellable and bounded even outside model work',async()=>{
 const controller=new AbortController(),original=globalThis.fetch;let observed:RequestInit|undefined
 globalThis.fetch=async(_url,init)=>{observed=init;return new Response('{}')}
 try{await withRequestSignal(controller.signal,()=>scopedFetch('https://api.github.com/next',{},'https://api.github.com'));assert.equal(observed?.redirect,'error');assert.ok(observed?.signal);controller.abort();assert.equal(observed?.signal?.aborted,true)}finally{globalThis.fetch=original}
})
test('all native pending tool views omit token arguments, including previously generic provider tools',()=>{
 for(const name of ['security_import_github_findings','security_import_ticket_findings','security_tracking_preview']){const view=securityPresentCall(name,{token:'synthetic-secret-in-arguments',claim_token:'private-claim',credential_ref:'github-test'});assert.ok(view);assert.ok(!JSON.stringify(view).includes('synthetic-secret-in-arguments'));assert.ok(!JSON.stringify(view).includes('private-claim'))}
 assert.ok(!JSON.stringify(securityPresentationMeta('security_import_ticket_findings',{token:'synthetic-secret'})).includes('synthetic-secret'))
})

test('provider error text is read once and oversized evidence bodies are rejected',async()=>{
 const {readProviderValue}=await import('../src/credentials.ts')
 assert.equal(await readProviderValue(new Response('upstream returned text')),'upstream returned text')
 assert.deepEqual(await readProviderValue(new Response('{"safe":true}')),{safe:true})
 await assert.rejects(()=>readProviderValue(new Response('x'.repeat(500)),100),/exceeds the bounded/)
})
test('native credential references keep secret values outside canonical outputs and UI metadata',async()=>{
 const {Context}=await import('@deepseek-ai/cordis'),{SystemPrompt}=await import('@deepseek-ai/dsh-system-prompt'),{ToolRuntime}=await import('@deepseek-ai/dsh-tools'),plugin=await import('../src/index.ts')
 const ctx=new Context();new SystemPrompt(ctx,{});new ToolRuntime(ctx,{})
 process.env.DSH_SYNTHETIC_CREDENTIAL='synthetic-native-reference-only';const original=globalThis.fetch
 globalThis.fetch=async(_url,init)=>{assert.equal((init?.headers as Record<string,string>).authorization,'Bearer synthetic-native-reference-only');return new Response('[]',{headers:{'content-type':'application/json'}})}
 const fiber=await ctx.plugin({name:plugin.name,inject:plugin.inject,apply:plugin.apply},config)
 try{const result=await ctx.tools.execute({callId:'opaque-reference' as never,signal:new AbortController().signal,name:'security_import_github_findings',arguments:{repository:'example/repo',source:'code_scanning',credential_ref:'github-test'}});assert.equal(result.isError,false,result.isError?result.error.message:'');assert.ok(!JSON.stringify(result).includes('synthetic-native-reference-only'))}
 finally{await fiber.dispose();globalThis.fetch=original;delete process.env.DSH_SYNTHETIC_CREDENTIAL}
})
