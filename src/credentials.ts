import { AsyncLocalStorage } from 'node:async_hooks'
import type { Config } from './config.js'
const requests=new AsyncLocalStorage<AbortSignal|undefined>()
export function withRequestSignal<T>(signal:AbortSignal|undefined,run:()=>T):T{return requests.run(signal,run)}
function origin(value:string):string{
 const url=new URL(value)
 if(url.username||url.password)throw new Error('Provider URLs must not contain credentials.')
 if(url.protocol!=='https:' && !(url.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(url.hostname)))throw new Error('Credential-bearing requests require HTTPS or explicit isolated loopback.')
 return url.origin
}
export function resolveCredential(config:Config,input:{token?:string;credential_ref?:string},destination:string,optional?:false):string
export function resolveCredential(config:Config,input:{token?:string;credential_ref?:string},destination:string,optional:true):string|undefined
export function resolveCredential(config:Config,input:{token?:string;credential_ref?:string},destination:string,optional=false):string|undefined{
 if(input.credential_ref&&input.token)throw new Error('Use one credential reference or legacy inline token, not both.')
 if(input.credential_ref){
  const matches=(config.credentialRefs??[]).filter(row=>row.id===input.credential_ref)
  if(matches.length!==1)throw new Error('Credential reference is not uniquely configured for this profile.')
  const binding=matches[0],destinationOrigin=origin(destination)
  if(!binding.origins.some(allowed=>origin(allowed)===destinationOrigin))throw new Error('Credential reference is not authorized for the requested provider origin.')
  if(!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(binding.environment))throw new Error('Credential binding has an invalid environment name.')
  const secret=process.env[binding.environment]
  if(!secret?.trim())throw new Error('Configured credential is unavailable in the host environment; no secret was returned.')
  return secret
 }
 if(input.token?.trim()){origin(destination);return input.token}
 if(optional)return undefined
 throw new Error('Provide an explicitly configured credential_ref; legacy inline token remains supported for compatibility.')
}
/** 分页和回读不得把 Authorization 头交给响应中提供的第三方 URL。 */
export async function scopedFetch(url:string,init:RequestInit,expectedOrigin:string):Promise<Response>{
 if(origin(url)!==origin(expectedOrigin))throw new Error('Provider response attempted a cross-origin authenticated request; credentials were not forwarded.')
 const caller=init.signal??requests.getStore(),timeout=AbortSignal.timeout(20000),signal=caller?AbortSignal.any([caller,timeout]):timeout
 return fetch(url,{...init,redirect:'error',signal})
}
export function githubFetch(url:string,init:RequestInit):Promise<Response>{return scopedFetch(url,init,'https://api.github.com')}
export function providerFetch(endpoint:string,url:string,init:RequestInit):Promise<Response>{return scopedFetch(url,init,endpoint)}

/** 响应只消费一次；拒绝无限/超大响应，非 JSON 保留为数据而非再次读取失效 Body。 */
export async function readProviderValue(response:Response,maxBytes=4*1024*1024):Promise<unknown>{
 if(!response.body)return null
 const reader=response.body.getReader(),chunks:Uint8Array[]=[];let bytes=0
 try{while(true){const next=await reader.read();if(next.done)break;bytes+=next.value.byteLength;if(bytes>maxBytes){void reader.cancel().catch(()=>undefined);throw new Error('Provider response exceeds the bounded evidence input size; narrow the requested source.')}chunks.push(next.value)}}finally{reader.releaseLock()}
 const value=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))
 try{return JSON.parse(value)}catch{return value}
}
