import { createHash } from 'node:crypto'
/** 仅缓存纯确定性分析线索，绝不缓存审阅覆盖、确认或动态证据。 */
const values=new Map<string,{value:unknown;bytes:number}>();let retainedBytes=0;const maximumBytes=32*1024*1024
export function cachedAnalysis<T>(analyzerVersion:string,policy:string,inputs:unknown,compute:()=>T):T{
  const key=createHash('sha256').update(JSON.stringify({analyzerVersion,policy,model:'none/deterministic-only',inputs})).digest('hex')
  if(values.has(key)){const entry=values.get(key)!;values.delete(key);values.set(key,entry);return structuredClone(entry.value) as T}
  const result=compute(),bytes=Buffer.byteLength(JSON.stringify(result));if(bytes>maximumBytes)return result
  while(values.size>=128||retainedBytes+bytes>maximumBytes){const oldest=values.keys().next().value!;retainedBytes-=values.get(oldest)!.bytes;values.delete(oldest)}
  values.set(key,{value:structuredClone(result),bytes});retainedBytes+=bytes;return result
}
