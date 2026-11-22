import { AsyncLocalStorage } from 'node:async_hooks'
import { withJobLease } from './job-lease.js'
const owned=new AsyncLocalStorage<ReadonlySet<string>>()

/** 同一扫描只有一个协调链；链内补漏/验证可重入，不阻塞其受限读取工具。 */
export async function withScanLease<T>(state:string,scanId:string,run:()=>Promise<T>):Promise<T>{
  const key=`${state}:${scanId}`,parent=owned.getStore()
  if(parent?.has(key))return run()
  return withJobLease(state,scanId,()=>owned.run(new Set([...(parent??[]),key]),run))
}
