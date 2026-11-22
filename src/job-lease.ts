import { mkdir, open, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
/** 进程级任务租约：活跃 PID 不抢占；死进程可恢复，状态仍由各工作流检查。 */
export async function withJobLease<T>(state:string,id:string,run:()=>Promise<T>):Promise<T>{
  if(!/^[a-z]+_[0-9a-f-]+$/.test(id))throw new Error('Invalid job id.')
  const dir=join(state,'job-locks');await mkdir(dir,{recursive:true,mode:0o700})
  const path=join(dir,`${id}.lock`)
  let fd:Awaited<ReturnType<typeof open>>
  try{fd=await open(path,'wx',0o600)}catch(e){
    if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e
    // 恢复者也必须互斥，避免两个进程同时删除旧锁时误删刚创建的新锁。
    const recovery=path+'.recovery'
    try{await mkdir(recovery,{mode:0o700})}catch(err){if((err as NodeJS.ErrnoException).code==='EEXIST')throw new Error('Audit job recovery is already in progress; inspect an orphaned recovery lock before retrying.');throw err}
    try{
      const old=JSON.parse(await readFile(path,'utf8')) as {pid:number}
      if(!Number.isInteger(old.pid)||old.pid<=0)throw new Error('Audit job lease is malformed; inspect it before recovery.')
      let live=true;try{process.kill(old.pid,0)}catch(err){if((err as NodeJS.ErrnoException).code==='ESRCH')live=false}
      if(live)throw new Error('Audit job already has an active coordinator; resume only after it exits.')
      await rm(path);fd=await open(path,'wx',0o600)
    }finally{await rm(recovery,{recursive:true})}
  }
  try{await fd.writeFile(JSON.stringify({pid:process.pid,at:new Date().toISOString()}));return await run()}
  finally{await fd.close();await rm(path,{force:true})}
}
