import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { isAbsolute, join } from 'node:path'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import { redactSensitive } from './audit-context.js'
const exec = promisify(execFile)
export class SandboxUnavailableError extends Error { constructor(){super('OS-enforced validation sandbox unavailable: configure a trusted local Docker image pinned by sha256 and an absolute Docker executable. No target code was executed; continue static validation.')} }
export function requireValidationSandbox(config: Config): { executable: string; image: string; socket: string } {
  const value=config.validationSandbox
  if(!value || !isAbsolute(value.executable) || !/^sha256:[a-f0-9]{64}$/.test(value.image)) throw new SandboxUnavailableError()
  // 只接受绝对路径的本地 Unix socket，避免把验证流量指向远程 Docker 守护进程。
  const socket=value.socket||'/var/run/docker.sock'
  if(!isAbsolute(socket)||/[\s,;'"`$]/.test(socket)) throw new SandboxUnavailableError()
  return {...value,socket}
}
/** 只使用本地固定镜像。无公网、无凭据继承、宿主只读挂载、有界 tmpfs/CPU/内存/进程/文件及墙钟。 */
export async function runSandboxedCommand(config: Config, source: string, argv: string[], timeout: number, signal?: AbortSignal): Promise<{stdout:string;stderr:string;exitCode?:number;timedOut:boolean}> {
  const sandbox=requireValidationSandbox(config)
  if(source.includes(','))throw new Error('Sandbox source path contains an unsupported mount separator.')
  const dockerConfig=await mkdtemp(join(tmpdir(),'dsh-docker-empty-config-'))
  const env:NodeJS.ProcessEnv={PATH:'/usr/bin:/bin:/usr/local/bin',DOCKER_CONFIG:dockerConfig,DOCKER_HOST:`unix://${sandbox.socket}`,HOME:dockerConfig}
  const name=`dsh-validate-${randomUUID()}`
  const args=['run','--name',name,'--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--memory-swap','256m','--cpus','1','--ulimit','cpu=30:30','--ulimit','fsize=16777216:16777216','--ulimit','nofile=128:128','--user','65534:65534','--tmpfs','/scratch:rw,nosuid,nodev,size=134217728,mode=1777','--tmpfs','/tmp:rw,nosuid,nodev,size=16777216,mode=1777','--mount',`type=bind,src=${source},dst=/source,readonly`,'--env','HOME=/scratch/home','--env','TMPDIR=/tmp','--env','PATH=/usr/local/bin:/usr/bin:/bin','--env','CI=1','--entrypoint','/bin/sh',sandbox.image,'-c','mkdir -p /scratch/home /scratch/work && cp -R /source/. /scratch/work/ && cd /scratch/work && exec "$@"','dsh-validator',...argv]
  try {
    // 不继承调用者的 Docker 地址、配置或凭据。预检失败也要清理临时目录。
    const inspect = await exec(sandbox.executable, ['image','inspect','--format','{{.Id}}',sandbox.image], {env,timeout:10_000,maxBuffer:4096,signal})
    if (inspect.stdout.trim() !== sandbox.image) throw new SandboxUnavailableError()
    try {
      const result = await exec(sandbox.executable, args, {env,timeout,maxBuffer:256_000,encoding:'utf8',signal})
      return {stdout:redactSensitive(result.stdout),stderr:redactSensitive(result.stderr),exitCode:0,timedOut:false}
    } catch (error) {
      if (signal?.aborted) throw error
      const failure = error as {stdout?:string;stderr?:string;code?:number;killed?:boolean}
      return {stdout:redactSensitive(failure.stdout??''),stderr:redactSensitive(failure.stderr??''),exitCode:typeof failure.code==='number'?failure.code:undefined,timedOut:!!failure.killed}
    } finally {
      await exec(sandbox.executable, ['rm','--force',name], {env,timeout:10_000,maxBuffer:4096}).catch(()=>undefined)
    }
  } finally {
    await rm(dockerConfig, {recursive:true,force:true})
  }
}
