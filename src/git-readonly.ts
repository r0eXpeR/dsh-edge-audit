import { execFile } from 'node:child_process'
import { lstat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { promisify } from 'node:util'
const exec=promisify(execFile)

/** 只读取元数据、不会接触工作树内容的命令，不需要中和驱动。 */
const METADATA_ONLY=new Set(['rev-parse','config','merge-base','ls-tree'])
/** 仓库本地配置中可以挂接外部命令的驱动键。 */
const DRIVER_KEY=/^(filter|diff|merge)\.(.+)\.(clean|smudge|process|command|textconv|driver)$/
const DRIVER_CACHE_TTL_MS=5_000
const driverCache=new Map<string,{expires:number;overrides:Promise<string[]>}>()

function hardenedEnv():NodeJS.ProcessEnv{
 const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('GIT_')))
 return Object.assign(env,{GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null',GIT_CONFIG_NOSYSTEM:'1',GIT_TERMINAL_PROMPT:'0'})
}

/**
 * 被审计仓库的 `.git/config`（含 include）可以定义 filter/diff/merge 驱动，配合
 * `.gitattributes` 后，`git diff HEAD`、`git status` 等工作树命令会执行其中的命令。
 * 读取配置本身不会执行任何命令，因此先枚举驱动名，再用空值逐一覆盖。
 */
async function driverOverrides(cwd:string,location:string[]):Promise<string[]>{
 const now=Date.now(),cached=driverCache.get(cwd)
 if(cached&&cached.expires>now)return cached.overrides
 const overrides=exec('git',[...location,'-c','safe.bareRepository=explicit','config','-z','--name-only','--get-regexp','^(filter|diff|merge)\\.'],{cwd,encoding:'utf8',env:hardenedEnv(),timeout:30_000,windowsHide:true,maxBuffer:1024*1024})
  .then(({stdout})=>stdout,(error:{code?:unknown;stdout?:unknown})=>{
   // 退出码 1 表示没有匹配项；其他错误交给后续真实命令报告。
   if(error.code===1)return ''
   return typeof error.stdout==='string'?error.stdout:''
  })
  .then(stdout=>{
   const values:string[]=[]
   for(const key of new Set(stdout.split('\0').map(item=>item.trim()).filter(Boolean))){
    const match=DRIVER_KEY.exec(key)
    if(!match)continue
    // `-c` 以第一个 `=` 分隔键值；含 `=` 或换行的驱动名无法安全覆盖，直接拒绝。
    if(/[=\n\r]/.test(match[2]!))throw new Error('Repository Git configuration declares a driver name that cannot be neutralized safely.')
    values.push('-c',`${key}=`)
    if(match[1]==='filter')values.push('-c',`filter.${match[2]}.required=false`)
   }
   return values
  })
 driverCache.set(cwd,{expires:now+DRIVER_CACHE_TTL_MS,overrides})
 overrides.catch(()=>driverCache.delete(cwd))
 return overrides
}

/**
 * 仓库配置可以用 `core.worktree` 把工作树指向任意宿主目录，此时 `git diff HEAD`
 * 会把宿主文件（例如 `~/.ssh/id_rsa`）与提交内容比较并输出。这里沿父目录找到
 * `.git`（目录或 gitfile），用命令行的 `--git-dir`/`--work-tree` 固定位置，
 * 命令行参数优先于仓库配置。找不到 `.git` 时不指定，由 safe.bareRepository 拒绝隐式裸仓库。
 */
async function repositoryLocation(cwd:string):Promise<string[]>{
 let current=resolve(cwd)
 while(true){
  const gitEntry=join(current,'.git')
  if(await lstat(gitEntry).then(()=>true,()=>false))return [`--git-dir=${gitEntry}`,`--work-tree=${current}`]
  const parent=dirname(current)
  if(parent===current)return []
  current=parent
 }
}

/** Git 元数据也是不可信输入：固定仓库位置，禁用 fsmonitor、Hooks、外部 diff、textconv 以及仓库本地 filter/diff/merge 驱动。 */
export async function readonlyGit(args:string[],options:{cwd:string;encoding:'utf8';maxBuffer?:number}){
 const command=args[0]!
 const location=await repositoryLocation(options.cwd)
 const neutralized=METADATA_ONLY.has(command)?[]:await driverOverrides(options.cwd,location)
 const safeArgs=['--no-pager',...location,'-c','safe.bareRepository=explicit','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-c','core.attributesFile=/dev/null','-c','diff.external=','-c','core.quotePath=false',...neutralized,command,...(['diff','diff-tree'].includes(command)?['--no-textconv','--no-ext-diff']:[]),...args.slice(1)]
 return exec('git',safeArgs,{...options,env:hardenedEnv(),timeout:30_000,windowsHide:true})
}
