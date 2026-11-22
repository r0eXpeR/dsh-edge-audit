import { readonlyGit } from './git-readonly.js'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, extname } from 'node:path'
import { safeSourcePath } from './source-evidence.js'
const exec=promisify(execFile)
/** 用 git 对象只读物化精确版本，不 checkout、不运行 Hooks、不覆盖工作树。 */
export async function materializeRevision(repository:string,revision:string,directory:string,requiredPaths:ReadonlySet<string>=new Set()):Promise<Array<{path:string;reason:string}>>{
  if(!/^[a-f0-9]{40,64}$/.test(revision))throw new Error('Git snapshot requires an immutable object id.')
  await mkdir(directory,{recursive:true,mode:0o700})
  const {stdout}=await readonlyGit(['ls-tree','-r','-l','-z','--full-tree',revision],{cwd:repository,encoding:'utf8',maxBuffer:4*1024*1024})
  const extensions=new Set(['.ts','.tsx','.js','.jsx','.mjs','.cjs','.go','.mod','.py','.php','.java','.cs','.rb','.rs','.c','.h','.cc','.cpp','.hpp','.json','.yaml','.yml','.toml','.xml','.md','.sh','.graphql','.proto','.vue'])
  const ignored=new Set(['.git','node_modules','vendor','dist','build','coverage']),omissions:Array<{path:string;reason:string}>=[]
  let count=0
  for(const entry of stdout.split('\0').filter(Boolean)){
    const split=entry.indexOf('\t'),header=entry.slice(0,split).trim().split(/\s+/),path=entry.slice(split+1)
    if(header[1]!=='blob')continue
    // 显式变更属于当前审计范围，不能被普通全仓库存的目录/扩展名默认值静默丢弃。
    if(!requiredPaths.has(path) && (path.split('/').some(part=>ignored.has(part)) || (!extensions.has(extname(path))&&!['Dockerfile','Makefile','Gemfile','requirements.txt'].includes(path.split('/').at(-1)!))))continue
    if(header[0]==='120000'){omissions.push({path,reason:'Revision symlink excluded; referent not trusted.'});continue}
    if(++count>10000||Number(header[3])>1048576){omissions.push({path,reason:'Revision source exceeds bounded inventory or file-size budget.'});continue}
    const destination=safeSourcePath(directory,path)
    const {stdout:content}=await readonlyGit(['show',`${revision}:${path}`],{cwd:repository,encoding:'utf8',maxBuffer:1048577})
    await mkdir(dirname(destination),{recursive:true});await writeFile(destination,content,{mode:0o400,flag:'wx'})
  }
  return omissions
}
