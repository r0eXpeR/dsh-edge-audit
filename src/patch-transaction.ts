import { lstat,readFile,writeFile,rename,rm } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { sha256 } from './state.js'
import { resolve } from 'node:path'
import { safeSourcePath } from './source-evidence.js'

export async function assertPatchPath(root:string,file:string):Promise<string>{
 const target=safeSourcePath(root,file);let current=resolve(root)
 if((await lstat(current)).isSymbolicLink())throw new Error('Patch root is a symbolic link.')
 for(const part of file.split('/')){current=resolve(current,part);if((await lstat(current)).isSymbolicLink())throw new Error('Patch paths refuse symbolic links.')}
 return target
}

/** 同目录原子替换，保留权限；提交前再次比对原字节，避免覆盖可观察到的用户编辑。 */
export async function replaceExpectedFile(path:string,expectedDigest:string,content:string):Promise<void>{
  const before=await lstat(path)
  if(!before.isFile()||before.isSymbolicLink())throw new Error('Patch target changed or is not a regular non-symlink file.')
  const raw=await readFile(path),text=raw.toString('utf8')
  // 字符串往返会把非 UTF-8 字节变成 U+FFFD，且回滚无法还原，因此直接拒绝。
  if(!Buffer.from(text,'utf8').equals(raw))throw new Error('Patch target is not valid UTF-8; mechanical replacement would corrupt its bytes.')
  if(sha256(text)!==expectedDigest)throw new Error('Patch target changed or is not a regular non-symlink file.')
  const temp=`${path}.dsh-${randomUUID()}.tmp`
  try{
    await writeFile(temp,content,{flag:'wx',mode:before.mode&0o777})
    const current=await lstat(path)
    if(!current.isFile()||current.isSymbolicLink()||current.ino!==before.ino||sha256(await readFile(path,'utf8'))!==expectedDigest)throw new Error('Patch target changed before atomic replacement; user edits were preserved.')
    await rename(temp,path)
  }finally{await rm(temp,{force:true})}
}
