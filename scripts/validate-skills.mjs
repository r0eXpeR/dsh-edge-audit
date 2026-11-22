import { readFile, lstat } from 'node:fs/promises'
import { resolve, join } from 'node:path'
const root=resolve(import.meta.dirname,'../skills')
const catalog=JSON.parse(await readFile(join(root,'catalog.json'),'utf8'))
const names=new Set()
for(const entry of catalog){
  if(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.name)||names.has(entry.name))throw new Error('Invalid or duplicate packaged skill name.')
  names.add(entry.name)
  if(!entry.resources.includes('SKILL.md')||!entry.description.trim())throw new Error('Skill entrypoint or description missing.')
  for(const resource of entry.resources){
    if(resource.startsWith('/')||resource.split('/').some(p=>!p||p==='.'||p==='..'))throw new Error('Invalid packaged skill resource path.')
    const path=join(root,entry.name,resource),stat=await lstat(path)
    if(!stat.isFile()||stat.isSymbolicLink()||stat.size>65536)throw new Error('Invalid packaged skill asset.')
    const text=await readFile(path,'utf8')
    if(/TODO|\[INSERT|<placeholder>/i.test(text))throw new Error('Unfinished skill scaffold.')
    if(resource==='SKILL.md'&&(!text.startsWith(`---\nname: ${entry.name}\n`)||!text.includes(`description: ${entry.description}\n`)))throw new Error('Skill frontmatter differs from native catalog.')
    for(const match of text.matchAll(/\]\((references\/[^)#]+)(?:#[^)]*)?\)/g))if(!entry.resources.includes(match[1]))throw new Error(`Unlisted skill reference ${match[1]}`)
  }
}
console.log(`Validated ${catalog.length} packaged security skills and their declared resources.`)
