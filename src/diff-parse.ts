/**
 * 统一 Diff 状态机。被审补丁是攻击者可控输入：hunk 内必须按 @@ 声明的行数计数，
 * 否则新增一行 `++ b/evil.ts` 就会被当成文件头，把后续改动藏起来或指向幽灵路径。
 */
export type DiffFileStatus='added'|'modified'|'deleted'|'renamed'
export interface DiffLine{kind:'+'|'-'|' ';text:string;oldLine?:number;newLine?:number}
export interface DiffHunk{header:string;oldStart:number;oldCount:number;newStart:number;newCount:number;lines:DiffLine[]}
export interface DiffFile{path:string;oldPath?:string;status:DiffFileStatus;binary:boolean;hunks:DiffHunk[];patch:string}

/** 还原 git 的 C 风格带引号路径（八进制转义的是 UTF-8 字节）。 */
export function unquoteGitPath(value:string):string{
 if(!value.startsWith('"')||!value.endsWith('"')||value.length<2)return value
 const bytes:number[]=[],body=value.slice(1,-1),simple:Record<string,number>={n:10,t:9,r:13,'"':34,'\\':92,a:7,b:8,f:12,v:11}
 for(let index=0;index<body.length;index++){
  if(body[index]!=='\\'){bytes.push(...Buffer.from(body[index]!,'utf8'));continue}
  const next=body[++index]!
  if(/[0-7]/.test(next)){bytes.push(Number.parseInt(body.slice(index,index+3),8));index+=2}
  else bytes.push(simple[next]??next.charCodeAt(0))
 }
 return Buffer.from(bytes).toString('utf8')
}

function headerPath(value:string):string|undefined{
 const clean=unquoteGitPath(value.replace(/\t.*$/,'').trim())
 if(clean==='/dev/null')return undefined
 return clean.replace(/^[ab]\//,'')
}

/** `diff --git a/x b/x` 里路径可含空格，只有两侧相同时才能无歧义还原。 */
function gitHeaderPath(line:string):string|undefined{
 const rest=line.slice('diff --git '.length)
 if(rest.startsWith('"')){const end=rest.indexOf('" ');if(end>0)return headerPath(rest.slice(0,end+1))}
 const middle=Math.floor((rest.length-1)/2)
 if(rest[middle]===' '&&rest.slice(2,middle)===rest.slice(middle+3))return rest.slice(2,middle)
 const match=/^a\/(.+?) b\/(.+)$/.exec(rest)
 return match?.[2]
}

export function parseUnifiedDiff(diff:string):DiffFile[]{
 const lines=diff.split('\n');if(lines.at(-1)==='')lines.pop()
 const files:DiffFile[]=[]
 let file:DiffFile|undefined,hunk:DiffHunk|undefined,start=0,oldLeft=0,newLeft=0,oldLine=0,newLine=0,from:string|undefined,to:string|undefined,sawTo=false,gitPath:string|undefined,status:DiffFileStatus='modified',binary=false
 const close=(end:number)=>{
  hunk=undefined
  if(!file)return
  file.patch=lines.slice(start,end).join('\n')+'\n'
  files.push(file);file=undefined
 }
 const open=(path:string|undefined,index:number,hunkFirst:boolean)=>{
  if(!path)return false
  const kind=!hunkFirst&&status==='modified'?(sawTo&&to===undefined?'deleted':from===undefined&&sawTo?'added':'modified'):status
  file={path,...(from!==undefined&&from!==path?{oldPath:from}:{}),status:kind,binary,hunks:[],patch:''};void index
  return true
 }
 for(let index=0;index<lines.length;index++){
  const raw=lines[index]!,line=raw.endsWith('\r')?raw.slice(0,-1):raw
  if(hunk&&(oldLeft>0||newLeft>0)){
   const mark=line[0]
   if(mark==='\\'){continue}
   if(mark==='+'){hunk.lines.push({kind:'+',text:line.slice(1),newLine});newLine++;newLeft--;continue}
   if(mark==='-'){hunk.lines.push({kind:'-',text:line.slice(1),oldLine});oldLine++;oldLeft--;continue}
   if(mark===' '||line===''){hunk.lines.push({kind:' ',text:line.slice(1),oldLine,newLine});oldLine++;newLine++;oldLeft--;newLeft--;continue}
   // 计数未走完就遇到别的内容：只可能是被截断，结束当前 hunk 再按头部解析。
   hunk=undefined;oldLeft=newLeft=0
  }
  if(line.startsWith('diff --git ')){
   close(index);start=index;from=to=undefined;sawTo=false;status='modified';binary=false;gitPath=gitHeaderPath(line)
   open(gitPath,index,false);continue
  }
  if(line.startsWith('\\'))continue
  if(line.startsWith('--- ')&&!hunk){from=headerPath(line.slice(4));if(file&&from!==undefined&&from!==file.path)file.oldPath=from;continue}
  if(line.startsWith('+++ ')&&!hunk){
   to=headerPath(line.slice(4));sawTo=true
   if(!file){open(to??from,index,false)}
   if(file){if(to)file.path=to;else{file.path=from??file.path;file.status='deleted';delete file.oldPath};if(from===undefined)file.status='added'}
   continue
  }
  if(!file&&!line.startsWith('@@'))continue
  const header=/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line)
  if(header&&file){
   oldLine=Number(header[1]);newLine=Number(header[3]);oldLeft=Number(header[2]??1);newLeft=Number(header[4]??1)
   hunk={header:line,oldStart:oldLine,oldCount:oldLeft,newStart:newLine,newCount:newLeft,lines:[]};file.hunks.push(hunk);continue
  }
  if(!file)continue
  if(line.startsWith('new file mode'))file.status='added'
  else if(line.startsWith('deleted file mode'))file.status='deleted'
  else if(line.startsWith('rename from '))file.oldPath=unquoteGitPath(line.slice(12))
  else if(line.startsWith('rename to ')){file.path=unquoteGitPath(line.slice(10));file.status='renamed'}
  else if(line.startsWith('copy to '))file.path=unquoteGitPath(line.slice(8))
  else if(line.startsWith('Binary files ')||line.startsWith('GIT binary patch'))file.binary=true
 }
 close(lines.length)
 return files
}

/** 依赖锁文件和压缩产物会吃光 1MB 上限，先从主补丁排除并如实记录。dist 不排除：可被用来藏恶意代码。 */
export const DEFAULT_DIFF_EXCLUDES=['package-lock.json','yarn.lock','pnpm-lock.yaml','bun.lockb','poetry.lock','Pipfile.lock','Cargo.lock','go.sum','composer.lock','Gemfile.lock','*.min.js','*.min.css','*.map']
export function diffExcludePathspecs(extra:string[]=[]):string[]{return [':/',...[...DEFAULT_DIFF_EXCLUDES,...extra].map(p=>`:(exclude,glob)${p.includes('/')?p:`**/${p}`}`)]}
export function isExcludedDiffPath(path:string,extra:string[]=[]):boolean{
 const name=path.split('/').at(-1)!
 return [...DEFAULT_DIFF_EXCLUDES,...extra].some(pattern=>{
  if(pattern.includes('/'))return path===pattern||(pattern.endsWith('/**')&&path.startsWith(pattern.slice(0,-2)))
  return pattern.startsWith('*.')?name.endsWith(pattern.slice(1)):name===pattern
 })
}
