import { collectSourceStructure, type SourceFact } from './source-structure.js'
import { dirname, posix } from 'node:path'
import type { ScanRecord } from './contracts.js'
import type { LlmPacket } from './llm/discovery.js'
import { readFrozenSource } from './source-evidence.js'
import { sha256, writeArtifact } from './state.js'

export interface ReviewRegion { id:string; path:string; startLine:number; endLine:number; sha256:string }
export type BoundaryFact = SourceFact
export interface InvestigationMap { schemaVersion:1; snapshotDigest:string; limitations:string[]; facts:BoundaryFact[]; links:Array<{from:string;to:string;line:number;kind:'local_import'}>; regions:ReviewRegion[]; packets:LlmPacket[] }

function resolveLocalImport(file:string,specifier:string,known:Set<string>):string|undefined{
  const baseDir=dirname(file)
  let base:string
  if(file.endsWith('.py')){
    const prefix=/^\.+/.exec(specifier)?.[0]??''
    if(prefix){let parent=baseDir;for(let index=1;index<prefix.length;index++)parent=dirname(parent);base=posix.normalize(posix.join(parent,specifier.slice(prefix.length).replace(/\./g,'/')))}
    else base=specifier.replace(/\./g,'/')
    const candidates=[`${base}.py`,`${base}/__init__.py`]
    const matches=[...known].filter(path=>candidates.some(candidate=>path===candidate||path.endsWith(`/${candidate}`)))
    return matches.length===1?matches[0]:undefined
  }
  if(file.endsWith('.java')){
    const candidate=`${specifier.replace(/\./g,'/')}.java`
    const matches=[...known].filter(path=>path===candidate||path.endsWith(`/${candidate}`))
    return matches.length===1?matches[0]:undefined
  }
  if(!specifier.startsWith('.')&&!/\.(?:php|phtml|php5|inc)$/.test(file))return
  base=posix.normalize(posix.join(baseDir,specifier))
  const candidates=[base,...['.ts','.tsx','.js','.jsx','.py','.php','.phtml','.php5','.inc','.rs','/index.ts','/index.js','/mod.rs'].map(ext=>base+ext),base.replace(/\.js$/,'.ts')]
  return candidates.find(candidate=>known.has(candidate))
}

/** 仅把真实源码中可定位的语法关系当作线索；导入关系不是可达性证明。 */
export async function buildInvestigationMap(scan:ScanRecord, batchRegions=6):Promise<InvestigationMap>{
  const sources=new Map<string,string>()
  for(const receipt of scan.coverage.receipts) sources.set(receipt.path,await readFrozenSource(scan.evidenceRoot??scan.target,receipt))
  const facts:BoundaryFact[]=[],regions:ReviewRegion[]=[],limitations:string[]=[],links:InvestigationMap['links']=[]
  const known=new Set(sources.keys())
  for(const receipt of scan.coverage.receipts){
    const lines=sources.get(receipt.path)!.split(/\r?\n/);if(lines.length>1&&lines.at(-1)==='')lines.pop()
    for(let start=1;start<=Math.max(1,lines.length);start+=200){const end=Math.min(start+199,Math.max(1,lines.length));regions.push({id:`review_${sha256(`${receipt.path}:${receipt.sourceSha256??receipt.sha256}:${start}:${end}`).slice(0,24)}`,path:receipt.path,startLine:start,endLine:end,sha256:receipt.sourceSha256??receipt.sha256})}
    const structure=collectSourceStructure(receipt.path,sources.get(receipt.path)!)
    facts.push(...structure.facts);limitations.push(...structure.limitations)
    for(const item of structure.imports){
      const to=resolveLocalImport(receipt.path,item.specifier,known)
      if(to&&to!==receipt.path)links.push({from:receipt.path,to,line:item.line,kind:'local_import'})
    }
  }
  const packets:LlmPacket[]=[],size=Math.max(1,Math.min(32,Math.floor(batchRegions)))
  const ordered=[...regions].sort((a,b)=>Number(facts.some(f=>f.file===b.path&&f.kind==='entrypoint'))-Number(facts.some(f=>f.file===a.path&&f.kind==='entrypoint'))||a.path.localeCompare(b.path)||a.startLine-b.startLine)
  for(let offset=0;offset<ordered.length;offset+=size){
    const assigned=ordered.slice(offset,offset+size),paths=[...new Set(assigned.map(r=>r.path))],local=facts.filter(f=>assigned.some(r=>r.path===f.file&&f.line>=r.startLine&&f.line<=r.endLine)),related=[...new Set(links.filter(l=>paths.includes(l.from)||paths.includes(l.to)).flatMap(l=>[l.from,l.to]))]
    packets.push({id:`packet_${packets.length+1}`,attacker:'Derive the concrete principal and input control from the cited entry points; exposure is unproven.',protectedAsset:'Derive the actual object/state protected by the cited controls and operations.',expectedControls:local.filter(f=>f.kind==='control').slice(0,12).map(f=>`${f.file}:${f.line} ${f.symbol}`),entryPoints:local.filter(f=>f.kind==='entrypoint').slice(0,12).map(f=>`${f.file}:${f.line}`),sensitiveOperations:local.filter(f=>f.kind==='sink').slice(0,12).map(f=>`${f.file}:${f.line} ${f.symbol}`),paths,regions:assigned,supportingPaths:related.filter(p=>!paths.includes(p)),sourceFacts:local.slice(0,60),questions:[`Trace the assigned regions through actual callers, controls and downstream operations; inspect related imports ${related.join(', ')||'(none resolved)'}. Import links are search leads, not execution edges.`,`Compare sibling guards and identity/object checks. Inspect these observed lifecycle branches: ${local.filter(f=>f.kind==='lifecycle').slice(0,8).map(f=>`${f.file}:${f.line}`).join(', ')||'derive from source'}. Preserve unknown deployment and reachability facts.`]})
  }
  const map:InvestigationMap={schemaVersion:1,snapshotDigest:scan.targetSnapshot.snapshotDigest,limitations,facts,links,regions:ordered,packets}
  await writeArtifact(scan,'artifacts/01_context/investigation-map.json',`${JSON.stringify(map,null,2)}\n`)
  return map
}

/** 检查点只接受真实读范围；搜索命中和文件计数不能代替读取。 */
export function observedRegion(scan:ScanRecord,actorId:string,region:ReviewRegion):boolean{
  const ranges=(scan.auditTrail??[]).filter(r=>r.actorId===actorId&&r.kind==='source_read'&&r.path===region.path&&r.sha256===region.sha256).sort((a,b)=>(a.startLine??0)-(b.startLine??0))
  let next=region.startLine
  for(const range of ranges){if((range.startLine??Infinity)>next)break;if((range.endLine??0)>=next)next=range.endLine!+1}
  return next>region.endLine
}
