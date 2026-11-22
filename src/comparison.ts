import type { Finding,ScanRecord } from './contracts.js'
function semanticSignature(f:Finding){
 const primary=f.locations.find(l=>l.role==='root_control')??f.locations.find(l=>l.role==='sink')??f.locations[0]
 return JSON.stringify([f.cwe||f.ruleId,primary?.excerpt.replace(/\s+/g,' ').trim(),f.locations.filter(l=>l.role==='entrypoint'||l.role==='sink').map(l=>[l.role,l.excerpt.replace(/\s+/g,' ').trim()]).sort()])
}
function modelDerived(f:Finding){return /^dsh-(?:llm|deep|diff):/.test(f.fingerprint)||f.discoveredBy?.some(actor=>actor!=='deterministic-engine')||f.evidence.some(e=>/delegated.*worker/i.test(e.detail))}
/** 只有全量且包含该发现文件的后续审计才能证明消失；Diff、聚焦复核和缩小范围不行。 */
function scopeCovers(after:ScanRecord,f:Finding){
 if(after.mode==='diff'||after.followupOf)return false
 const files=new Set(after.coverage.receipts.map(r=>r.path))
 return f.locations.every(l=>files.has(l.file))
}
/** 命名空间/版本迁移或覆盖不足时，消失的候选只能 unknown，不能被解释为修复。 */
export function compareScans(before:ScanRecord,after:ScanRecord){
 const result={new:[] as string[],persisting:[] as string[],reopened:[] as string[],resolved:[] as string[],unknown:[] as string[]}
 if(before.targetSnapshot.targetId!==after.targetSnapshot.targetId){result.new=after.findings.map(f=>f.id);result.unknown=before.findings.map(f=>f.id);return result}
 const previous=new Map(before.findings.map(f=>[f.fingerprint,f])),current=new Map(after.findings.map(f=>[f.fingerprint,f]))
 const paired=new Set<string>(),matched=new Set<string>(),pair=(old:Finding,f:Finding)=>{paired.add(old.fingerprint);matched.add(f.fingerprint);if((old.status==='resolved'||old.status==='false_positive')&&f.status==='open')result.reopened.push(f.id);else result.persisting.push(f.id)}
 for(const f of current.values()){const old=previous.get(f.fingerprint);if(old)pair(old,f)}
 const unmatchedBefore=[...previous.values()].filter(f=>!paired.has(f.fingerprint)),unmatchedAfter=[...current.values()].filter(f=>!matched.has(f.fingerprint))
 // 只有唯一双向匹配才跨行移动/路径重命名；同形的独立实例不凭猜测合并。
 for(const f of unmatchedAfter){const key=semanticSignature(f),old=unmatchedBefore.filter(p=>semanticSignature(p)===key),peers=unmatchedAfter.filter(p=>semanticSignature(p)===key);if(old.length===1&&peers.length===1)pair(old[0],f);else result.new.push(f.id)}
 for(const f of previous.values())if(!paired.has(f.fingerprint))(!modelDerived(f)&&scopeCovers(after,f)&&![...current.values()].some(c=>semanticSignature(c)===semanticSignature(f))&&after.coverage.auditComplete===true&&(before.findingIdentityVersion??1)===(after.findingIdentityVersion??1)?result.resolved:result.unknown).push(f.id)
 return result
}
