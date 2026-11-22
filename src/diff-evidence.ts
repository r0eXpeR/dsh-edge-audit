import type { Location, ScanRecord } from './contracts.js'
import { readArtifact,sha256 } from './state.js'
import { parseUnifiedDiff } from './diff-parse.js'
export interface ChangeEvidence {file:string;hunk:string;explanation:string}
/** 删除控制等未落在新增行的候选，必须关联冻结补丁的真实 hunk，不能偷换成旧问题。 */
export async function bindDiffEvidence(scan:ScanRecord,locations:Location[],change?:ChangeEvidence){
 if(scan.mode!=='diff')return
 if(locations.some(l=>scan.coverage.changedLines?.[l.file]?.includes(l.line)))return change?{...change,patchSha256:scan.diffArtifact?.sha256}:undefined
 if(!change||change.explanation.trim().length<40||!scan.diffArtifact)throw new Error('An unchanged-line Diff candidate requires explicit snapshot-bound change evidence, not an unrelated existing issue.')
 const patch=await readArtifact(scan,scan.diffArtifact.path)
 if(sha256(patch)!==scan.diffArtifact.sha256)throw new Error('Frozen Diff patch changed after inventory.')
 let matched=false
 for(const hunk of parseUnifiedDiff(patch).find(file=>file.path===change.file)?.hunks??[]){
  if(hunk.header.trim()!==change.hunk.trim()||!hunk.lines.some(line=>line.kind==='-'))continue
  const start=Math.max(1,hunk.newStart)
  if(locations.some(l=>l.file===change.file&&l.line>=Math.max(1,start-1)&&l.line<=start+Math.max(hunk.newCount,1)))matched=true
 }
 if(!matched)throw new Error('Diff change evidence must cite a real removal hunk and its affected current source region.')
 return {...change,patchSha256:scan.diffArtifact.sha256}
}
