import type { Finding } from './contracts.js'
/** 所有报告、跟踪与修复入口共享同一最终证据门禁。历史 Supported 不自动升级。 */
export function confirmedFinding(finding:Finding):boolean {
  return finding.disposition==='reportable' && finding.validationRecord?.conclusion==='reportable' && finding.validationRecord.independent===true && !!finding.validationRecord.reviewer && !!finding.attackPathRecord?.reviewer && finding.attackPathRecord.reviewer!==finding.validationRecord.reviewer && !finding.discoveredBy?.includes(finding.attackPathRecord.reviewer) && finding.lifecycleState==='confirmed'
}
export function evidenceState(finding:Finding){
  if(confirmedFinding(finding))return {lifecycleState:'confirmed',evidenceLevel:finding.evidenceLevel,legacySupported:false}
  if(finding.lifecycleState && finding.lifecycleState!=='confirmed')return {lifecycleState:finding.lifecycleState,evidenceLevel:finding.evidenceLevel??'source_backed',legacySupported:false}
  return {lifecycleState:finding.disposition==='suppressed'||finding.disposition==='not_applicable'?'rejected':'needs_validation',evidenceLevel:'source_backed',legacySupported:finding.disposition==='reportable'}
}
