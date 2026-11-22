import type { ToolCallView, ToolResult, ToolResultView } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { redactSensitive } from './audit-context.js'

const labels:Record<string,string>={
 security_import_github_findings:'读取 GitHub 安全待办',security_import_ticket_findings:'读取安全工单',security_tracking_preview:'预览外部跟踪',security_tracking_advisory_preview:'预览私有漏洞通告',security_create_github_security_advisory:'创建私有草稿通告',security_get_revalidation:'查看独立复验',security_record_triage_decision:'记录分诊决定',security_update_finding:'记录审阅注记',security_llm_get_scope:'读取标准审计范围',security_diff_get_review_items:'读取变更调查任务',security_deep_get_worklist:'读取深度工作清单',security_deep_get_reducer_input:'核对候选等价性',security_deep_report_reducer:'保存候选合并依据',security_llm_report_candidates:'提交源码候选',security_diff_report_candidates:'提交变更候选',security_deep_report_candidate:'提交深度调查候选',
 security_scan:'安全审计',security_assess:'建立候选调查',security_review_diff:'审查代码变更',security_run_deep_investigation:'深度安全审计',security_start_investigation:'建立调查',security_get_scan:'查看调查记录',security_get_coverage:'查看覆盖账本',security_review_coverage:'独立复核覆盖',security_validate_scan:'独立验证与攻击路径',security_finalize_investigation:'封存调查结果',security_scan_history:'查看审计历史',security_export_scan:'导出审计报告',security_resume_standard_scan:'恢复标准审计',security_resume_diff_scan:'恢复变更审计',security_resume_deep_investigation:'恢复深度审计',security_resume_deep_discovery:'恢复深度调查',security_resume_deep_closure:'恢复独立验证',security_record_validation:'保存独立验证',security_record_attack_path:'保存攻击路径',security_record_revalidation:'保存修复复验',security_record_coverage_check:'保存覆盖检查',security_report_coverage_critic:'保存覆盖复核',security_apply_remediation:'应用已审阅修复',security_rollback_remediation:'回滚已审阅修复',security_plan_candidate_validation:'查看验证计划',security_run_candidate_runtime_validation:'运行隔离验证',security_create_tracking_issue:'创建外部跟踪',security_start_disclosure_campaign:'生成独立披露报告',security_read_scan_source:'读取冻结源码',security_llm_read_source:'读取调查源码',security_diff_read_source:'读取变更上下文',security_diff_read_patch:'读取冻结补丁',security_deep_read_source:'读取深度调查区域',security_read_scan_context:'读取审计上下文',security_compare_scans:'比较审计记录',
}
function object(value:unknown):Record<string,unknown>{return value&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{}}
function number(value:unknown):number|undefined{return typeof value==='number'&&Number.isFinite(value)?value:undefined}
function text(value:unknown):string|undefined{return typeof value==='string'?redactSensitive(value).slice(0,240):undefined}
function inline(value:unknown):string{return String(value??'').replace(/[\\`*_\[\]<>]/g,'\\$&')}
export function securityPresentCall(name:string,args:unknown):ToolCallView|undefined{
 const value=object(args),title=labels[name]??(name.includes('read')?'读取审计证据':name.includes('report')?'保存调查进展':name.replace(/^security_/,'安全审计 · '))
 if(!title)return undefined
 const rawInput:Record<string,unknown>={};for(const key of ['path','mode','scan_id','finding_id','candidate_id','job_id','phase','format'])if(typeof value[key]==='string')rawInput[key]=text(value[key])
 const kind=name.includes('read')||name.includes('get')||name.includes('history')?'read':name.includes('apply')||name.includes('rollback')?'edit':name.includes('search')?'search':name.includes('scan')||name.includes('run_')?'execute':'other'
 return {card:'generic',title,kind,...(Object.keys(rawInput).length?{rawInput}:{}),...(typeof value.path==='string'?{locations:[{path:value.path,...(number(value.start_line)?{line:number(value.start_line)}:{})}]}:{})}
}
/** 只保存小型 UI 元数据，机器可读 render 不变；不复制源码、Token 或完整参数。 */
export function securityPresentationMeta(name:string,value:unknown):JsonValue{
 const data=object(value),counts=object(data.counts),coverage=object(data.coverage)
 const result={tool:name,scanId:text(data.scanId??data.id),lifecycle:text(data.lifecycle),complete:typeof data.complete==='boolean'?data.complete:undefined,mode:text(data.mode),phase:text(data.phase),candidates:number(data.findings)??number(data.totalFindings)??(Array.isArray(data.candidates)?data.candidates.length:undefined),confirmed:number(data.confirmedFindings??counts.confirmed),pending:number(data.pendingCandidates??counts.pending),rejected:number(counts.rejected),inventoryFiles:number(data.inventoryFiles??data.filesScanned??coverage.receiptCount??(Array.isArray(coverage.receipts)?coverage.receipts.length:undefined)),reviewedFiles:number(data.reviewedFiles??coverage.reviewedFiles),totalUnits:number(data.totalUnits),coverageComplete:typeof data.auditComplete==='boolean'?data.auditComplete:typeof coverage.auditComplete==='boolean'?coverage.auditComplete:undefined,path:text(data.path),startLine:number(data.startLine),endLine:number(data.endLine),sha256:text(data.sha256),recorded:data.recorded===true||data.closed===true||data.attached===true?true:undefined,format:text(data.format),items:Array.isArray(value)?value.length:undefined}
 return JSON.parse(JSON.stringify(result)) as JsonValue
}
export function securityPresentResult(name:string,_args:unknown,result:ToolResult):ToolResultView|undefined{
 if(result.isError){const detail=redactSensitive(result.content.filter(b=>b.type==='text').map(b=>(b as {text:string}).text).join('\n')).slice(0,1800),cancelled=/aborted|cancelled|AbortError/i.test(detail)
  return {card:'generic',title:cancelled?'已中断 · 保留已记录进度':'未完成 · 需要处理错误',content:[{type:'text',text:`${cancelled?'请使用返回的任务标识续扫；未完成部分不会计为成功。':'先处理下列原因，再继续同一调查；不会自动确认风险。'}\n\n${detail.split('\n').map(line=>'    '+line).join('\n')}`}]}}
 const meta=object(result.meta);if(!Object.keys(meta).length)return undefined
 if(meta.path&&meta.startLine){return {card:'generic',title:`${text(meta.path)} · ${meta.startLine}–${meta.endLine}`,content:[{type:'text',text:`冻结源码 · 摘要 \`${inline(String(meta.sha256??'').slice(0,12))}\`。读取不等于安全审阅。`},...result.content.filter(b=>b.type==='text').map(b=>({type:'text' as const,text:(b as {text:string}).text.split('\n').map(line=>'    '+line).join('\n')}))]}}
 const incomplete=meta.complete===false||['incomplete','capped','failed','cancelled','queued','running'].includes(String(meta.lifecycle))
 const done=meta.complete===true||(meta.lifecycle==='completed'&&meta.phase==='finalization')
 const title=incomplete?'审计未完成':done?(Number(meta.pending)>0?'已封存 · 仍有待验证线索':'审计流程已完成'):meta.lifecycle==='completed'?'当前步骤已完成':labels[name]??'调查进展已保存'
 const rows:string[]=[]
 if(meta.scanId)rows.push(`调查标识：\`${inline(meta.scanId)}\``)
 if(meta.confirmed!==undefined)rows.push(`**确认 ${meta.confirmed}**${meta.pending!==undefined?` · 待验证 ${meta.pending}`:''}${meta.rejected!==undefined?` · 已排除 ${meta.rejected}`:''}`)
 else if(meta.candidates!==undefined)rows.push(`候选 ${meta.candidates} · 确认数量请查看证据记录`)
 if(meta.inventoryFiles!==undefined||meta.reviewedFiles!==undefined)rows.push(`源文件库存 ${meta.inventoryFiles??'未提供'} · 已完成审阅 ${meta.reviewedFiles??'未提供'}`)
 if(meta.totalUnits!==undefined)rows.push(`覆盖单元 ${meta.totalUnits} · ${meta.coverageComplete===true?'独立覆盖复核已接受':'仍需检查覆盖与缺口'}`)
 if(meta.items!==undefined)rows.push(`返回 ${meta.items} 条记录。`)
 if(incomplete)rows.push('**下一步：**查看覆盖缺口、待验证候选或失败原因；保留原任务继续调查。')
 if(meta.recorded===true)rows.push('收据已保存；单条收据不代表整次审计完成。')
 if(!rows.length)return labels[name]||meta.lifecycle?{card:'generic',title}:undefined
 return {card:'generic',title,content:[{type:'text',text:rows.join('\n\n')}]}
}
