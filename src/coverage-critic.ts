import { rankedDomains } from './coverage.js'
import type { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'
import { randomUUID } from 'node:crypto'
import type { Config } from './config.js'
import { createAuditAgent, waitForAuditAgent } from './runtime.js'
import { coverageDigest } from './coverage.js'
import { getStateDir, loadScan } from './state.js'

/** Critic 只提出覆盖任务，不重新执行普通扫描，也不能签发漏洞结论。 */
export async function runCoverageCritic(ctx: Context, config: Config, scanId: string, signal?: AbortSignal, stage:'post_wave'|'final_clean'='post_wave'): Promise<boolean> {
  const scan=await loadScan(getStateDir(config.stateDir),scanId), actorId=`critic_${randomUUID()}`
  const before=scan.coverage.critics?.length ?? 0
  const prompt=`Critic stage: ${stage}. You are an independent coverage critic for scan_id ${scanId}. A missing_units attackClass must be dataflow or a domain id listed by security_get_coverage. Call security_get_coverage and follow every nextOffset page before a clean assessment. For every reviewed unit, independently read at least one of that unit's cited source lines with security_read_scan_source and assess whether its question, conclusion and attack class are supported. For every detailsTruncated unit, follow detailsRef with security_read_scan_context kind coverage_unit and all nextOffset pages before a clean assessment. Check unmapped routes/RPC, identity/tenant/object boundaries, sensitive sinks without caller traces, sensitive output without egress traces, controller/service differences, effective middleware, error/default/lifecycle branches and excluded domains. Propose source-backed missing_units and reassign_ids, never findings. Submit security_report_coverage_critic once with the latest ledger_digest (initial ${coverageDigest(scan)}), every missing unit with exact source path/line/boundary/attackClass/reason, reassign_ids and a substantive rationale. A clean pass needs no gaps and must examine the actual coverage, not worker counts. Do not close coverage units, validate candidates, run code or access external services.`
  const handle=await createAuditAgent(ctx,{signal,sessionId:SessionId(`dsh-edge-critic-${randomUUID()}`),meta:{cwd:scan.target,origin:'subagent',delegationDepth:1},setup(c){c.tools.restrict({allow:['security_get_coverage','security_read_scan_source','security_read_scan_context','security_report_coverage_critic']});c.systemPrompt.section({name:`dsh-edge-audit:${actorId}`,order:163,interpolate:false,text:prompt})}},{stateDir:config.stateDir,maxConcurrentModelWorkers:config.maxConcurrentModelWorkers,workerTimeoutMs:config.workerTimeoutMs,budgetScanId:config.auditBudgetScanId,maxModelTokens:config.maxModelTokens,id:actorId,role:'coverage_critic',scanId,phase:stage,domains:rankedDomains(scan)})
  try {
    handle.agent.followup(createUserMessage({content:[{type:'text',text:prompt}],source:{kind:'dsh-edge-audit',form:'relay'}}))
    await waitForAuditAgent(handle.agent,signal,config.workerTimeoutMs)
    return ((await loadScan(getStateDir(config.stateDir),scanId)).coverage.critics?.length ?? 0)>before
  } finally {await handle.dispose()}
}
