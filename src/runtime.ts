import { acquireBudgetScanSlot, acquireModelSlot } from './model-pool.js'
import { skillGuidance } from './skills.js'
import { bindAuditSession, unbindAuditSession, redactSensitive, UNTRUSTED_SOURCE_POLICY, type AuditActor } from './audit-context.js'
import { auditAdmissionReason, auditBudgetReason, AuditBudgetExceeded } from './audit-budget.js'
import { loadScan, getStateDir } from './state.js'
import { mutateScan } from './scan-store.js'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent, AgentHandle, CreateAgentOptions } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-working-directory'

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap {
    /** 插件自己的持久化消息来源，不能冒充用户输入。 */
    'dsh-edge-audit': { kind: 'dsh-edge-audit'; form: 'relay' }
  }
}

/** 目录属于调用 Session；禁止通过 chdir 改变并发会话的执行环境。 */
export function workspaceDirectory(ctx: Context, agent?: Agent): string {
  if (!agent?.session) throw new Error('Security audit requires an actual Session working directory; select the authorized workspace in DSH.')
  const directories = ctx.get('workingDirectory')
  const cwd = directories?.get(agent.session) ?? agent.session.header.cwd
  if (!cwd) throw new Error('Security audit requires a Session working directory.')
  return cwd
}

/** 使用公开 Agent API 保持父子归属、模型路由和创建阶段取消。 */
export async function createAuditAgent(ctx: Context, options: CreateAgentOptions, actor?: AuditActor): Promise<AgentHandle> {
  // agents 是可选运行时能力；不能绕过 Cordis inject 直接访问 ctx.agents。
  const agents = typeof ctx.get === 'function' ? ctx.get('agents') : ctx.agents
  if (!agents) throw new Error('The active DSH profile has no native agent-creation service.')
  let budgetKey:string|undefined
  const budgetId=actor?.stateDir&&actor.scanId?actor.budgetScanId??actor.scanId:undefined
  if(actor?.stateDir && actor.scanId){
    if(actor.maxModelTokens)await mutateScan({stateDir:actor.stateDir},budgetId!,scan=>{scan.auditBudget={maxModelTokens:Math.min(scan.auditBudget?.maxModelTokens??Infinity,actor.maxModelTokens!)}})
    const retained=await loadScan(getStateDir(actor.stateDir),budgetId!)
    if(Number.isFinite(Math.min(retained.auditBudget?.maxModelTokens??Infinity,actor.maxModelTokens??Infinity)))budgetKey=`${getStateDir(actor.stateDir)}:${budgetId}`
    if(retained.auditDeadlineAt){const remaining=Date.parse(retained.auditDeadlineAt)-Date.now();if(remaining<=0)throw new AuditBudgetExceeded('The original audit wall-clock deadline is exhausted; resume never resets it.');const deadlineSignal=AbortSignal.timeout(Math.min(remaining,2_147_483_647));options={...options,signal:options.signal?AbortSignal.any([options.signal,deadlineSignal]):deadlineSignal}}
  }
  options.signal?.throwIfAborted()
  let releaseBudget:()=>void=()=>undefined,release:()=>void=()=>undefined
  try{if(budgetKey)releaseBudget=await acquireBudgetScanSlot(budgetKey,options.signal);if(actor)release=await acquireModelSlot(actor.maxConcurrentModelWorkers,options.signal)}
  catch(error){releaseBudget();throw error}
  let handle:AgentHandle
  const proposedSessionId=String(options.sessionId),pendingMarked:string[]=[]
  const clearPending=async()=>{if(!actor?.stateDir)return;for(const scanId of pendingMarked)await mutateScan({stateDir:actor.stateDir},scanId,scan=>{scan.modelExecutions=scan.modelExecutions?.filter(row=>row.sessionId!==proposedSessionId||row.terminalReason!=='pending')})}
  try{
    if(actor?.stateDir&&actor.scanId&&!budgetKey){const reason=await auditBudgetReason(actor.stateDir,budgetId!,actor.maxModelTokens);if(reason)throw new AuditBudgetExceeded(reason)}
    options.signal?.throwIfAborted()
    if(budgetKey&&actor?.stateDir&&actor.scanId){for(const scanId of new Set([budgetId!,actor.scanId])){await mutateScan({stateDir:actor.stateDir},scanId,scan=>{if(scanId===budgetId){const reason=auditAdmissionReason(scan,actor.maxModelTokens,actor.role==='discoverer'||actor.role==='architect');if(reason)throw new AuditBudgetExceeded(reason)}scan.modelExecutions??=[];if(scan.modelExecutions.some(row=>row.sessionId===proposedSessionId))throw new Error('Audit model Session id already has a retained execution record.');scan.modelExecutions.push({sessionId:proposedSessionId,actorId:`session:${proposedSessionId}`,role:actor.role,jobId:actor.jobId,workerId:actor.workerId,at:new Date().toISOString(),usage:null,usageComplete:false,toolCalls:0,terminalReason:'pending'})});pendingMarked.push(scanId)}}
  const parent = agents.currentInitiator?.()
  handle = await agents.create({
    ...options,
    setup(agentCtx, agent) {
      options.setup?.(agentCtx, agent)
      agentCtx.systemPrompt.section({name:'dsh-edge-audit:assignment-budget',order:169,interpolate:false,text:auditBudgetPrompt(actor?.workerTimeoutMs)})
      const phase=(actor?.role==='discoverer'||actor?.role==='architect')?'discovery':actor?.role==='validator'?'validation':actor?.role==='attack_path'?'attack-path':actor?.role==='coverage_critic'?'coverage':undefined
      if(phase)agentCtx.systemPrompt.section({name:'dsh-edge-audit:trusted-phase-skill',order:168,interpolate:false,text:skillGuidance(phase,actor?.domains,{threatModelMethod:actor?.role==='architect'})})
      agentCtx.systemPrompt.section({name:'dsh-edge-audit:untrusted-boundary',order:170,interpolate:false,text:UNTRUSTED_SOURCE_POLICY})
    },
    ...(parent ? {
      parentAgent: parent,
      agentOptions: { ...parent.options },
      meta: {
        ...options.meta,
        parentSession: parent.session.id,
        delegationDepth: (parent.session.header.delegationDepth ?? 0) + 1,
      },
    } : {}),
  })
  }catch(error){try{await clearPending()}finally{release();releaseBudget()}throw error}
  const sessionId = handle.agent.session?.id as string | undefined
  if(budgetKey&&sessionId!==proposedSessionId){try{await handle.dispose();await clearPending()}finally{release();releaseBudget()}throw new Error('Budgeted audit Agent did not retain the requested Session identity.')}
  if (actor && sessionId) bindAuditSession(sessionId, actor)
  if (!sessionId){const original=handle.dispose.bind(handle);return {...handle,async dispose(){try{await original()}finally{release();releaseBudget()}}}}
  const dispose = handle.dispose.bind(handle)
  let recorded=false
  return { ...handle, agent: handle.agent, async dispose() {
    try {
      if(!recorded && actor?.stateDir && actor.scanId){
        const evidence=auditExecutionEvidence(handle.agent),endings=(handle.agent.session?.snapshotEvents?.()??[]).filter(e=>(e as {type?:string}).type==='turn/end')
        const last=endings.at(-1) as {data?:{reason?:{kind?:string}}}|undefined
        for(const scanId of new Set([actor.scanId,actor.budgetScanId??actor.scanId]))await mutateScan({stateDir:actor.stateDir},scanId,scan=>{
          if(scan.lifecycle==='completed')return
          scan.modelExecutions??=[]
          const row={sessionId,actorId:`session:${sessionId}`,role:actor.role,jobId:actor.jobId,workerId:actor.workerId,at:new Date().toISOString(),usage:evidence.usage,toolCalls:evidence.toolCalls,terminalReason:last?.data?.reason?.kind,usageComplete:last?.data?.reason?.kind==='completed'&&!!evidence.usage}
          const index=scan.modelExecutions.findIndex(existing=>existing.sessionId===sessionId)
          if(index<0)scan.modelExecutions.push(row)
          else if(scan.modelExecutions[index].terminalReason==='pending')scan.modelExecutions[index]=row
        })
        recorded=true
      }
    } finally { try { await dispose() } finally { unbindAuditSession(sessionId);release();releaseBudget() } }
  } }

}

/** 缺报告、模型超时均由调用方记为 incomplete；idle 本身不表示成功。 */
export async function waitForAuditAgent(agent: { whenIdle(): Promise<unknown>;session?:{snapshotEvents?:()=>ReadonlyArray<unknown>} }, signal?: AbortSignal, timeoutMs = 180_000): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined
  let onAbort: (() => void) | undefined
  try {
    await Promise.race([
      agent.whenIdle(),
      new Promise<never>((_ok,reject)=> { timer=setTimeout(()=>reject(new Error('Audit model worker timed out before a valid terminal report.')),Math.max(100,Math.min(timeoutMs,3_600_000))); if(signal) { onAbort=()=>reject(signal.reason ?? new Error('Audit cancelled.')); if(signal.aborted) onAbort(); else signal.addEventListener('abort',onAbort,{once:true}) } }),
    ])
    const endings=(agent.session?.snapshotEvents?.()??[]).filter(raw=>(raw as {type?:string}).type==='turn/end')
    const last=endings.at(-1) as {data?:{reason?:{kind?:string;error?:{message?:string;code?:string}}}}|undefined
    if(last?.data?.reason?.kind && last.data.reason.kind!=='completed'){const reason=last.data.reason;const detail=reason.error?.message?` ${reason.error.code??'MODEL_ERROR'}: ${redactSensitive(reason.error.message).slice(0,1000)}`:'';throw new Error(`Audit worker ended with ${reason.kind}; it is not successful review completion.${detail}`)}
  } finally { if(timer)clearTimeout(timer);if(signal && onAbort)signal.removeEventListener('abort',onAbort) }
}

/** 只统计宿主真正保留的 usage；没有服务端计数时返回 null，不估算为零。 */
export function auditTokenUsage(agent:{session?:{snapshotEvents?:()=>ReadonlyArray<unknown>}}): {inputTokens:number;outputTokens:number;cacheReadTokens:number;cacheWriteTokens:number;calls:number} | null {
  const events=agent.session?.snapshotEvents?.() ?? [],total={inputTokens:0,outputTokens:0,cacheReadTokens:0,cacheWriteTokens:0,calls:0}
  for(const raw of events){const event=raw as {type?:string;data?:{usage?:{inputTokens?:number;outputTokens?:number;cacheReadTokens?:number;cacheWriteTokens?:number}}};if(event.type!=='assistant/message'||!event.data?.usage)continue;const usage=event.data.usage;if(!Number.isFinite(usage.inputTokens)||!Number.isFinite(usage.outputTokens))continue;total.inputTokens+=usage.inputTokens!;total.outputTokens+=usage.outputTokens!;total.cacheReadTokens+=usage.cacheReadTokens??0;total.cacheWriteTokens+=usage.cacheWriteTokens??0;total.calls++}
  return total.calls?total:null
}

/** 失败路径也保留宿主真实证据；不能把没有成功收尾误写为没有执行。 */
export function auditExecutionEvidence(agent: { session?: { deriveMessages?: () => ReadonlyArray<{role:string;content:ReadonlyArray<{type:string;text?:string}>}>; snapshotEvents?:()=>ReadonlyArray<unknown> } }) {
  const transcript = (agent.session?.deriveMessages?.() ?? []).filter(m=>m.role==='assistant').flatMap(m=>m.content.filter(b=>b.type==='text').map(b=>b.text??'')).join('\n\n').slice(-100_000)
  const events = agent.session?.snapshotEvents?.() ?? []
  return { transcript: redactSensitive(transcript), usage: auditTokenUsage(agent), toolCalls: events.filter(e=>(e as {type?:string}).type==='tool/call').length }
}

/** 预留提交检查点的时间；硬超时仍由宿主执行，不能靠提示词解除。 */
export function auditBudgetPrompt(timeoutMs = 180_000): string {
  const started=Date.now(), reserve=Math.min(30_000,Math.max(100,Math.floor(timeoutMs/5)))
  return `This bounded assignment starts at ${new Date(started).toISOString()}; stop opening investigations by ${new Date(started+timeoutMs-reserve).toISOString()} and submit source-backed candidates, coverage and the terminal checkpoint before ${new Date(started+timeoutMs).toISOString()}. Reserve the last ${reserve} ms for checkpoint submission. Explicitly defer unfinished regions; never claim them reviewed. The coordinator retains completed batches and will schedule remaining work.`
}
