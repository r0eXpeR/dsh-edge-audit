const fixturePolicyFacts={impact:'high',likelihood:'high',vector:'remote',authScope:'public',preconditions:'plausible',attackerInputControl:'yes',selfOnly:false,privilegedOnly:false,operatorOnly:false,developerOnly:false,physicalAccessOnly:false,unreachable:false,unrealisticPreconditions:false}
// 仅供隔离 Desktop 回归的测试插件，不包含在发布包内。
import assert from 'node:assert/strict'
import { mkdir, writeFile, readFile, readdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { LlmAdapter, ToolCallId, createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'

export const inject = ['tools', 'agents', 'llm', 'systemPrompt', 'webServer', 'workingDirectory']

function toolChunks(name, args) {
  const id = ToolCallId(randomUUID()), value = JSON.stringify(args)
  return [
    { type: 'block-start', index: 0, blockType: 'tool-call' },
    { type: 'tool-call-delta', index: 0, id, name, argumentsDelta: value },
    { type: 'block-end', index: 0, block: { type: 'tool-call', id, name, arguments: value } },
    { type: 'finish', reason: { kind: 'tool-calls' } },
  ]
}
function textChunks(text) {
  return [
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text },
    { type: 'block-end', index: 0, block: { type: 'text', text } },
    { type: 'finish', reason: { kind: 'stop' } },
  ]
}
const candidate = {
  ruleId: 'dynamic-code.eval', title: 'Fixture request reaches eval', summary: 'Request query code reaches eval directly.',
  cwe: 'CWE-95', severity: 'high', confidence: 'medium', attacker: 'Remote fixture request caller',
  violatedInvariant: 'Untrusted input must not become executable code.', sourceToSink: 'req.query.code -> eval',
  impact: 'Evaluation of attacker-controlled code', remediation: 'Replace eval with an allowlisted dispatch table.',
  counterevidence: 'No control exists in this deliberately vulnerable fixture; deployment was not assessed.',
  locations: ['entrypoint','root_control','sink'].map(role=>({path:'app.ts',startLine:1,role})), evidence: [],
}

/** 脚本适配器只验证协议和生命周期，不代表模型发现能力。 */
class FixtureAdapter extends LlmAdapter {
  states = new Map()
  requests = 0
  holdWorkers = false
  holdStandard = false
  holdDiff = false
  holdClaimedClosure = false
  workerEntered
  async *stream(options) {
    this.requests++
    let state = this.states.get(options.sessionId)
    if (!state) {
      const prompt = options.messages.flatMap(m => m.content.filter(b => b.type === 'text').map(b => b.text)).join('\n')
      const standard = /Job: `([^`]+)`; worker: `([^`]+)`; claim token: `([^`]+)`/.exec(prompt)
      const deep = /job_id (deep_[0-9a-f-]+)/.exec(prompt)
      const worker = /worker_id (worker_\d+_\d+)/.exec(prompt)
      const reducer = /reducer_id ([a-z0-9_]+)/.exec(prompt)
      const token = /claim_token ([0-9a-f-]+)/.exec(prompt)
      const disclosure=/campaign_id (disclosure_[0-9a-f-]+)/.exec(prompt),writer=/worker_id (writer_[a-z0-9._-]+)/.exec(prompt)
      const closing = /scan_id (scan_[0-9a-f-]+), owner (closure_[a-z_]+_\d+_\d+)/.exec(prompt)
      const visible = options.tools?.map(t => t.name) ?? []
      state = { queue: [], visible, step: 0 }
      if (prompt.includes('COMPAT_APPROVAL_FIXTURE')) {
        state.kind = 'approval'
        state.queue.push(['security_install_precommit_hook', { approved: true }])
      } else if(prompt.includes('independent coverage critic')) {
        state.kind='critic';state.scanId=/scan_id (scan_[0-9a-f-]+)/.exec(prompt)[1];state.queue.push(['security_get_coverage',{scan_id:state.scanId}])
      } else if(disclosure && writer){state.kind='disclosure';state.args={campaign_id:disclosure[1],worker_id:writer[1],claim_token:token[1]};state.queue.push(['security_disclosure_get_assignment',state.args])
      } else if (closing) {
        state.kind = 'closure'; state.args = { scan_id: closing[1], owner: closing[2] }
        state.phase = visible.includes('security_record_validation') ? 'validation' : 'attack_path'
        state.queue.push(['security_get_scan', { scan_id: closing[1] }])
      } else if (standard && (visible.includes('security_llm_get_scope')||visible.includes('security_diff_get_review_items'))) {
        const [, job_id, worker_id, claim_token] = standard
        state.args = { job_id, worker_id, claim_token }
        state.kind = visible.includes('security_diff_get_review_items') ? 'diff' : 'llm'
        state.queue.push(['security_' + state.kind + (state.kind === 'diff' ? '_get_review_items' : '_get_scope'), state.args])
      } else if (deep && reducer) {
        state.kind = 'reducer'; state.args = { job_id: deep[1], reducer_id: reducer[1], claim_token: token[1] }
        state.queue.push(['security_deep_get_reducer_input', state.args], ['security_deep_report_reducer', { ...state.args, merges: [] }])
      } else if (deep && worker) {
        state.kind = 'deep'; state.args = { job_id: deep[1], worker_id: worker[1], claim_token: token[1] }
        state.queue.push(['security_deep_get_worklist', state.args])
      } else throw new Error('Unexpected fixture Agent prompt')
      this.states.set(options.sessionId, state)
    }
    if ((state.kind === 'deep' && this.holdWorkers)||(state.kind==='llm'&&(this.holdStandard||this.holdWorkers))||(state.kind==='diff'&&this.holdDiff)) {
      this.workerEntered?.()
      await new Promise(resolve => {
        if (options.signal.aborted) resolve()
        else options.signal.addEventListener('abort', resolve, { once: true })
      })
      options.signal.throwIfAborted()
    }
    if(state.step===1 && state.kind==='disclosure'){
      state.queue.push(['security_disclosure_read_source',{...state.args,path:'app.ts'}],['security_disclosure_submit_report',{...state.args,summary:'A scripted fixture report describes the direct request-to-eval operation.',attacker:'A caller of the deliberately vulnerable fixture.',entry_point:'The caller-controlled fixture query parameter.',vulnerable_path:'The exact fixture passes query text to eval.',bad_state:'Untrusted request text becomes executable fixture code.',impact:'The documented fixture evaluation boundary is crossed.',exploitability:'Only the finite fixture source context is established.',counterevidence:'No additional enforcing fixture control is present.',limitations:'Scripted protocol report only; no real model or deployment was evaluated.',remediation:'Replace string evaluation with an explicit allowlist.',reproduction_status:'not_run',reproduction_notes:'This disclosure workflow did not execute a PoC or target code.',source_references:[{path:'app.ts',line:1,explanation:'The frozen fixture contains the direct request-to-eval expression.'}]}])
    }
    if (state.step === 1 && ['llm', 'diff', 'deep'].includes(state.kind)) {
      const result = options.messages.filter(m => m.role === 'tool').at(-1)
      const scope = JSON.parse(result.content.filter(b => b.type === 'text').map(b => b.text).join(''))
      state.scanId=scope.scanId ?? /scan_id (scan_[0-9a-f-]+)/.exec(options.messages.flatMap(m=>m.content.filter(b=>b.type==='text').map(b=>b.text)).join('\n'))?.[1]
      const items = state.kind === 'llm' ? scope.worklist : scope.items
      for (const item of items) state.queue.push(['security_' + state.kind + '_read_source', state.kind === 'deep' ? { ...state.args, work_item_id: item.id } : { ...state.args, path: item.path, start_line: item.startLine ?? 1, end_line: item.endLine ?? 200 }])
      if(scope.workerKind==='architect'){
        state.queue.push(['security_llm_report_worker',{...state.args,fully_reviewed_file_count:0,resolved_questions:['Bounded representative fixture architecture mapping.'],reviewed_region_ids:(scope.assignedRegions??[]).map(r=>r.id),deferred_regions:[],architecture_facts:items.map(item=>({statement:'The retained finite fixture source declares the operation under review; source mapping does not establish production reachability.',sourceReferences:[{file:item.path,line:item.startLine??1,role:'root_control'}]})),architecture_limitations:['Representative architecture mapping is not complete security coverage.']}])
      }else {
      state.queue.push(['security_get_coverage',{scan_id:state.scanId}])
      if (state.kind === 'deep') {
        state.queue.push(['security_deep_report_candidate', { ...state.args, rule_id: 'custom.desktop-fixture', title: 'Fixture request reaches eval', severity: 'high', cwe: 'CWE-95', file: 'app.ts', line: 1, source_references:['entrypoint','root_control','sink'].map(role=>({file:'app.ts',line:1,role})),root_cause: 'The deliberately vulnerable fixture passes request query text into eval without an enforcing guard.' }])
        state.queue.push(['security_deep_report_worker', { ...state.args, threat_model: 'A remote fixture caller controls request query text crossing the request boundary into dynamic execution.', reviewed_work_item_ids: items.map(i => i.id), deferred: [], coverage_summary: 'Every immutable fixture region was read using the worker-restricted source tool.' }])
      } else {
        state.queue.push(['security_' + state.kind + '_report_candidates', { ...state.args, candidates: [candidate] }])
        state.queue.push(['security_' + state.kind + '_report_worker', { ...state.args, resolved_questions: ['The fixture has a direct request-to-eval flow.'], fully_reviewed_file_count: items.length }])
      }
    }
    }
    if(state.last==='security_get_coverage'){
      const message=options.messages.filter(m=>m.role==='tool').at(-1),coverage=JSON.parse(message.content.filter(b=>b.type==='text').map(b=>b.text).join(''))
      if(state.kind==='critic')state.queue.push(['security_read_scan_source',{scan_id:state.scanId,path:'app.ts'}],['security_report_coverage_critic',{scan_id:state.scanId,ledger_digest:coverage.digest,reassign_ids:[],missing_units:[],rationale:'The finite deliberately vulnerable fixture has explicit request/evaluator units and all retained ranges; this scripted critique validates protocol only.'}])
      else state.queue.unshift(...coverage.units.map(unit=>['security_record_coverage_check',{scan_id:state.scanId,unit_id:unit.id,status:'reviewed',question:'Does request text reach the exact evaluator in this deliberately vulnerable fixture?',conclusion:'The full fixed test source region was read and its declared request-to-evaluator boundary was examined; no unknown repository audit is claimed.',source_references:[{file:unit.path,line:unit.startLine,role:'root_control'}],limitations:[]}]))
    }
    if(state.kind==='closure'&&state.last==='security_claim_audit_task'&&this.holdClaimedClosure){
      const message=options.messages.filter(m=>m.role==='tool').at(-1),claim=JSON.parse(message.content.filter(b=>b.type==='text').map(b=>b.text).join(''))
      if(claim){this.workerEntered?.();await new Promise(resolve=>{if(options.signal.aborted)resolve();else options.signal.addEventListener('abort',resolve,{once:true})});options.signal.throwIfAborted()}
    }
    if(state.kind==='closure' && ['security_get_scan','security_claim_audit_task'].includes(state.last)){
      const message=options.messages.filter(m=>m.role==='tool').at(-1),value=JSON.parse(message.content.filter(b=>b.type==='text').map(b=>b.text).join(''))
      const claim=['security_claim_audit_task',{...state.args,phase:state.phase}]
      if(state.last==='security_claim_audit_task' && value){state.task=value;state.queue.push(['security_get_scan',{scan_id:state.args.scan_id,candidate_id:value.candidateId}])}
      if(state.last==='security_get_scan'){
        if(!state.task)state.queue.push(claim)
        else{
          const task=state.task,finding=value.findings.find(f=>f.candidateId===task.candidateId)
          if(!finding)throw new Error('Claimed candidate was not visible in its scoped scan view')
          const source_references=finding.locations.map(l=>({file:l.file,line:l.line,role:l.role??'root_control'}))
          for(const role of ['entrypoint','sink'])if(!source_references.some(r=>r.role===role))source_references.push({file:'app.ts',line:1,role})
          state.queue.push(['security_read_scan_source',{scan_id:state.args.scan_id,path:'app.ts'}],['security_attach_evidence_locations',{scan_id:state.args.scan_id,candidate_id:task.candidateId,claim_token:task.claimToken,source_references}])
          const common={scan_id:state.args.scan_id,candidate_id:task.candidateId,claim_token:task.claimToken,attacker:'Fixture request caller',entry_point:'req.query.code',source_references}
          if(state.phase==='validation')state.queue.push(['security_record_validation',{...common,conclusion:'reportable',method:'static',trust_boundary:'Request text to evaluator',root_control:'eval(req.query.code)',sink:'eval',impact:'Request-controlled code evaluation',direct_evidence:'Frozen fixture source shows a direct query-to-eval expression.',counterevidence:'No local guard appears in the fixture.',limitations:'Scripted protocol review; no external model or live exploit was used.',confidence:'medium'}])
          else state.queue.push(['security_record_attack_path',{...common,policy_facts:fixturePolicyFacts,preconditions:'Fixture route is callable.',dataflow:'req.query.code -> eval',outcome:'Request-controlled code evaluation',severity_rationale:'Untrusted text enters a sensitive execution sink.',change_conditions:'An enforced guard would invalidate this path.'}])
          state.task=undefined;state.queue.push(claim)
        }
      }
    }
    const next = state.queue.shift()
    state.last = next?.[0]
    state.step++
    if (next) { assert.ok(state.visible.includes(next[0]), 'Worker tool must be visible in scoped catalog'); yield* toolChunks(...next) }
    else yield* textChunks('Fixture protocol review completed; no external model was invoked.')
  }
}

export function apply(ctx) {
  const adapter = new FixtureAdapter()
  ctx.llm.registerAdapter(['security-compat-fixture'], adapter)
  let running
  ctx.effect(() => ctx.webServer.register({ kind: 'exact', path: '/security-compat/run',
    async handler(request, response) {
      if (request.method !== 'POST') { response.statusCode = 405; response.end(); return }
      try {
        const result = await (running ??= run(ctx, adapter))
        response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(result))
      } catch (error) {
        response.statusCode = 500; response.setHeader('content-type', 'application/json')
        response.end(JSON.stringify({ passed: false, error: error.stack }))
      }
    },
  }))
}

async function run(ctx, adapter) {
  const sandbox = dirname(process.env.DSH_HOME)
  const fixture = join(sandbox, 'fixture'), other = join(sandbox, 'other-workspace')
  await mkdir(fixture, { recursive: true }); await mkdir(other, { recursive: true })
  await writeFile(join(fixture, 'app.ts'), 'export function route(req) { return safe(req.query.code) }\n')
  const git = promisify(execFile)
  for (const args of [['init'], ['config', 'user.email', 'fixture@example.invalid'], ['config', 'user.name', 'Compatibility Fixture'], ['add', '.'], ['commit', '-m', 'baseline']]) await git('git', args, { cwd: fixture })
  await writeFile(join(fixture, 'app.ts'), 'export function route(req) { return eval(req.query.code) } // {{literal_source}}\n')
  await writeFile(join(other, 'clean.ts'), 'export const value = 1\n')
  const handles = []
  const checks = [], executions = []
  const created = [], disposed = []
  const failedWorkerCalls = [], expectedCancelledCalls=[]
  const offResult = ctx.on('tools/result', (exec, result) => {
    if(exec.agent?.session.header.origin==='subagent'&&result.isError){if((result.error.info?.code??result.error.code)==='ABORTED'&&exec.signal.aborted)expectedCancelledCalls.push({name:exec.name});else failedWorkerCalls.push({name:exec.name,error:result.error})}
  })
  const offCreate = ctx.on('agent/created', ({ agent }) => { created.push({ id: agent.id, cwd: agent.session.header.cwd, parentSession: agent.session.header.parentSession }) })
  const offDispose = ctx.on('agent/disposed', ({ agent }) => { disposed.push(agent.id) })
  let count = 0
  async function root(cwd, answer) {
    const h = await ctx.agents.create({ sessionId: SessionId('security-compat-' + randomUUID()), meta: { cwd }, agentOptions: { provider: 'security-compat-fixture', model: 'fixture' }, setup(scope) {
      scope.tools.presentAs('native')
      if (answer) scope.on('approval/request', async () => answer, { prepend: true })
    } })
    handles.push(h); return h.agent
  }
  async function call(agent, name, args = {}, allowError = false, signal = new AbortController().signal) {
    const result = await ctx.agents.withInitiator(agent, () => ctx.tools.execute({ agent, callId: ToolCallId('compat-' + ++count), name, arguments: args, signal }))
    executions.push({ name, isError: result.isError, ...(result.isError ? { error: result.error } : {}) })
    const definition=ctx.tools.get(name,agent)
    assert.equal(definition?.presentCall?.({...args,token:'synthetic-presenter-secret'})?.card,'generic')
    assert.ok(!JSON.stringify(definition.presentCall({...args,token:'synthetic-presenter-secret'})).includes('synthetic-presenter-secret'))
    if(!result.isError&&result.meta)assert.doesNotThrow(()=>definition.presentResult?.(args,result))
    if (!allowError) assert.equal(result.isError, false, name + ': ' + result.error?.message)
    return result.isError ? result : result.value
  }
  async function close(agent, scanId) {
    const alreadyComplete=(await call(agent,'security_get_scan',{scan_id:scanId})).lifecycle==='completed'
    if(!alreadyComplete){
    for (const phase of ['validation', 'attack_path']) {
      while (true) {
        const task = await call(agent, 'security_claim_audit_task', { scan_id: scanId, owner: 'desktop-bridge', phase })
        if (!task) break
        const scan = await call(agent, 'security_get_scan', { scan_id: scanId, candidate_id: task.candidateId })
        const finding = scan.findings.find(f => f.candidateId === task.candidateId)
        const source_references = [...finding.locations.map(l => ({ file: l.file, line: l.line, role: l.role ?? 'root_control' }))];for(const role of ['entrypoint','sink'])if(!source_references.some(r=>r.role===role))source_references.push({file:'app.ts',line:1,role})
        await call(agent, 'security_read_scan_source', { scan_id: scanId, path: 'app.ts' })
        await call(agent,'security_attach_evidence_locations',{scan_id:scanId,candidate_id:task.candidateId,claim_token:task.claimToken,source_references})
        if (phase === 'validation') await call(agent, 'security_record_validation', {
          scan_id: scanId, candidate_id: task.candidateId, claim_token: task.claimToken,
          conclusion: 'reportable', method: 'static', attacker: 'Deliberately vulnerable fixture caller',
          entry_point: 'req.query.code', trust_boundary: 'Request text to JavaScript evaluator', root_control: 'eval(req.query.code)', sink: 'eval', impact: 'Evaluation of request-controlled code',
          direct_evidence: 'The frozen one-line fixture shows the direct source-to-sink expression.',
          counterevidence: 'There is no local guard; production reachability is outside this fixture.', limitations: 'Scripted fixture review; no external model or exploit was run.', confidence: 'medium', source_references,
        })
        else await call(agent, 'security_record_attack_path', { policy_facts:fixturePolicyFacts,scan_id: scanId, candidate_id: task.candidateId, claim_token: task.claimToken,
          attacker: 'Fixture request caller', entry_point: 'req.query.code', preconditions: 'The fixture route is callable.', dataflow: 'req.query.code -> eval(req.query.code)', outcome: 'Request-controlled JavaScript evaluation', severity_rationale: 'Direct input to sensitive execution in the fixture.', change_conditions: 'A proven enforcing allowlist would invalidate this path.', source_references })
      }
    }
    const coverage=await call(agent,'security_get_coverage',{scan_id:scanId});for(const unit of coverage.units){await call(agent,'security_read_scan_source',{scan_id:scanId,path:unit.path,start_line:unit.startLine,end_line:unit.endLine});await call(agent,'security_record_coverage_check',{scan_id:scanId,unit_id:unit.id,status:'reviewed',question:'Does this explicit finite fixture cross its documented request/evaluator boundary?',conclusion:'The source region and operation were examined in this scripted protocol fixture; no actual model or unknown repository was evaluated.',source_references:[{file:unit.path,line:unit.startLine,role:'root_control'}],limitations:[]})}
    await call(agent,'security_review_coverage',{scan_id:scanId})
    }
    const finished = await call(agent, 'security_finalize_investigation', { scan_id: scanId })
    assert.equal(finished.lifecycle, 'completed')
    assert.equal((await call(agent, 'security_verify_scan_bundle', { scan_id: scanId })).valid, true)
    for (const format of ['markdown', 'json', 'sarif', 'csv', 'html']) {
      const exported = await call(agent, 'security_export_scan', { scan_id: scanId, format })
      assert.ok(exported.content.length > 0)
      await mkdir(join(sandbox, 'reports', scanId), { recursive: true })
      await writeFile(join(sandbox, 'reports', scanId, format + '.txt'), exported.content)
    }
  }
  try {
    const agent = await root(fixture), neighbor = await root(other)
    const names = ctx.tools.schemas(agent).map(t => t.name).filter(n => n.startsWith('security_'))
    assert.ok(names.length > 60)
    checks.push({ name: 'registration-and-native-card-presenters', tools: names.length })
    const packaged=await call(agent,'security_list_skills',{})
    assert.equal(packaged.length,8)
    const trusted=await call(agent,'security_read_skill',{name:'dsh-edge-validation'})
    assert.equal(trusted.provider,'dsh-edge-audit');assert.equal(trusted.source,'bundled')
    const nativeSkills=await ctx.get('skills').list()
    assert.equal(nativeSkills.filter(s=>s.provider==='dsh-edge-audit').length,8)
    assert.ok((await ctx.get('skills').get('dsh-edge-audit')).content.length>0)
    checks.push({name:'native-packaged-phase-skills-and-domain-assets',skills:packaged.length})

    const [first, second] = await Promise.all([call(agent, 'security_scan', { discovery: 'engine' }), call(neighbor, 'security_scan', { discovery: 'engine' })])
    assert.ok(first.findings > 0); assert.equal(second.findings, 0)
    const firstScan = await call(agent, 'security_get_scan', { scan_id: first.scanId })
    assert.equal(firstScan.target, fixture)
    assert.ok(firstScan.findings.some(f => f.locations.some(l => l.role === 'sink')))
    checks.push({ name: 'session-workspace-isolation-and-dataflow', scanId: first.scanId, neighborScanId: second.scanId, processCwd: process.cwd() })
    await call(agent, 'security_cancel_investigation', { scan_id: first.scanId, reason: 'Desktop fixture recovery check.' })
    assert.equal((await call(agent, 'security_resume_investigation', { scan_id: first.scanId })).lifecycle, 'validation')
    await close(agent, first.scanId)
    checks.push({ name: 'engine-full-audit-receipts-resume-exports', scanId: first.scanId })
    const denied = await call(agent, 'security_install_precommit_hook', { approved: false }, true)
    assert.equal(denied.isError, true); assert.match(denied.error.message, /requires approved: true/)
    checks.push({ name: 'approval-acknowledgement-denied' })
    for (const answer of ['rejected', 'unavailable', 'cancelled', 'allowed-once']) {
      const approver = await root(fixture, answer)
      approver.followup(createUserMessage({ content: [{ type: 'text', text: 'COMPAT_APPROVAL_FIXTURE' }], source: { kind: 'user' } }))
      await approver.whenIdle()
      const events = approver.session.snapshotEvents()
      assert.equal(events.filter(e => e.type === 'approval/asked').length, 1)
      assert.deepEqual(events.filter(e => e.type === 'approval/decided').map(e => e.data.outcome), [answer])
      const hook = await readFile(join(fixture, '.git/hooks/pre-commit'), 'utf8').catch(e => e.code === 'ENOENT' ? '' : Promise.reject(e))
      assert.equal(Boolean(hook), answer === 'allowed-once')
      checks.push({ name: 'native-approval-audit-and-workspace-write', outcome: answer })
    }
    const standard = await call(agent, 'security_scan', { discovery: 'llm' })
    assert.ok(standard.findings > 0)
    await close(agent, standard.scanId)
    checks.push({ name: 'scripted-native-agent-standard-audit', scanId: standard.scanId, jobId: standard.discoveryJobId })
    const diff = await call(agent, 'security_review_diff', { discovery: 'llm', mode: 'working_tree' })
    await close(agent, diff.scanId)
    checks.push({ name: 'scripted-native-agent-diff-audit', scanId: diff.scanId, jobId: diff.discoveryJobId })
    const investigation = await call(agent, 'security_start_investigation', { mode: 'deep' })
    const deep = await call(agent, 'security_start_deep_discovery', { scan_id: investigation.scanId, max_rounds: 2 })
    assert.equal(deep.lifecycle, 'saturated')
    await close(agent, investigation.scanId)
    assert.equal('workers' in deep, false, 'Public DTO must not leak internal worker claim tokens')
    checks.push({ name: 'scripted-native-agent-deep-audit', scanId: investigation.scanId, jobId: deep.id })
    // 真正运行中的六个 Agent 在取消后必须退出，持久化 Job 再由新一轮接续。
    const interrupted = await call(agent, 'security_start_investigation', { mode: 'deep' })
    adapter.holdWorkers = true
    const entered = new Promise(resolve => { adapter.workerEntered = resolve })
    const controller = new AbortController()
    const pending = call(agent, 'security_start_deep_discovery', { scan_id: interrupted.scanId, max_rounds: 2 }, true, controller.signal)
    await entered
    controller.abort(new Error('Desktop compatibility cancellation fixture'))
    const aborted = await pending
    assert.equal(aborted.isError, true)
    adapter.holdWorkers = false
    const jobFiles = await readdir(join(sandbox, 'state/deep-discovery'))
    const jobs = await Promise.all(jobFiles.map(file => readFile(join(sandbox, 'state/deep-discovery', file), 'utf8').then(JSON.parse)))
    const cancelledJob = jobs.find(job => job.scanId === interrupted.scanId)
    assert.equal(cancelledJob.lifecycle, 'cancelled')
    for (const worker of cancelledJob.workers) assert.equal(ctx.agents.get(worker.sessionId), undefined)
    const resumed = await call(agent, 'security_resume_deep_discovery', { job_id: cancelledJob.id })
    assert.equal(resumed.lifecycle, 'saturated')
    await close(agent, interrupted.scanId)
    checks.push({ name: 'native-agent-cancellation-disposal-resume', scanId: interrupted.scanId, jobId: resumed.id })
    const fullDeep = await call(agent, 'security_run_deep_investigation', { max_rounds: 2 })
    assert.equal(fullDeep.lifecycle, 'completed',JSON.stringify({result:fullDeep,states:[...adapter.states.values()].filter(s=>s.kind==='closure').map(s=>({kind:s.kind,phase:s.phase,last:s.last,step:s.step,visible:s.visible}))}))
    assert.equal((await call(agent, 'security_verify_scan_bundle', { scan_id: fullDeep.scanId })).valid, true)
    checks.push({ name: 'scripted-native-full-deep-independent-audits-and-sized-closure', ...fullDeep })
    for(const kind of ['standard','diff']){
      adapter[kind==='standard'?'holdStandard':'holdDiff']=true
      const entered=new Promise(resolve=>{adapter.workerEntered=resolve}),controller=new AbortController()
      const pending=call(agent,kind==='standard'?'security_scan':'security_review_diff',{discovery:'llm'},true,controller.signal)
      await entered;controller.abort(new Error('Interrupted '+kind+' fixture'));assert.equal((await pending).isError,true)
      adapter[kind==='standard'?'holdStandard':'holdDiff']=false
      const directory=join(sandbox,'state',kind==='standard'?'llm-discovery':'diff-discovery'),jobs=await Promise.all((await readdir(directory)).map(file=>readFile(join(directory,file),'utf8').then(JSON.parse))),job=jobs.find(j=>j.lifecycle==='cancelled')
      assert.ok(job,'Cancelled job must be durably retained')
      const resumed=await call(agent,kind==='standard'?'security_resume_standard_scan':'security_resume_diff_scan',{job_id:job.id});assert.equal(resumed.complete,true);assert.equal((await call(agent,'security_verify_scan_bundle',{scan_id:job.scanId})).valid,true)
      checks.push({name:'native-'+kind+'-cancellation-and-public-resume',scanId:job.scanId})
    }
    const closureScan=await call(agent,'security_start_investigation',{mode:'deep'});adapter.holdClaimedClosure=true
    const closureEntered=new Promise(resolve=>{adapter.workerEntered=resolve}),closureController=new AbortController(),pendingClosure=call(agent,'security_start_deep_closure',{scan_id:closureScan.scanId,phase:'validation'},true,closureController.signal)
    await closureEntered;closureController.abort(new Error('Interrupt claimed validation fixture'));assert.equal((await pendingClosure).isError,true);adapter.holdClaimedClosure=false
    const closureJobs=await Promise.all((await readdir(join(sandbox,'state/deep-closure'))).map(file=>readFile(join(sandbox,'state/deep-closure',file),'utf8').then(JSON.parse))),closureJob=closureJobs.find(j=>j.scanId===closureScan.scanId)
    const pendingScan=await call(agent,'security_get_scan',{scan_id:closureScan.scanId});assert.ok(pendingScan.tasks.every(t=>t.status!=='claimed'),'Disposed reviewer claims must be released immediately')
    const resumedClosure=await call(agent,'security_resume_deep_closure',{job_id:closureJob.id});assert.equal(resumedClosure.lifecycle,'completed');await close(agent,closureScan.scanId)
    checks.push({name:'native-claimed-closure-cancellation-release-and-resume',scanId:closureScan.scanId})
    const disclosure=await call(agent,'security_start_disclosure_campaign',{vulnerabilities:[{id:'fixture-eval',title:'Fixture evaluator report',notes:'The deliberately vulnerable fixed fixture evaluates query text; this campaign checks report protocol only.',source_paths:['app.ts']}]});assert.equal(disclosure.lifecycle,'completed');assert.ok((await readFile(join(disclosure.reportsDirectory,'fixture-eval.md'),'utf8')).includes('not_run'));checks.push({name:'native-bound-disclosure-writer-and-source-report',campaignId:disclosure.id})
    assert.deepEqual(failedWorkerCalls, [])
    assert.ok(created.some(a => a.parentSession === agent.id))
    return { passed: true, externalModelAudit: 'NOT_RUN_NO_CREDENTIAL', checks, executions, agentCreated: created, agentDisposed: disposed, scriptedModelRequests: adapter.requests, expectedCancelledCalls }
  } finally {
    for (const h of handles) await h.dispose()
    offCreate(); offDispose(); offResult()
  }
}
