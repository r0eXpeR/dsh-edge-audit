import { flowSemanticsVersion, prepareFlowSemantics, resolvedFunctionDeclaration, returnedSource, returnedFlowTraces, hasReturnedFlow, semanticProcessSink, type FlowTrace } from './ast-flow-semantics.js'
const analyzerVersion = createHash('sha256').update(readFileSync(new URL(import.meta.url))).update(flowSemanticsVersion).update(process.versions.node).update(readFileSync(new URL('../package.json',import.meta.resolve('@typescript-eslint/typescript-estree')))).digest('hex')
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { cachedAnalysis } from './analysis-cache.js'
import { parse } from '@typescript-eslint/typescript-estree'
import { dirname, extname, join, normalize } from 'node:path'
import type { Candidate } from './scanner.js'
import type { Evidence, Severity } from './contracts.js'

interface AstNode {
  type?: string
  range?: [number, number]
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } }
  [key: string]: unknown
}

interface AstRule { id: string; title: string; cwe: string; severity: Severity; rationale: string; sinks: string[] }
interface FunctionRecord { name: string; params: string[]; body: AstNode; declaration: AstNode }
interface FunctionSink { rule: AstRule; sink: string; node: AstNode; file?: string; source?: string; trace?: Array<{file:string;line:number;excerpt:string}> }
interface ModuleFunction extends FunctionRecord { id: string; file: string; source: string }
interface ModuleRecord { file: string; source: string; program: AstNode; functions: Map<string, ModuleFunction>; exports: Map<string, string>; imports: Map<string, { file: string; exported: string }>; namespaces: Map<string, string> }
const moduleDeclarations = new WeakMap<AstNode, ModuleFunction>()

export interface JavaScriptModule { file: string; source: string }
export interface ModuleGraphAnalysis { candidates: Candidate[]; parseErrors: Array<{ file: string; message: string }> }

const AST_RULES: AstRule[] = [
  { id: 'dangerous-dynamic-code', title: 'Dynamic code execution from request data', cwe: 'CWE-95', severity: 'high', rationale: 'Request-derived data reaches dynamic code evaluation.', sinks: ['eval', 'function'] },
  { id: 'shell-command-construction', title: 'Command execution from request data', cwe: 'CWE-78', severity: 'high', rationale: 'Request-derived data reaches a process-execution API.', sinks: ['exec', 'execsync', 'execfile', 'execfilesync', 'spawn', 'spawnsync', 'system', 'popen'] },
  { id: 'path-traversal-sink', title: 'Filesystem operation from request data', cwe: 'CWE-22', severity: 'medium', rationale: 'Request-derived data reaches a filesystem API without a proven containment control.', sinks: ['readfile', 'writefile', 'appendfile', 'open', 'createreadstream', 'createwritestream', 'sendfile'] },
  { id: 'ssrf-request-sink', title: 'Outbound request from request data', cwe: 'CWE-918', severity: 'medium', rationale: 'Request-derived data selects an outbound network destination.', sinks: ['fetch', 'request', 'get', 'post'] },
  { id: 'sql-injection-query-construction', title: 'SQL query construction from request data', cwe: 'CWE-89', severity: 'high', rationale: 'Request-derived data reaches a database query-text API.', sinks: ['query', 'execute', 'raw', 'queryraw', 'executeraw'] },
  { id: 'prototype-pollution-merge', title: 'Prototype-polluting merge from request data', cwe: 'CWE-1321', severity: 'medium', rationale: 'Request-derived object data reaches a generic object merge primitive without a proven prototype-key filter.', sinks: ['assign', 'merge'] },
  { id: 'weak-randomness-security', title: 'Predictable randomness in a security field', cwe: 'CWE-330', severity: 'medium', rationale: 'Math.random() reaches a security-sensitive value where a cryptographic random source is required.', sinks: [] },
  { id: 'hardcoded-secret-marker', title: 'Embedded credential literal', cwe: 'CWE-798', severity: 'medium', rationale: 'A credential-named field contains a non-placeholder string literal that should be moved to managed secret storage.', sinks: [] },
  { id: 'tls-verification-disabled', title: 'TLS certificate verification disabled', cwe: 'CWE-295', severity: 'high', rationale: 'A TLS client configuration explicitly disables certificate verification.', sinks: [] },
  { id: 'cors-wildcard-credentials', title: 'Credentialed wildcard CORS policy', cwe: 'CWE-942', severity: 'medium', rationale: 'A CORS middleware configuration allows wildcard or reflected origins with credentials.', sinks: [] },
]

function children(node: AstNode): AstNode[] {
  const values: AstNode[] = []
  for (const [key, value] of Object.entries(node)) {
    if (key === 'parent' || key === 'loc' || key === 'range' || key === 'tokens' || key === 'comments') continue
    if (value && typeof value === 'object' && 'type' in value) values.push(value as AstNode)
    if (Array.isArray(value)) for (const item of value) if (item && typeof item === 'object' && 'type' in item) values.push(item as AstNode)
  }
  return values
}

function walk(node: AstNode, visit: (node: AstNode) => void): void { visit(node); for (const child of children(node)) walk(child, visit) }
function isFunction(node: AstNode | null | undefined): boolean { return node?.type === 'FunctionDeclaration' || node?.type === 'FunctionExpression' || node?.type === 'ArrowFunctionExpression' }
function walkFunction(node: AstNode, visit: (node: AstNode) => void, root = true): void { visit(node); for (const child of children(node)) { if (isFunction(child)) continue; walkFunction(child, visit, false) } }
function id(node: AstNode | undefined): string | undefined { return node?.type === 'Identifier' && typeof node.name === 'string' ? node.name : undefined }
function line(source: string, number: number): string { return source.split(/\r?\n/)[number - 1]?.trim().slice(0, 240) ?? '' }
function memberName(node: AstNode | undefined): string {
  if (!node) return ''
  if (node.type === 'Identifier' && typeof node.name === 'string') return node.name
  if (node.type === 'ThisExpression') return 'this'
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const object = memberName(node.object as AstNode); const property = node.computed ? literal(node.property as AstNode) : memberName(node.property as AstNode)
    return [object, property].filter(Boolean).join('.')
  }
  return ''
}
function literal(node: AstNode | undefined): string { return node?.type === 'Literal' && typeof node.value === 'string' ? node.value : '' }

interface SavedReturnValue { expression:AstNode; state:Set<string> }
const returnedBindings=new WeakMap<Set<string>,Map<string,SavedReturnValue[]>>()
function savedReturnExpressions(node:AstNode,state:Set<string>):SavedReturnValue[]|undefined{
  const key=id(node)
  if(key)return returnedBindings.get(state)?.get(key)
  const child=node.type==='MemberExpression'||node.type==='OptionalMemberExpression'?'object':node.type==='AwaitExpression'?'argument':['ChainExpression','TSAsExpression','TSNonNullExpression','TSTypeAssertion'].includes(node.type??'')?'expression':undefined
  if(!child)return
  return savedReturnExpressions(node[child] as AstNode,state)?.map(value=>({expression:{...node,[child]:value.expression},state:value.state}))
}
function sourceExpression(node: AstNode | undefined, tainted: Set<string>, replayDepth=0): boolean {
  if (!node) return false
  if(replayDepth>64)return false
  const saved=savedReturnExpressions(node,tainted)
  if(saved)return saved.some(value=>sourceExpression(value.expression,value.state,replayDepth+1))
  const returned=returnedSource(node,leaf=>sourceExpression(leaf,tainted,replayDepth+1))
  if(returned!==undefined)return returned
  if (['AwaitExpression','TSAsExpression','TSNonNullExpression','TSTypeAssertion'].includes(node.type ?? '')) return sourceExpression((node.argument ?? node.expression) as AstNode,tainted)
  if (node.type === 'Identifier') return tainted.has(String(node.name))
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
    const name = memberName(node).toLowerCase()
    if (/^(?:req|request|ctx\.request|event)\.(?:body|query|params|param|headers|cookies|url|path)(?:\.|$)/.test(name)) return true
    return sourceExpression(node.object as AstNode, tainted)
  }
  if (node.type === 'TemplateLiteral') return Array.isArray(node.expressions) && node.expressions.some(expression => sourceExpression(expression as AstNode, tainted))
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression' || node.type === 'AssignmentExpression') return sourceExpression(node.left as AstNode, tainted) || sourceExpression(node.right as AstNode, tainted)
  if (node.type === 'ConditionalExpression') return sourceExpression(node.consequent as AstNode, tainted) || sourceExpression(node.alternate as AstNode, tainted)
  if (node.type === 'ArrayExpression') return Array.isArray(node.elements) && node.elements.some(element => sourceExpression(element as AstNode, tainted))
  if (node.type === 'ObjectExpression') return Array.isArray(node.properties) && node.properties.some(property => sourceExpression((property as AstNode).value as AstNode, tainted))
  if (node.type === 'ChainExpression') return sourceExpression(node.expression as AstNode, tainted)
  if (node.type === 'NewExpression') {
    const callee = memberName(node.callee as AstNode).toLowerCase()
    return (callee === 'url' || callee === 'globalthis.url') && sourceExpression(((node.arguments ?? []) as AstNode[])[0], tainted)
  }
  if (node.type === 'CallExpression') {
    const callee = memberName(node.callee as AstNode).toLowerCase()
    const args = (node.arguments ?? []) as AstNode[]
    if (['string', 'globalthis.string', 'json.stringify'].includes(callee)) return sourceExpression(args[0], tainted)
    if (/(?:^|\.)tostring$/.test(callee)) return sourceExpression((node.callee as AstNode)?.object as AstNode, tainted)
    return /(?:decode|encode|trim|replace|slice|substring|concat|join|tolowercase|touppercase|normalize|format)$/.test(callee) && (args.some(argument => sourceExpression(argument, tainted)) || sourceExpression((node.callee as AstNode)?.object as AstNode, tainted))
  }
  return false
}

const taintProvenance=new WeakMap<Set<string>,Map<string,FlowTrace[]>>()
function sourceProofTraces(node:AstNode|undefined,state:Set<string>):FlowTrace[]{
  if(!node)return []
  const traces=returnedFlowTraces(node)
  walk(node,child=>{const key=id(child);if(key)traces.push(...(taintProvenance.get(state)?.get(key)??[]))})
  return [...new Map(traces.map(item=>[`${item.file}:${item.line}`,item])).values()]
}
function copyTaint(state:Set<string>):Set<string>{const result=new Set(state);taintProvenance.set(result,new Map(taintProvenance.get(state)));returnedBindings.set(result,new Map(returnedBindings.get(state)));return result}
function candidate(rule: AstRule, source: string, file: string, node: AstNode, sink: string, taintedArgument: AstNode, state=new Set<string>()): Candidate | undefined {
  const number = node.loc?.start.line
  if (!number) return undefined
  const excerpt = line(source, number)
  const evidence: Evidence[] = [
    { kind: 'pattern', detail: `AST resolved sensitive call ${sink}.`, location: { file, line: number, excerpt, role: 'sink' } },
    { kind: 'context', detail: 'AST local data-flow analysis resolved a request-derived value in a sensitive call argument.', location: { file, line: taintedArgument.loc?.start.line ?? number, excerpt: line(source, taintedArgument.loc?.start.line ?? number), role: 'entrypoint' } },
  ]
  evidence.push(...sourceProofTraces(taintedArgument,state).map(location=>({kind:'context' as const,detail:'AST resolved a source-backed helper return in the value reaching this sink.',location:{...location,role:'propagation' as const}})))
  return { rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe, evidence }
}

function localFunctions(program: AstNode): FunctionRecord[] {
  const records: FunctionRecord[] = []
  walk(program, node => {
    const declaration = node.type === 'FunctionDeclaration' ? node : node.type === 'VariableDeclarator' && isFunction(node.init as AstNode) ? node.init as AstNode : undefined
    const name = node.type === 'FunctionDeclaration' ? id(node.id as AstNode) : node.type === 'VariableDeclarator' ? id(node.id as AstNode) : undefined
    if (!declaration || !name) return
    const params = Array.isArray(declaration.params) ? declaration.params.map(item => id(item as AstNode) ?? ((item as AstNode).type==='AssignmentPattern'?id((item as AstNode).left as AstNode):undefined) ?? '') : []
    records.push({ name, params, body: declaration.body as AstNode, declaration })
  })
  return records
}

function assignmentNames(pattern: AstNode | undefined): string[] {
  const direct = id(pattern)
  if (direct) return [direct]
  if (pattern?.type === 'ObjectPattern') return ((pattern.properties ?? []) as AstNode[]).flatMap(property => property.type === 'Property' ? assignmentNames(property.value as AstNode) : property.type === 'RestElement' ? assignmentNames(property.argument as AstNode) : [])
  if (pattern?.type === 'ArrayPattern') return ((pattern.elements ?? []) as Array<AstNode | null>).flatMap(element => assignmentNames(element ?? undefined))
  if (pattern?.type === 'AssignmentPattern') return assignmentNames(pattern.left as AstNode)
  if (pattern?.type === 'RestElement') return assignmentNames(pattern.argument as AstNode)
  return []
}

function assignmentPaths(pattern:AstNode|undefined,path:string[]=[]):Array<{name:string;path:string[]}>{
  if(!pattern)return []
  const direct=id(pattern);if(direct)return [{name:direct,path}]
  if(pattern.type==='AssignmentPattern')return assignmentPaths(pattern.left as AstNode,path)
  if(pattern.type==='ObjectPattern')return ((pattern.properties??[]) as AstNode[]).flatMap(item=>{
    if(item.type!=='Property')return assignmentNames(item).map(name=>({name,path}))
    const key=item.computed?literal(item.key as AstNode):id(item.key as AstNode)??literal(item.key as AstNode)
    return key?assignmentPaths(item.value as AstNode,[...path,key]):[]
  })
  if(pattern.type==='ArrayPattern')return ((pattern.elements??[]) as Array<AstNode|null>).flatMap((item,index)=>assignmentPaths(item??undefined,[...path,String(index)]))
  return assignmentNames(pattern).map(name=>({name,path}))
}
function projectExpression(node:AstNode,path:string[]):AstNode{return path.reduce<AstNode>((object,key)=>({type:'MemberExpression',object,property:{type:'Literal',value:key},computed:true,loc:node.loc}),node)}

function propertyName(node: AstNode | undefined): string { return node?.computed ? literal(node.key as AstNode).toLowerCase() : id(node?.key as AstNode)?.toLowerCase() ?? '' }

function outboundDestinationArguments(argumentsList: AstNode[]): AstNode[] {
  const first = argumentsList[0]
  if (!first || first.type !== 'ObjectExpression') return first ? [first] : []
  const destinations = new Set(['url', 'uri', 'href', 'host', 'hostname', 'baseurl'])
  return ((first.properties ?? []) as AstNode[]).flatMap(property => property.type === 'Property' && destinations.has(propertyName(property)) ? [property.value as AstNode] : [])
}

function prototypeMergeSourceArguments(argumentsList: AstNode[]): AstNode[] {
  // The first argument is the target. Only later source objects can introduce
  // special prototype keys into it.
  return argumentsList.slice(1)
}

function explicitShellOption(node: AstNode | undefined): boolean {
  if (node?.type !== 'ObjectExpression') return false
  let enabled = false
  for (const property of (node.properties ?? []) as AstNode[]) {
    if (property.type === 'SpreadElement') enabled = false // 后续展开属性可能覆盖 shell，不能证明实际配置。
    if (property.type === 'Property' && propertyName(property) === 'shell')
      enabled = (property.value as AstNode)?.value === true || literal(property.value as AstNode).length > 0
  }
  return enabled
}

function sensitiveSinkArguments(rule: AstRule, sink: string, argumentsList: AstNode[]): AstNode[] {
  if (rule.id === 'ssrf-request-sink') return outboundDestinationArguments(argumentsList)
  if (rule.id === 'sql-injection-query-construction') return argumentsList.slice(0, 1)
  if (rule.id === 'prototype-pollution-merge') return prototypeMergeSourceArguments(argumentsList)
  if (rule.id === 'shell-command-construction') {
    // spawn/execFile 系列默认按 argv 传参；显式启用 shell 后，参数也会进入命令解释边界。
    if (/(?:^|\.)(?:spawn|spawnsync|execfile|execfilesync)$/.test(sink)) {
      if(explicitShellOption(argumentsList[2]))return argumentsList.slice(0,2)
      const executable=literal(argumentsList[0]),argv=argumentsList[1]
      if(/^(?:.*[\\/])?(?:sh|bash|dash|zsh|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|python[\d.]*|node|perl|ruby)$/i.test(executable) && argv?.type==='ArrayExpression'){
        const args=(argv.elements??[]) as Array<AstNode|null>
        return [argumentsList[0],...args.flatMap((arg,index)=>/^(?:-c|-lc|\/c|-command|-encodedcommand|-e|--eval)$/i.test(literal(arg??undefined))&&args[index+1]?[args[index+1]!]:[])]
      }
    }
    return argumentsList.slice(0, 1)
  }
  if (rule.id === 'path-traversal-sink' || (rule.id === 'dangerous-dynamic-code' && sink !== 'function')) return argumentsList.slice(0, 1)
  return argumentsList
}

function sinkFor(node: AstNode): Array<{ rule: AstRule; sink: string; argumentsList: AstNode[] }> {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return []
  const canonical=semanticProcessSink(node)
  if(canonical===null)return []
  const sink = canonical ?? memberName(node.callee as AstNode).toLowerCase(); const final = sink.split('.').at(-1) ?? sink; const argumentsList = (node.arguments ?? []) as AstNode[]
  const receiver=(node.callee as AstNode)?.object as AstNode|undefined
  if(final==='exec' && ((receiver?.type==='Literal' && receiver.regex) || (receiver?.type==='NewExpression' && /^(?:RegExp|globalThis\.RegExp)$/.test(memberName(receiver.callee as AstNode)))))return []
  return AST_RULES.filter(rule => rule.sinks.includes(final)
    && (rule.id !== 'ssrf-request-sink' || /(?:fetch|axios|request|http|https)/.test(sink))
    && (rule.id !== 'sql-injection-query-construction' || /(?:^|\.)(?:db|database|pool|client|connection|manager|repository|sequelize|knex)\.(?:query|execute|raw|queryraw|executeraw)$/.test(sink))
    && (rule.id !== 'prototype-pollution-merge' || /^(?:object\.assign|(?:_|lodash)\.merge)$/.test(sink)))
    .map(rule => ({ rule, sink, argumentsList: sensitiveSinkArguments(rule, sink, argumentsList) }))
}

const SECURITY_RANDOM_FIELD = /(?:token|secret|session|password|reset|nonce|csrf|verification|verify|otp|code)/i
const SECRET_FIELD = /(?:api[_-]?key|access[_-]?key|secret|password|token|private[_-]?key|credential)/i
const PLACEHOLDER_SECRET = /(?:^|[-_\s])(?:example|sample|dummy|placeholder|changeme|replace(?:[_-]?me)?|your|not[_-]?a[_-]?real)(?:[-_\s]|$)|^(?:test|development|dev)[-_\s]/i

function randomBindingSources(program: AstNode): Map<string, AstNode> {
  const assignments: Array<{ name: string; value: AstNode }> = []
  walk(program, node => {
    if (node.type === 'VariableDeclarator') {
      const name = id(node.id as AstNode); const value = node.init as AstNode | undefined
      if (name && value) assignments.push({ name, value })
    }
    if (node.type === 'AssignmentExpression') {
      const name = id(node.left as AstNode); const value = node.right as AstNode | undefined
      if (name && value) assignments.push({ name, value })
    }
  })
  const bindings = new Map<string, AstNode>()
  for (let pass = 0; pass < assignments.length + 1; pass++) {
    let changed = false
    for (const assignment of assignments) {
      if (bindings.has(assignment.name)) continue
      const source = mathRandomSource(assignment.value, bindings)
      if (source) { bindings.set(assignment.name, source); changed = true }
    }
    if (!changed) break
  }
  return bindings
}

function mathRandomSource(node: AstNode | undefined, bindings: Map<string, AstNode>): AstNode | undefined {
  if (!node) return undefined
  if (node.type === 'Identifier') return bindings.get(String(node.name))
  if (node.type === 'ChainExpression' || node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion' || node.type === 'TSNonNullExpression' || node.type === 'AwaitExpression') return mathRandomSource(node.expression as AstNode, bindings)
  if (node.type === 'CallExpression') {
    if (memberName(node.callee as AstNode).toLowerCase() === 'math.random') return node
    const calleeSource = mathRandomSource(node.callee as AstNode, bindings)
    if (calleeSource) return calleeSource
    return ((node.arguments ?? []) as AstNode[]).map(argument => mathRandomSource(argument, bindings)).find((source): source is AstNode => Boolean(source))
  }
  if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') return mathRandomSource(node.object as AstNode, bindings)
  if (node.type === 'TemplateLiteral') return ((node.expressions ?? []) as AstNode[]).map(expression => mathRandomSource(expression, bindings)).find((source): source is AstNode => Boolean(source))
  if (node.type === 'BinaryExpression' || node.type === 'LogicalExpression' || node.type === 'AssignmentExpression') return mathRandomSource(node.left as AstNode, bindings) ?? mathRandomSource(node.right as AstNode, bindings)
  if (node.type === 'ConditionalExpression') return mathRandomSource(node.consequent as AstNode, bindings) ?? mathRandomSource(node.alternate as AstNode, bindings)
  if (node.type === 'SequenceExpression') return ((node.expressions ?? []) as AstNode[]).map(expression => mathRandomSource(expression, bindings)).find((source): source is AstNode => Boolean(source))
  return undefined
}

function weakRandomnessCandidate(rule: AstRule, source: string, file: string, target: string, sink: AstNode, random: AstNode): Candidate | undefined {
  const number = sink.loc?.start.line
  const randomLine = random.loc?.start.line
  if (!number || !randomLine) return undefined
  const excerpt = line(source, number)
  return {
    rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe,
    evidence: [
      { kind: 'pattern', detail: `AST resolved Math.random() reaching security-sensitive field ${target}.`, location: { file, line: randomLine, excerpt: line(source, randomLine), role: 'entrypoint' } },
      { kind: 'context', detail: 'AST local value-flow analysis resolved a non-cryptographic random source in a security-sensitive assignment.', location: { file, line: number, excerpt, role: 'sink' } },
    ],
  }
}

function weakRandomnessCandidates(program: AstNode, source: string, file: string): Candidate[] {
  const rule = AST_RULES.find(item => item.id === 'weak-randomness-security')
  if (!rule) return []
  const bindings = randomBindingSources(program); const candidates: Candidate[] = []
  const report = (target: string, sink: AstNode, value: AstNode | undefined): void => {
    if (!SECURITY_RANDOM_FIELD.test(target)) return
    const random = mathRandomSource(value, bindings)
    const item = random && weakRandomnessCandidate(rule, source, file, target, sink, random)
    if (item) candidates.push(item)
  }
  walk(program, node => {
    if (node.type === 'VariableDeclarator') report(id(node.id as AstNode) ?? '', node, node.init as AstNode | undefined)
    if (node.type === 'AssignmentExpression') {
      const left = node.left as AstNode
      const target = id(left) ?? (left.type === 'MemberExpression' || left.type === 'OptionalMemberExpression' ? left.computed ? literal(left.property as AstNode) : id(left.property as AstNode) ?? '' : '')
      report(target, node, node.right as AstNode | undefined)
    }
    if (node.type === 'Property') report(propertyName(node), node, node.value as AstNode | undefined)
  })
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return [...unique.values()]
}

function hardcodedSecretCandidate(rule: AstRule, source: string, file: string, field: string, sink: AstNode, value: string): Candidate | undefined {
  const number = sink.loc?.start.line
  if (!number) return undefined
  const excerpt = line(source, number)
  return {
    rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe,
    evidence: [
      { kind: 'pattern', detail: `AST resolved a string literal assigned to credential field ${field}.`, location: { file, line: number, excerpt, role: 'sink' } },
      { kind: 'context', detail: `The embedded literal is ${value.length} characters and does not match a recognized placeholder form.`, location: { file, line: number, excerpt, role: 'root_control' } },
    ],
  }
}

function hardcodedSecretCandidates(program: AstNode, source: string, file: string): Candidate[] {
  const rule = AST_RULES.find(item => item.id === 'hardcoded-secret-marker')
  if (!rule) return []
  const candidates: Candidate[] = []
  const report = (field: string, sink: AstNode, value: AstNode | undefined): void => {
    const embedded = literal(value)
    if (!SECRET_FIELD.test(field) || embedded.length < 8 || PLACEHOLDER_SECRET.test(embedded)) return
    const item = hardcodedSecretCandidate(rule, source, file, field, sink, embedded)
    if (item) candidates.push(item)
  }
  walk(program, node => {
    if (node.type === 'VariableDeclarator') report(id(node.id as AstNode) ?? '', node, node.init as AstNode | undefined)
    if (node.type === 'AssignmentExpression') {
      const left = node.left as AstNode
      const field = id(left) ?? (left.type === 'MemberExpression' || left.type === 'OptionalMemberExpression' ? left.computed ? literal(left.property as AstNode) : id(left.property as AstNode) ?? '' : '')
      report(field, node, node.right as AstNode | undefined)
    }
    if (node.type === 'Property' || node.type === 'PropertyDefinition') report(propertyName(node), node, node.value as AstNode | undefined)
  })
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return [...unique.values()]
}

function falseLiteral(node: AstNode | undefined): boolean { return node?.type === 'Literal' && node.value === false }

function objectBindingSources(program: AstNode): Map<string, AstNode> {
  const bindings = new Map<string, AstNode>()
  walk(program, node => {
    if (node.type !== 'VariableDeclarator' && node.type !== 'AssignmentExpression') return
    const name = id(node.type === 'VariableDeclarator' ? node.id as AstNode : node.left as AstNode)
    const value = node.type === 'VariableDeclarator' ? node.init as AstNode | undefined : node.right as AstNode | undefined
    if (name && value?.type === 'ObjectExpression') bindings.set(name, value)
  })
  return bindings
}

function tlsConfigurationArgument(node: AstNode | undefined, bindings: Map<string, AstNode>): AstNode | undefined {
  if (node?.type === 'ObjectExpression') return node
  return node?.type === 'Identifier' ? bindings.get(String(node.name)) : undefined
}

function tlsClientCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return false
  const callee = memberName(node.callee as AstNode).toLowerCase()
  return /^(?:request|https\.(?:request|get)|tls\.(?:connect|createsecurecontext)|https\.agent)$/.test(callee)
}

function tlsDisabledCandidate(rule: AstRule, source: string, file: string, property: AstNode, call: AstNode): Candidate | undefined {
  const number = property.loc?.start.line; const callLine = call.loc?.start.line
  if (!number || !callLine) return undefined
  const excerpt = line(source, number)
  return {
    rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe,
    evidence: [
      { kind: 'pattern', detail: 'AST resolved rejectUnauthorized: false in a TLS client configuration object.', location: { file, line: number, excerpt, role: 'root_control' } },
      { kind: 'context', detail: 'AST resolved that configuration object as an argument to a supported TLS client call.', location: { file, line: callLine, excerpt: line(source, callLine), role: 'sink' } },
    ],
  }
}

function tlsVerificationDisabledCandidates(program: AstNode, source: string, file: string): Candidate[] {
  const rule = AST_RULES.find(item => item.id === 'tls-verification-disabled')
  if (!rule) return []
  const bindings = objectBindingSources(program); const candidates: Candidate[] = []
  walk(program, node => {
    if (!tlsClientCall(node)) return
    const args = (node.arguments ?? []) as AstNode[]
    for (const argument of args) {
      const config = tlsConfigurationArgument(argument, bindings)
      if (!config) continue
      for (const property of (config.properties ?? []) as AstNode[]) {
        if (property.type !== 'Property' || propertyName(property) !== 'rejectunauthorized' || !falseLiteral(property.value as AstNode)) continue
        const item = tlsDisabledCandidate(rule, source, file, property, node)
        if (item) candidates.push(item)
      }
    }
  })
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return [...unique.values()]
}

function trueLiteral(node: AstNode | undefined): boolean { return node?.type === 'Literal' && node.value === true }
function wildcardOrigin(node: AstNode | undefined): boolean { return trueLiteral(node) || literal(node) === '*' }

function corsMiddlewareCall(node: AstNode): boolean {
  if (node.type !== 'CallExpression') return false
  return memberName(node.callee as AstNode).toLowerCase() === 'cors'
}

function corsWildcardCredentialsCandidates(program: AstNode, source: string, file: string): Candidate[] {
  const rule = AST_RULES.find(item => item.id === 'cors-wildcard-credentials')
  if (!rule) return []
  const bindings = objectBindingSources(program); const candidates: Candidate[] = []
  walk(program, node => {
    if (!corsMiddlewareCall(node)) return
    const config = tlsConfigurationArgument(((node.arguments ?? []) as AstNode[])[0], bindings)
    if (!config) return
    const properties = (config.properties ?? []) as AstNode[]
    const origin = properties.find(property => property.type === 'Property' && ['origin', 'origins'].includes(propertyName(property)) && wildcardOrigin(property.value as AstNode))
    const credentials = properties.find(property => property.type === 'Property' && ['credentials', 'supportscredentials'].includes(propertyName(property)) && trueLiteral(property.value as AstNode))
    if (!origin || !credentials || !origin.loc?.start.line || !credentials.loc?.start.line) return
    const number = origin.loc.start.line; const excerpt = line(source, number)
    candidates.push({
      rule: rule.id, severity: rule.severity, file, line: number, excerpt, rationale: rule.rationale, cwe: rule.cwe,
      evidence: [
        { kind: 'pattern', detail: 'AST resolved a wildcard or reflected origin in a CORS middleware configuration object.', location: { file, line: number, excerpt, role: 'root_control' } },
        { kind: 'context', detail: 'AST resolved credential support in the same CORS middleware configuration object.', location: { file, line: credentials.loc.start.line, excerpt: line(source, credentials.loc.start.line), role: 'expected_control' } },
        { kind: 'context', detail: 'AST resolved this object as an argument to cors().', location: { file, line: node.loc?.start.line ?? number, excerpt: line(source, node.loc?.start.line ?? number), role: 'sink' } },
      ],
    })
  })
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return [...unique.values()]
}

/** 函数局部绑定隔离；不把同名变量跨不相关作用域传播。 */
function analysisScopes(program: AstNode): AstNode[] { const scopes=[program]; walk(program,node=>{if(isFunction(node)&&node.body)scopes.push(node.body as AstNode)});return scopes }
/** 每个作用域只向前处理一次完整语句；调用点取快照，分支只增加可能污点。 */
function taintTracker(scope: AstNode, seeds: string[] = []): (node: AstNode) => Set<string> {
  const body = (scope.type === 'Program' || scope.type === 'BlockStatement') && Array.isArray(scope.body) ? scope.body as AstNode[] : []
  let tainted = new Set(seeds), nextStatement = 0, lastBefore = -1
  const transfer = (assignment: AstNode, definite: boolean, state: Set<string>): void => {
    const pattern = (assignment.type === 'VariableDeclarator' ? assignment.id : assignment.left) as AstNode
    const value = (assignment.type === 'VariableDeclarator' ? assignment.init : assignment.right) as AstNode | undefined
    const captured=copyTaint(state),saved=returnedBindings.get(captured)!
    if(!taintProvenance.has(state))taintProvenance.set(state,new Map())
    if(!returnedBindings.has(state))returnedBindings.set(state,new Map())
    const provenance=taintProvenance.get(state)!
    const values=returnedBindings.get(state)!
    let tracksReturns=!!value&&hasReturnedFlow(value)
    if(value)walk(value,node=>{if(id(node)&&saved.has(id(node)!))tracksReturns=true})
    for (const {name,path} of assignmentPaths(pattern)) {
      const projected=value?projectExpression(value,path):undefined
      const flows=sourceExpression(projected,captured)
      const proof=sourceProofTraces(value,captured)
      if (flows){state.add(name);provenance.set(name,definite?proof:[...(provenance.get(name)??[]),...proof])}
      else if (definite){state.delete(name);provenance.delete(name)}
      if(tracksReturns&&projected){
        const previous=values.get(name)??(captured.has(name)?[{expression:{type:'Identifier',name},state:captured}]:[])
        values.set(name,definite?[{expression:projected,state:captured}]:[...previous,{expression:projected,state:captured}].slice(-64))
      }else if(definite)values.delete(name)
    }
  }
  const possibleAssignments = (statement: AstNode, state: Set<string>, before: number): void => {
    if (isFunction(statement)) return
    const assignments: AstNode[] = []
    walkFunction(statement, assignment => {
      if ((assignment.type === 'VariableDeclarator' || assignment.type === 'AssignmentExpression') && (assignment.range?.[0] ?? Number.POSITIVE_INFINITY) < before) assignments.push(assignment)
    })
    assignments.sort((a,b)=>(a.range?.[0]??0)-(b.range?.[0]??0))
    for (const assignment of assignments) transfer(assignment,false,state)
  }
  const completeStatement = (statement: AstNode, state: Set<string>): void => {
    if (statement.type === 'VariableDeclaration') {
      for (const declaration of (statement.declarations ?? []) as AstNode[]) {
        if (declaration.init) possibleAssignments(declaration.init as AstNode,state,Number.POSITIVE_INFINITY)
        transfer(declaration,true,state)
      }
    } else if (statement.type === 'ExpressionStatement' && (statement.expression as AstNode)?.type === 'AssignmentExpression') {
      const assignment = statement.expression as AstNode
      if (assignment.right) possibleAssignments(assignment.right as AstNode,state,Number.POSITIVE_INFINITY)
      transfer(assignment, assignment.operator === '=',state)
    } else possibleAssignments(statement,state,Number.POSITIVE_INFINITY)
  }
  return node => {
    const before = node.range?.[0] ?? Number.POSITIVE_INFINITY
    if (before < lastBefore) { tainted = new Set(seeds); nextStatement = 0 }
    lastBefore = before
    while (nextStatement < body.length && (body[nextStatement]!.range?.[1] ?? Number.POSITIVE_INFINITY) <= before) completeStatement(body[nextStatement++]!,tainted)
    const result = copyTaint(tainted)
    const current = body[nextStatement]
    if (current && (current.range?.[0] ?? Number.POSITIVE_INFINITY) < before) possibleAssignments(current,result,before)
    return result
  }
}

/** Fixed-point summaries for named local functions: parameter index -> reachable sink. */
function localFunctionSinks(program: AstNode): Map<AstNode, Map<number, FunctionSink[]>> {
  const functions = localFunctions(program); const byDeclaration = new Map(functions.map(item => [item.declaration, item])); const summaries = new Map<AstNode, Map<number, FunctionSink[]>>(functions.map(item => [item.declaration, new Map()]))
  const add = (declaration: AstNode, index: number, item: FunctionSink): boolean => {
    const entries = summaries.get(declaration)?.get(index) ?? []; const key = `${item.rule.id}:${item.node.range?.join(':') ?? item.sink}`
    if (entries.some(existing => `${existing.rule.id}:${existing.node.range?.join(':') ?? existing.sink}` === key)) return false
    const target = summaries.get(declaration); if (!target) return false; target.set(index, [...entries, item]); return true
  }
  for (let pass = 0; pass < functions.length * Math.max(2, functions.length) + 1; pass++) {
    let changed = false
    for (const record of functions) for (const [index, param] of record.params.entries()) {
      const taintAt = taintTracker(record.body,[param])
      walkFunction(record.body, node => {
        if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return
        const tainted = taintAt(node)
        for (const sink of sinkFor(node)) if (sink.argumentsList.some(argument => sourceExpression(argument, tainted))) changed = add(record.declaration, index, { rule: sink.rule, sink: sink.sink, node, trace:sink.argumentsList.flatMap(argument=>sourceProofTraces(argument,tainted)) }) || changed
        if (node.type !== 'CallExpression') return
        const target=byDeclaration.get(resolvedFunctionDeclaration(node) as AstNode);if(!target)return
        const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.declaration)
        for (const [targetIndex] of target.params.entries()) if (args[targetIndex] && sourceExpression(args[targetIndex], tainted)) for (const result of nested?.get(targetIndex) ?? []) changed = add(record.declaration, index, result) || changed
      })
    }
    if (!changed) break
  }
  return summaries
}

function analyzeJavaScriptAstUncached(source: string, file: string): { candidates: Candidate[]; parseError?: string } {
  let program: AstNode
  try { program = parse(source, { loc: true, range: true, jsx: true, comment: false }) as unknown as AstNode } catch (error) { return { candidates: [], parseError: error instanceof Error ? error.message : String(error) } }
  prepareFlowSemantics([{program,file,source}])
  const candidates: Candidate[] = [...weakRandomnessCandidates(program, source, file), ...hardcodedSecretCandidates(program, source, file), ...tlsVerificationDisabledCandidates(program, source, file), ...corsWildcardCredentialsCandidates(program, source, file)]; const functions = new Map(localFunctions(program).map(item => [item.declaration, item])); const summaries = localFunctionSinks(program)
  for(const scope of analysisScopes(program)){
  const taintAt=taintTracker(scope)
  walkFunction(scope, node => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return
    const tainted=taintAt(node)
    for (const sink of sinkFor(node)) { const input = sink.argumentsList.find(argument => sourceExpression(argument, tainted)); if (input) { const item = candidate(sink.rule, source, file, node, sink.sink, input,tainted); if (item) candidates.push(item) } }
    const target=functions.get(resolvedFunctionDeclaration(node) as AstNode);if(!target)return
    const argumentsList = (node.arguments ?? []) as AstNode[]
    for (const [index] of target.params.entries()) {
      const input = argumentsList[index]; if (!input || !sourceExpression(input, tainted)) continue
      for (const result of summaries.get(target.declaration)?.get(index) ?? []) {
        const item = candidate(result.rule, source, file, result.node, result.sink, input,tainted)
        if (item) { item.evidence.push(...(result.trace??[]).map(location=>({kind:'context' as const,detail:'Resolved helper-return propagation before the local sink.',location:{...location,role:'propagation' as const}})),{ kind: 'context', detail: `AST local call-chain analysis resolved request-derived input through ${target.name}() to ${result.sink}.`, location: { file, line: node.loc?.start.line ?? item.line, excerpt: line(source, node.loc?.start.line ?? item.line), role: 'propagation' } }); candidates.push(item) }
      }
    }
  })
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return { candidates: [...unique.values()] }
}

function extensionCandidates(path: string): string[] {
  if (extname(path)) return [path]
  return [path, ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(extension => `${path}${extension}`), ...['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].map(extension => join(path, `index${extension}`))]
}

function resolveRelativeModule(file: string, specifier: string, known: Set<string>): string | undefined {
  if (!specifier.startsWith('.')) return undefined
  const base = normalize(join(dirname(file), specifier))
  return extensionCandidates(base).find(candidate => known.has(candidate))
}

function exportDeclarationNames(node: AstNode | null | undefined): string[] {
  // `export {}` 与 `export { a }` 没有 declaration。
  if (!node) return []
  if (node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') return [id(node.id as AstNode)].filter((value): value is string => Boolean(value))
  if (node.type !== 'VariableDeclaration') return []
  return Array.isArray(node.declarations) ? node.declarations.map(item => id((item as AstNode).id as AstNode)).filter((value): value is string => Boolean(value)) : []
}

function requireTarget(node: AstNode | undefined): string | undefined {
  if (node?.type !== 'CallExpression' || id(node.callee as AstNode) !== 'require') return undefined
  const argumentsList = (node.arguments ?? []) as AstNode[]
  return argumentsList.length === 1 ? literal(argumentsList[0]) : undefined
}

function moduleExportProperty(node: AstNode | undefined): string | undefined {
  if (!node || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression')) return undefined
  const object = memberName(node.object as AstNode)
  if (object !== 'exports' && object !== 'module.exports') return undefined
  return node.computed ? literal(node.property as AstNode) : id(node.property as AstNode)
}

function isModuleExports(node: AstNode | undefined): boolean { return memberName(node) === 'module.exports' }

function addCommonJsImport(target: string, pattern: AstNode | undefined, imports: Map<string, { file: string; exported: string }>, namespaces: Map<string, string>): void {
  if (!pattern) return
  if (pattern.type === 'Identifier') {
    const local = String(pattern.name)
    // The binding may be invoked as a default-exported function or accessed as a namespace.
    namespaces.set(local, target)
    imports.set(local, { file: target, exported: 'default' })
    return
  }
  if (pattern.type !== 'ObjectPattern') return
  for (const property of (pattern.properties ?? []) as AstNode[]) {
    if (property.type !== 'Property') continue
    const exported = property.computed ? literal(property.key as AstNode) : id(property.key as AstNode)
    const local = id(property.value as AstNode)
    if (local && exported) imports.set(local, { file: target, exported })
  }
}

function addCommonJsExports(statement: AstNode, file: string, functions: Map<string, ModuleFunction>, exports: Map<string, string>): void {
  if (statement.type !== 'ExpressionStatement') return
  const expression = statement.expression as AstNode
  if (expression?.type !== 'AssignmentExpression' || expression.operator !== '=') return
  const left = expression.left as AstNode; const right = expression.right as AstNode
  const property = moduleExportProperty(left)
  if (property) { const local = id(right); if (local && functions.has(local)) exports.set(property, functions.get(local)!.id); return }
  if (!isModuleExports(left)) return
  const local = id(right)
  if (local && functions.has(local)) { exports.set('default', functions.get(local)!.id); return }
  if (right.type !== 'ObjectExpression') return
  for (const entry of (right.properties ?? []) as AstNode[]) {
    if (entry.type !== 'Property') continue
    const exported = entry.computed ? literal(entry.key as AstNode) : id(entry.key as AstNode)
    const localName = id(entry.value as AstNode)
    if (exported && localName && functions.has(localName)) exports.set(exported, functions.get(localName)!.id)
  }
}

function createModuleRecord(file: string, source: string, known: Set<string>): { record?: ModuleRecord; parseError?: string } {
  let program: AstNode
  try { program = parse(source, { loc: true, range: true, jsx: true, comment: false }) as unknown as AstNode } catch (error) { return { parseError: error instanceof Error ? error.message : String(error) } }
  const functions = new Map<string, ModuleFunction>()
  const topLevel=new Set<AstNode>()
  for(const raw of (program.body??[]) as AstNode[]){
    const statement=['ExportNamedDeclaration','ExportDefaultDeclaration'].includes(raw.type??'')?raw.declaration as AstNode:raw
    if(!statement)continue
    if(isFunction(statement))topLevel.add(statement)
    if(statement.type==='VariableDeclaration')for(const item of (statement.declarations??[]) as AstNode[])if(isFunction(item.init as AstNode))topLevel.add(item.init as AstNode)
  }
  for (const item of localFunctions(program)) {
    const record={ ...item, id: `${file}:${item.name}:${item.declaration.range?.[0]??0}`, file, source }
    functions.set(record.id,record);moduleDeclarations.set(item.declaration,record)
    if(topLevel.has(item.declaration))functions.set(item.name,record)
  }
  const exports = new Map<string, string>(); const imports = new Map<string, { file: string; exported: string }>(); const namespaces = new Map<string, string>()
  const body = Array.isArray(program.body) ? program.body as AstNode[] : []
  for (const statement of body) {
    if (statement.type === 'ImportDeclaration') {
      const specifier = literal(statement.source as AstNode); const target = resolveRelativeModule(file, specifier, known); if (!target) continue
      for (const imported of (statement.specifiers ?? []) as AstNode[]) {
        const local = id(imported.local as AstNode); if (!local) continue
        if (imported.type === 'ImportNamespaceSpecifier') { namespaces.set(local, target); continue }
        const exported = imported.type === 'ImportDefaultSpecifier' ? 'default' : id(imported.imported as AstNode); if (exported) imports.set(local, { file: target, exported })
      }
      continue
    }
    if (statement.type === 'VariableDeclaration') {
      for (const declaration of (statement.declarations ?? []) as AstNode[]) {
        const specifier = requireTarget(declaration.init as AstNode)
        const target = specifier ? resolveRelativeModule(file, specifier, known) : undefined
        if (target) addCommonJsImport(target, declaration.id as AstNode, imports, namespaces)
      }
      continue
    }
    if (statement.type === 'ExportNamedDeclaration') {
      for (const name of exportDeclarationNames(statement.declaration as AstNode)) if (functions.has(name)) exports.set(name, functions.get(name)!.id)
      for (const specifier of (statement.specifiers ?? []) as AstNode[]) { const local = id(specifier.local as AstNode); const exported = id(specifier.exported as AstNode); if (local && exported && functions.has(local)) exports.set(exported, functions.get(local)!.id) }
      continue
    }
    if (statement.type === 'ExportDefaultDeclaration') {
      const declaration = statement.declaration as AstNode; const local = id(declaration?.id as AstNode)??id(declaration); if (local && functions.has(local)) exports.set('default', functions.get(local)!.id)
    }
    addCommonJsExports(statement, file, functions, exports)
  }
  return { record: { file, source, program, functions, exports, imports, namespaces } }
}

function targetForCall(node: AstNode): ModuleFunction | undefined {
  const declaration=resolvedFunctionDeclaration(node)
  return declaration?moduleDeclarations.get(declaration):undefined
}

/**
 * Summarize parameter-to-sink flows across the scanned relative ES-module graph.
 * External packages and dynamic imports are intentionally unresolved: they require
 * source or runtime evidence rather than an inferred summary.
 */
function moduleFunctionSinks(modules: Map<string, ModuleRecord>, functions: Map<string, ModuleFunction>): Map<string, Map<number, FunctionSink[]>> {
  const summaries = new Map<string, Map<number, FunctionSink[]>>([...functions.values()].map(record => [record.id, new Map()]))
  const add = (record: ModuleFunction, index: number, item: FunctionSink): boolean => {
    const entries = summaries.get(record.id)?.get(index) ?? []; const key = `${item.rule.id}:${item.file}:${item.node.range?.join(':') ?? item.sink}`
    if (entries.some(existing => `${existing.rule.id}:${existing.file}:${existing.node.range?.join(':') ?? existing.sink}` === key)) return false
    const target = summaries.get(record.id); if (!target) return false; target.set(index, [...entries, item]); return true
  }
  for (let pass = 0; pass < functions.size * Math.max(2, functions.size) + 1; pass++) {
    let changed = false
    for (const record of functions.values()) for (const [index, param] of record.params.entries()) {
      const module = modules.get(record.file); if (!module) continue
      const taintAt = taintTracker(record.body,[param])
      walkFunction(record.body, node => {
        if (node.type !== 'CallExpression' && node.type !== 'NewExpression') return
        const tainted = taintAt(node)
        for (const sink of sinkFor(node)) if (sink.argumentsList.some(argument => sourceExpression(argument, tainted))) changed = add(record, index, { rule: sink.rule, sink: sink.sink, node,file:record.file,source:record.source,trace:sink.argumentsList.flatMap(argument=>sourceProofTraces(argument,tainted)) }) || changed
        if (node.type !== 'CallExpression') return
        const target = targetForCall(node); if (!target) return
        const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.id)
        for (const [targetIndex] of target.params.entries()) if (args[targetIndex] && sourceExpression(args[targetIndex], tainted)) for (const result of nested?.get(targetIndex) ?? []) changed = add(record, index, {...result,trace:[{file:record.file,line:node.loc?.start.line ?? 1,excerpt:line(record.source,node.loc?.start.line ?? 1)},...(result.trace??[])]}) || changed
      })
    }
    if (!changed) break
  }
  return summaries
}

/** Analyze request-input flows that cross local ES-module boundaries inside one scan scope. */
function analyzeJavaScriptModuleGraphUncached(inputs: JavaScriptModule[]): ModuleGraphAnalysis {
  const normalized = inputs.map(input => ({ ...input, file: normalize(input.file) })); const known = new Set(normalized.map(input => input.file)); const modules = new Map<string, ModuleRecord>(); const parseErrors: ModuleGraphAnalysis['parseErrors'] = []
  for (const input of normalized) { const parsed = createModuleRecord(input.file, input.source, known); if (parsed.record) modules.set(input.file, parsed.record); else if (parsed.parseError) parseErrors.push({ file: input.file, message: parsed.parseError }) }
  const functions = new Map<string, ModuleFunction>(); for (const module of modules.values()) for (const record of module.functions.values()) functions.set(record.id, record)
  prepareFlowSemantics([...modules.values()].map(({program,file,source})=>({program,file,source})),(file,specifier,exported)=>{
    const path=resolveRelativeModule(file,specifier,known),target=path&&modules.get(path)?.exports.get(exported)
    return target?functions.get(target)?.declaration:undefined
  })
  const summaries = moduleFunctionSinks(modules, functions); const candidates: Candidate[] = []
  for (const module of modules.values()) {
    candidates.push(...weakRandomnessCandidates(module.program, module.source, module.file))
    candidates.push(...hardcodedSecretCandidates(module.program, module.source, module.file))
    candidates.push(...tlsVerificationDisabledCandidates(module.program, module.source, module.file))
    candidates.push(...corsWildcardCredentialsCandidates(module.program, module.source, module.file))
    for(const scope of analysisScopes(module.program)){
    const taintAt=taintTracker(scope)
    walkFunction(scope, node => {
      if (node.type !== 'CallExpression') return
      const tainted=taintAt(node)
      for(const sink of sinkFor(node)){
        const input=sink.argumentsList.find(argument=>sourceExpression(argument,tainted))
        if(input){const item=candidate(sink.rule,module.source,module.file,node,sink.sink,input,tainted);if(item)candidates.push(item)}
      }
      const target = targetForCall(node); if (!target) return
      const args = (node.arguments ?? []) as AstNode[]; const nested = summaries.get(target.id)
      for (const [index] of target.params.entries()) {
        const input = args[index]; if (!input || !sourceExpression(input, tainted)) continue
        for (const result of nested?.get(index) ?? []) {
          const item = candidate(result.rule, result.source ?? target.source, result.file ?? target.file, result.node, result.sink, input,tainted)
          if(item) { item.evidence=item.evidence.filter(e=>e.location?.role!=='entrypoint');item.evidence.push({kind:'context',detail:'Observed request input at caller.',location:{file:module.file,line:input.loc?.start.line??1,excerpt:line(module.source,input.loc?.start.line??1),role:'entrypoint'}},...(result.trace??[]).map(location=>({kind:'context' as const,detail:'Resolved intermediate call to downstream sink.',location:{...location,role:'propagation' as const}}))) }
          if (!item) continue
          const at = node.loc?.start.line ?? item.line
          item.evidence.push({ kind: 'context', detail: `AST cross-module call-chain analysis resolved request-derived input through ${target.name}() in ${target.file} to ${result.sink}.`, location: { file: module.file, line: at, excerpt: line(module.source, at), role: 'propagation' } })
          candidates.push(item)
        }
      }
    })
    }
  }
  const unique = new Map<string, Candidate>(); for (const item of candidates) unique.set(`${item.rule}:${item.file}:${item.line}:${item.excerpt}`, item)
  return { candidates: [...unique.values()], parseErrors }
}

export function analyzeJavaScriptAst(source: string, file: string): { candidates: Candidate[]; parseError?: string } {return cachedAnalysis(analyzerVersion,'analyzeJavaScriptAst/bounded-source/v1',[file,source],()=>analyzeJavaScriptAstUncached(source,file))}

export function analyzeJavaScriptModuleGraph(inputs: JavaScriptModule[]): ModuleGraphAnalysis {return cachedAnalysis(analyzerVersion,'analyzeJavaScriptModuleGraph/bounded-source/v1',inputs,()=>analyzeJavaScriptModuleGraphUncached(inputs))}
