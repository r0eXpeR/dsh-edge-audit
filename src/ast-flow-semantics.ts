import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
/** 有界的词法绑定与返回值摘要。只分析 AST，不执行模块或目标函数。 */
export const flowSemanticsVersion = createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex')
export interface FlowNode {
  type?: string
  range?: [number, number]
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } }
  [key: string]: unknown
}
interface Scope { parent?: Scope; functionScope: boolean; bindings: Map<string, Binding> }
interface Binding { kind: string; node: FlowNode; init?: FlowNode; path: string[]; imported?: { specifier: string; exported: string }; mutated?: boolean }
interface FunctionInfo { node: FlowNode; file: string; source: string }
export interface FlowTrace { file: string; line: number; excerpt: string }
interface Origin { parameter?: number; path: string[]; leaf?: FlowNode; trace: FlowTrace[] }
interface Value { origins: Origin[]; fields?: Record<string, Value>; promise?: boolean }
interface Summary { info: FunctionInfo; value: Value }
const scopes = new WeakMap<FlowNode, Scope>()
const functions = new WeakMap<FlowNode, FunctionInfo>()
const targets = new WeakMap<FlowNode, FunctionInfo>()
const summaries = new WeakMap<FlowNode, Summary>()
const sinkNames = new WeakMap<FlowNode, string | null>()
const nodeSources=new WeakMap<FlowNode,{file:string;lines:string[]}>()
const MAX_PATH = 8, MAX_ORIGINS = 64, MAX_PASSES = 64
const processMethods = new Set(['exec', 'execsync', 'execfile', 'execfilesync', 'spawn', 'spawnsync', 'fork'])
const empty = (): Value => ({ origins: [] })
const name = (node: FlowNode | undefined): string | undefined => node?.type === 'Identifier' ? String(node.name) : undefined
const string = (node: FlowNode | undefined): string | undefined => node?.type === 'Literal' && typeof node.value === 'string' ? node.value : undefined
const func = (node: FlowNode | undefined): boolean => ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node?.type ?? '')
function children(node: FlowNode): FlowNode[] {
  return Object.entries(node).filter(([key]) => !['loc', 'range', 'parent', 'tokens', 'comments'].includes(key)).flatMap(([, value]) =>
    Array.isArray(value) ? value.filter(v => v && typeof v === 'object' && 'type' in v) : value && typeof value === 'object' && 'type' in value ? [value] : []) as FlowNode[]
}
function walk(node: FlowNode, visit: (node: FlowNode) => void): void { visit(node); children(node).forEach(child => walk(child, visit)) }
function lookup(node: FlowNode, key: string): Binding | undefined {
  for (let scope = scopes.get(node); scope; scope = scope.parent) { const binding = scope.bindings.get(key); if (binding) return binding }
}
function property(node: FlowNode): string | undefined {
  const key=node.property as FlowNode
  return node.computed ? string(key)??(key?.type==='Literal'&&typeof key.value==='number'?String(key.value):undefined) : name(key)
}
function pattern(node: FlowNode | undefined, visit: (id: FlowNode, path: string[]) => void, path: string[] = []): void {
  if (!node) return
  if (node.type === 'Identifier') visit(node, path)
  else if (node.type === 'AssignmentPattern') pattern(node.left as FlowNode, visit, path)
  else if (node.type === 'ObjectPattern') for (const item of (node.properties ?? []) as FlowNode[]) {
    const key = item.computed ? string(item.key as FlowNode) : name(item.key as FlowNode) ?? string(item.key as FlowNode)
    if (item.type === 'Property' && key !== undefined) pattern(item.value as FlowNode, visit, [...path, key])
  }
  else if (node.type === 'ArrayPattern') ((node.elements ?? []) as Array<FlowNode | null>).forEach((item, index) => pattern(item ?? undefined, visit, [...path, String(index)]))
}
function bindProgram(program: FlowNode, file: string, source: string): FunctionInfo[] {
  const result: FunctionInfo[] = []
  const sourceInfo={file,lines:source.split(/\r?\n/)}
  const visit = (node: FlowNode, outer: Scope): void => {
    let scope = outer
    if (func(node)) {
      if (node.type === 'FunctionDeclaration' && name(node.id as FlowNode)) outer.bindings.set(name(node.id as FlowNode)!, { kind: 'function', node, path: [] })
      scope = { parent: outer, functionScope: true, bindings: new Map() }
      if (node.type==='FunctionExpression' && name(node.id as FlowNode)) scope.bindings.set(name(node.id as FlowNode)!, { kind: 'function', node, path: [] })
      for (const param of (node.params ?? []) as FlowNode[]) pattern(param, id => scope.bindings.set(name(id)!, { kind: 'parameter', node: id, path: [] }))
      if (node.body) { const info = { node, file, source }; functions.set(node, info); result.push(info) }
    } else if (['BlockStatement', 'CatchClause', 'ForStatement', 'ForInStatement', 'ForOfStatement', 'SwitchStatement'].includes(node.type ?? '')) {
      scope = { parent: outer, functionScope: false, bindings: new Map() }
      if (node.type === 'CatchClause') pattern(node.param as FlowNode, id => scope.bindings.set(name(id)!, { kind: 'parameter', node: id, path: [] }))
    }
    scopes.set(node, scope)
    nodeSources.set(node,sourceInfo)
    if (node.type === 'ImportDeclaration') for (const item of (node.specifiers ?? []) as FlowNode[]) {
      const local = name(item.local as FlowNode), specifier = string(node.source as FlowNode)
      if (!local || specifier === undefined) continue
      const typeOnly = node.importKind === 'type' || item.importKind === 'type'
      const exported = item.type === 'ImportNamespaceSpecifier' ? '*' : item.type === 'ImportDefaultSpecifier' ? 'default' : name(item.imported as FlowNode) ?? string(item.imported as FlowNode)
      scope.bindings.set(local, { kind: 'import', node: item, path: [], ...(!typeOnly && exported ? { imported: { specifier, exported } } : {}) })
    }
    if (node.type === 'VariableDeclaration') for (const declaration of (node.declarations ?? []) as FlowNode[]) {
      let owner = scope
      if (node.kind === 'var') while (!owner.functionScope && owner.parent) owner = owner.parent
      pattern(declaration.id as FlowNode, (id, path) => owner.bindings.set(name(id)!, { kind: String(node.kind), node: declaration, init: declaration.init as FlowNode, path }))
    }
    if (node.type === 'ClassDeclaration' && name(node.id as FlowNode)) scope.bindings.set(name(node.id as FlowNode)!, { kind: 'value', node, path: [] })
    children(node).forEach(child => visit(child, scope))
  }
  visit(program, { functionScope: true, bindings: new Map() })
  walk(program, node => {
    if (!['AssignmentExpression', 'UpdateExpression'].includes(node.type ?? '')) return
    const target = (node.left ?? node.argument) as FlowNode
    pattern(target, id => { const binding = lookup(node, name(id)!); if (binding) binding.mutated = true })
    if (target?.type === 'MemberExpression' && name(target.object as FlowNode)) { const binding = lookup(node, name(target.object as FlowNode)!); if (binding) binding.mutated = true }
  })
  return result
}
function reference(node: FlowNode | undefined, seen = new Set<Binding>()): { specifier: string; exported: string } | undefined {
  if (!node) return
  if (node.type === 'Identifier') {
    const binding = lookup(node, name(node)!)
    if (!binding || binding.mutated || seen.has(binding)) return
    seen.add(binding)
    if (binding.imported) return binding.imported
    if (binding.kind !== 'const' || !binding.init) return
    const ref = reference(binding.init, seen)
    if (ref && binding.path.length <= 1) return binding.path.length ? { ...ref, exported: binding.path[0] } : ref
  }
  if (node.type === 'MemberExpression') {
    const ref = reference(node.object as FlowNode, seen), key = property(node)
    if (ref && key && ['*', 'default'].includes(ref.exported)) return { ...ref, exported: key }
  }
  if (node.type === 'CallExpression' && name(node.callee as FlowNode) === 'require' && !lookup(node.callee as FlowNode, 'require')) {
    const args = (node.arguments ?? []) as FlowNode[], specifier = string(args[0])
    if (args.length === 1 && specifier !== undefined) return { specifier, exported: 'default' }
  }
}
function localFunction(node: FlowNode | undefined, seen = new Set<Binding>()): FunctionInfo | undefined {
  if (!node) return
  if (func(node)) return functions.get(node)
  if (node.type !== 'Identifier') return
  const binding = lookup(node, name(node)!)
  if (!binding || binding.mutated || seen.has(binding)) return
  seen.add(binding)
  if (binding.kind === 'function') return functions.get(binding.node)
  if (binding.init && !binding.path.length && (binding.node.range?.[0] ?? 0) < (node.range?.[0] ?? Infinity)) return localFunction(binding.init, seen)
}
function trace(info: FunctionInfo, node: FlowNode): FlowTrace { const line = node.loc?.start.line ?? 1; return { file: info.file, line, excerpt: nodeSources.get(node)?.lines[line - 1]?.trim().slice(0, 240) ?? '' } }
function originKey(origin: Origin): string { return `${origin.parameter ?? 'leaf'}:${origin.leaf?nodeSources.get(origin.leaf)?.file??'':''}:${origin.leaf?.range?.join(':') ?? ''}:${JSON.stringify(origin.path)}` }
function merge(...values: Value[]): Value {
  return mergeBounded(values,0)
}
function mergeBounded(values:Value[],depth:number):Value {
  if(depth>MAX_PATH)return empty()
  const origins = new Map<string, Origin>(), fields: Record<string, Value> = Object.create(null)
  for (const value of values) {
    for (const origin of value.origins) {
      if (origin.path.length > MAX_PATH) continue
      const key = originKey(origin), prior = origins.get(key)
      const traces = [...(prior?.trace ?? []), ...origin.trace]
      origins.set(key, { ...origin, trace: [...new Map(traces.map(item => [`${item.file}:${item.line}`, item])).values()].slice(0, 16) })
    }
    for (const [key, field] of Object.entries(value.fields ?? {})) fields[key] = mergeBounded(fields[key]?[fields[key],field]:[field],depth+1)
  }
  return { origins: [...origins.values()].slice(0, MAX_ORIGINS), ...(Object.keys(fields).length ? { fields } : {}), ...(values.some(v => v.promise) ? { promise: true } : {}) }
}
function project(value: Value, key: string): Value {
  if (value.promise) return empty()
  return merge(value.fields&&Object.hasOwn(value.fields,key)?value.fields[key]:empty(), { origins: value.origins.map(origin => ({ ...origin, path: [...origin.path, key] })) })
}
function annotate(value: Value, at: FlowTrace): Value {
  return { ...value, origins: value.origins.map(origin => ({ ...origin, trace: [...origin.trace, at].slice(0, 16) })), ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([key, item]) => [key, annotate(item, at)])) } : {}) }
}
type Environment = Map<Binding, Value>
function expression(node: FlowNode | undefined, env: Environment, info: FunctionInfo, leaves = false, visited = new Set<Binding>()): Value {
  if (!node) return empty()
  if (node.type === 'Identifier') {
    const binding = lookup(node, name(node)!)
    if (binding && env.has(binding)) return env.get(binding)!
    if (binding?.kind === 'const' && binding.init && !binding.mutated && !visited.has(binding)) {
      const next = new Set(visited); next.add(binding)
      let value = expression(binding.init, env, info, leaves, next)
      for (const key of binding.path) value = project(value, key)
      return value
    }
    return leaves ? { origins: [{ leaf: node, path: [], trace: [] }] } : empty()
  }
  if (['TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression', 'ChainExpression'].includes(node.type ?? '')) return expression(node.expression as FlowNode, env, info, leaves, visited)
  if (node.type === 'AwaitExpression') return { ...expression(node.argument as FlowNode, env, info, leaves, visited), promise: false }
  if (node.type === 'MemberExpression') {
    const key = property(node)
    if (key === undefined) return empty()
    const object = expression(node.object as FlowNode, env, info, leaves, visited)
    if (object.origins.length || object.fields || object.promise) return project(object, key)
    // 自由请求对象的属性是源码输入；参数对象已通过 env 表示，不能无条件变成请求源。
    let root = node, parts: string[] = []
    while (root.type === 'MemberExpression') { const part = property(root); if (!part) break; parts.unshift(part); root = root.object as FlowNode }
    if (['req', 'request', 'event'].includes(name(root) ?? '') && !lookup(root, name(root)!) && /^(?:body|query|params|headers|cookies|url|path)$/.test(parts[0] ?? '')) return { origins: [{ leaf: node, path: [], trace: [] }] }
    return empty()
  }
  if (node.type === 'ObjectExpression' || node.type === 'ArrayExpression') {
    const fields: Record<string, Value> = Object.create(null)
    if (node.type === 'ArrayExpression') ((node.elements ?? []) as Array<FlowNode | null>).forEach((item, index) => { fields[String(index)] = expression(item ?? undefined, env, info, leaves, visited) })
    else for (const item of (node.properties ?? []) as FlowNode[]) {
      const key = item.computed ? string(item.key as FlowNode) : name(item.key as FlowNode) ?? string(item.key as FlowNode)
      if (item.type === 'Property' && key !== undefined) fields[key] = expression(item.value as FlowNode, env, info, leaves, visited)
    }
    return { origins: [], fields }
  }
  if (node.type === 'CallExpression') {
    const target = targets.get(node), summary = target && summaries.get(target.node)
    const args = (node.arguments ?? []) as FlowNode[]
    if (summary) {
      const instantiate = (value: Value): Value => {
        const origins = value.origins.map(origin => {
          if (origin.parameter === undefined) return { origins: [origin] }
          let actual = expression(args[origin.parameter], env, info, leaves, visited)
          for (const key of origin.path) actual = project(actual, key)
          for (const at of origin.trace) actual = annotate(actual, at)
          return actual
        })
        return { ...merge(...origins), ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([key, item]) => [key, instantiate(item)])) } : {}), promise: !!target?.node.async || value.promise }
      }
      return annotate(instantiate(summary.value), trace(info, node))
    }
    const callee = node.callee as FlowNode, method = name(callee) ?? (callee.type === 'MemberExpression' ? property(callee) : undefined)
    if (['String', 'stringify'].includes(method ?? '')) return expression(args[0], env, info, leaves, visited)
    if (callee.type === 'MemberExpression' && /^(?:toString|trim|replace|slice|substring|concat|join|toLowerCase|toUpperCase|normalize)$/.test(method ?? '')) return merge(expression(callee.object as FlowNode, env, info, leaves, visited), ...args.map(arg => expression(arg, env, info, leaves, visited)))
    return empty()
  }
  if(node.type==='NewExpression' && ['URL','globalThis.URL'].includes(name(node.callee as FlowNode)??((node.callee as FlowNode)?.type==='MemberExpression'?`${name((node.callee as FlowNode).object as FlowNode)}.${property(node.callee as FlowNode)}`:'')))return expression(((node.arguments??[]) as FlowNode[])[0],env,info,leaves,visited)
  if (node.type === 'ConditionalExpression') return merge(expression(node.consequent as FlowNode, env, info, leaves, visited), expression(node.alternate as FlowNode, env, info, leaves, visited))
  if (['BinaryExpression', 'LogicalExpression'].includes(node.type ?? '')) return merge(expression(node.left as FlowNode, env, info, leaves, visited), expression(node.right as FlowNode, env, info, leaves, visited))
  if (node.type === 'TemplateLiteral') return merge(...((node.expressions ?? []) as FlowNode[]).map(item => expression(item, env, info, leaves, visited)))
  return empty()
}
function assign(patternNode: FlowNode, value: Value, env: Environment): void {
  pattern(patternNode, (id, path) => { const binding = lookup(id, name(id)!); if (!binding) return; let part = value; for (const key of path) part = project(part, key); env.set(binding, part) })
}
function mergeEnvironments(target: Environment, ...sources: Environment[]): void {
  for (const key of new Set(sources.flatMap(source => [...source.keys()]))) target.set(key, merge(...sources.map(source => source.get(key) ?? empty())))
}
interface Completion { value: Value; continues: boolean }
function statement(node: FlowNode | undefined, env: Environment, info: FunctionInfo): Completion {
  if (!node) return { value: empty(), continues: true }
  if (node.type === 'ReturnStatement') return { value: annotate(expression(node.argument as FlowNode, env, info), trace(info, node)), continues: false }
  if (node.type === 'ThrowStatement') return { value: empty(), continues: false }
  if (node.type === 'BlockStatement') {
    let value = empty()
    for (const child of (node.body ?? []) as FlowNode[]) { const result = statement(child, env, info); value = merge(value, result.value); if (!result.continues) return { value, continues: false } }
    return { value, continues: true }
  }
  if (node.type === 'VariableDeclaration') for (const item of (node.declarations ?? []) as FlowNode[]) assign(item.id as FlowNode, expression(item.init as FlowNode, env, info), env)
  if (node.type === 'ExpressionStatement') {
    const value = node.expression as FlowNode
    if (value.type === 'AssignmentExpression' && value.operator === '=') assign(value.left as FlowNode, expression(value.right as FlowNode, env, info), env)
  }
  if (node.type === 'IfStatement') {
    const test = node.test as FlowNode
    if (test?.type === 'Literal' && typeof test.value === 'boolean') return statement((test.value ? node.consequent : node.alternate) as FlowNode, env, info)
    const left = new Map(env), right = new Map(env), a = statement(node.consequent as FlowNode, left, info), b = statement(node.alternate as FlowNode, right, info)
    mergeEnvironments(env, ...(a.continues ? [left] : []), ...(b.continues ? [right] : []))
    return { value: merge(a.value, b.value), continues: a.continues || b.continues }
  }
  if (node.type === 'TryStatement') {
    const bodyEnv = new Map(env), catchEnv = new Map(env), body = statement(node.block as FlowNode, bodyEnv, info), handler = node.handler as FlowNode | undefined
    const caught = handler ? statement(handler.body as FlowNode, catchEnv, info) : { value: empty(), continues: false }
    mergeEnvironments(env, ...(body.continues ? [bodyEnv] : []), ...(caught.continues ? [catchEnv] : []))
    const final = statement(node.finalizer as FlowNode, env, info)
    return { value: final.continues ? merge(body.value, caught.value, final.value) : final.value, continues: final.continues && (body.continues || caught.continues) }
  }
  return { value: empty(), continues: true }
}
export function prepareFlowSemantics(programs: Array<{ program: FlowNode; file: string; source: string }>, external?: (file: string, specifier: string, exported: string) => FlowNode | undefined): void {
  const records = programs.flatMap(input => bindProgram(input.program, input.file, input.source))
  for (const input of programs) walk(input.program, node => {
    if (node.type !== 'CallExpression') return
    const callee = node.callee as FlowNode, ref = reference(callee)
    if (ref && /^(?:node:)?child_process$/.test(ref.specifier) && processMethods.has(ref.exported.toLowerCase())) sinkNames.set(node, `child_process.${ref.exported.toLowerCase()}`)
    else if (name(callee) && lookup(callee, name(callee)!) && processMethods.has(name(callee)!.toLowerCase())) sinkNames.set(node, null)
    else if(callee.type==='MemberExpression'&&processMethods.has((property(callee)??'').toLowerCase())){
      let root=callee.object as FlowNode
      while(root.type==='MemberExpression')root=root.object as FlowNode
      if(name(root)&&lookup(root,name(root)!))sinkNames.set(node,null)
    }
    const local = localFunction(callee), importedNode = !local && ref ? external?.(input.file, ref.specifier, ref.exported) : undefined
    const target = local ?? (importedNode ? functions.get(importedNode) : undefined)
    if (target) targets.set(node, target)
  })
  for (const info of records) summaries.set(info.node, { info, value: empty() })
  for (let pass = 0; pass < Math.min(MAX_PASSES, records.length + 1); pass++) {
    let changed = false
    for (const info of records) {
      const env: Environment = new Map()
      ;((info.node.params ?? []) as FlowNode[]).forEach((param, index) => assign(param, { origins: [{ parameter: index, path: [], trace: [] }] }, env))
      const body = info.node.body as FlowNode
      const value = body.type === 'BlockStatement' ? statement(body, env, info).value : annotate(expression(body, env, info), trace(info, body))
      const previous = summaries.get(info.node)!, next = merge(previous.value, value)
      if (JSON.stringify(next) !== JSON.stringify(previous.value)) { summaries.set(info.node, { info, value: next }); changed = true }
    }
    if (!changed) break
  }
}
export function resolvedFunctionDeclaration(call: FlowNode): FlowNode | undefined { return targets.get(call)?.node }
export function semanticProcessSink(call: FlowNode): string | null | undefined { return sinkNames.get(call) }
function modeled(node: FlowNode): boolean { return node.type === 'CallExpression' && targets.has(node) || children(node).some(modeled) }
export function hasReturnedFlow(node:FlowNode):boolean{return modeled(node)}
function sourceNode(origin: Origin): FlowNode | undefined {
  let node = origin.leaf
  for (const key of origin.path) node = node ? { type: 'MemberExpression', object: node, property: { type: 'Identifier', name: key }, computed: false, loc: node.loc } : undefined
  return node
}
/** undefined 表示普通表达式，交回已有局部污点逻辑；有已解析调用才应用返回摘要。 */
export function returnedSource(node: FlowNode, check: (node: FlowNode) => boolean): boolean | undefined {
  if (!modeled(node)) return
  const info = { node, file: '', source: '' }, value = expression(node, new Map(), info, true)
  const tainted = (value: Value): boolean => !value.promise && (value.origins.some(origin => { const leaf = sourceNode(origin); return !!leaf && check(leaf) }) || Object.values(value.fields ?? {}).some(tainted))
  return tainted(value)
}
export function returnedFlowTraces(node: FlowNode): FlowTrace[] {
  if (!modeled(node)) return []
  const value = expression(node, new Map(), { node, file: '', source: '' }, true)
  const collect = (value: Value): FlowTrace[] => [...value.origins.flatMap(origin => origin.trace), ...Object.values(value.fields ?? {}).flatMap(collect)]
  return [...new Map(collect(value).filter(item => item.file).map(item => [`${item.file}:${item.line}`, item])).values()]
}
