import assert from 'node:assert/strict'
import test from 'node:test'
import { analyzeJavaScriptAst, analyzeJavaScriptModuleGraph } from '../src/ast-analysis.ts'

const commands = (source: string) => analyzeJavaScriptAst(source, 'app.ts').candidates.filter(c => c.rule === 'shell-command-construction')

test('Process aliases resolve ESM imports, CommonJS destructuring and constant namespace aliases', () => {
  for (const setup of [
    "import { exec as run } from 'node:child_process';",
    "const { exec: run } = require('child_process');",
    "import * as processes from 'child_process'; const run = processes.exec;",
    "const processes = require('node:child_process'); const { exec: run } = processes;",
  ]) assert.equal(commands(`${setup}\nexport function route(req) { return run(req.query.command) }`).length, 1, setup)
})

test('Process aliases do not cross parameter/block shadows, reassignment or shadowed require', () => {
  for (const source of [
    "import { exec as run } from 'child_process'; function route(req, run) { run(req.query.command) }",
    "import { exec as run } from 'child_process'; function route(req) { const run = value => value; run(req.query.command) }",
    "const processes = require('child_process'); let run = processes.exec; run = value => value; run(req.query.command);",
    "function route(req, require) { const { exec: run } = require('child_process'); run(req.query.command) }",
    "import type { exec as run } from 'child_process'; function route(req) { run(req.query.command) }",
    "import * as processes from 'child_process'; function route(req, processes) { processes.exec(req.query.command) }",
    "const processes = require('child_process'); processes.exec = value => value; function route(req) { processes.exec(req.query.command) }",
    "const pattern = /^[a-z]+$/; function route(req) { pattern.exec(req.query.text) }",
  ]) assert.equal(commands(source).length, 0, source)
  const siblings = "import { exec as run } from 'child_process'; function safe(req, run) { run(req.query.command) }\nfunction unsafe(req) { run(req.query.command) }"
  assert.deepEqual(commands(siblings).map(c => c.line), [2])
})

test('Local return summaries follow request-object projections and retain return evidence', () => {
  const source = 'function input(req) { return req.query.command }\nexport function route(req) { return exec(input(req)) }'
  const result = commands(source)
  assert.equal(result.length, 1)
  assert.equal(result[0].line, 2)
  assert.ok(result[0].evidence.some(e => e.location?.line === 1 && e.location.role === 'propagation'))
})

test('Return summaries propagate only selected parameters and honor definite overwrites', () => {
  const source = `function second(first, value) { let result = value; return result }
function cleared(value) { let result = value; result = 'date'; return result }
function route(req) {
  exec(second(req.query.ignored, 'date'))
  exec(cleared(req.query.command))
  exec(second('date', req.query.command))
}`
  assert.deepEqual(commands(source).map(c => c.line), [6])
  const array="const wrap = value => ['date', value];\nfunction route(req) { exec(wrap(req.query.command)[0]); exec(wrap(req.query.command)[1]) }"
  assert.equal(commands(array).length,1)
})

test('Implicit arrows and nested return wrappers reach a sink through an assignment', () => {
  const source = `const identity = value => value;
function prefix(value) { return 'echo ' + identity(value) }
function route(req) { const command = prefix(req.query.command); exec(command) }`
  const result=commands(source)
  assert.deepEqual(result.map(c => c.line), [3])
  assert.ok(result[0].evidence.some(e=>e.location?.line===1&&e.location.role==='propagation'))
  assert.ok(result[0].evidence.some(e=>e.location?.line===2&&e.location.role==='propagation'))
})

test('Return function resolution respects nested function and call-site parameter shadows', () => {
  const source = `function pick(value) { return 'date' }
function unsafe(req) { function pick(value) { return value } exec(pick(req.query.command)) }
function safe(req) { exec(pick(req.query.command)) }
function opaque(req, pick) { exec(pick(req.query.command)) }`
  assert.deepEqual(commands(source).map(c => c.line), [2])
})

test('Constant object projections and constant callers do not inherit request taint', () => {
  const source = `function get(input) { return input.query.command }
function wrap(value) { return { safe: 'date', unsafe: value } }
function route(req) {
  exec(get({ query: { command: 'date' } }))
  exec(wrap(req.query.command).safe)
  exec(wrap(req.query.command).unsafe)
}`
  assert.deepEqual(commands(source).map(c => c.line), [6])
})

test('Async return values flow only when awaited', () => {
  const source = `async function input(req) { return req.query.command }
async function route(req) {
  exec(input(req))
  exec(await input(req))
}`
  assert.deepEqual(commands(source).map(c => c.line), [4])
})

test('Unreachable returns and overriding finally returns do not create a tainted summary', () => {
  const source = `function early(value) { return 'date'; return value }
function final(value) { try { return value } finally { return 'date' } }
function route(req) { exec(early(req.query.command)); exec(final(req.query.command)) }`
  assert.equal(commands(source).length, 0)
})

test('Cross-module return helpers preserve frozen source locations at the consuming sink', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'input.ts', source: 'export function get(input) { return input.query.command }\n' },
    { file: 'middle.ts', source: "import { get } from './input';\nexport const command = req => get(req);\n" },
    { file: 'route.ts', source: "import { command as pick } from './middle';\nimport { exec as run } from 'node:child_process';\nexport function route(req) { return run(pick(req)) }\n" },
  ])
  const findings = result.candidates.filter(c => c.rule === 'shell-command-construction')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].file, 'route.ts')
  assert.ok(findings[0].evidence.some(e => e.location?.file === 'input.ts'))
  assert.ok(findings[0].evidence.some(e => e.location?.file === 'middle.ts'))
})

test('Cross-module safe return helpers do not taint a constant return or a shadowed import', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'input.ts', source: "export function get(value) { return 'date' }\n" },
    { file: 'route.ts', source: "import { get } from './input';\nfunction route(req) { exec(get(req.query.command)) }\nfunction opaque(req, get) { exec(get(req.query.command)) }\n" },
  ])
  assert.equal(result.candidates.filter(c => c.rule === 'shell-command-construction').length, 0)
})

test('Recursive object returns stay bounded instead of expanding summary fields indefinitely', () => {
  const source = `function recursive(value) { return { left: recursive(value), right: recursive(value) } }
function identity(value, more) { if (more) return identity(value, false); return value }
function route(req) { exec(identity(req.query.command, true)) }`
  const start=performance.now()
  assert.equal(commands(source).length,1)
  assert.ok(performance.now()-start<2000)
})

test('Namespaced module calls respect argument shadows and constant imported return values', () => {
  const result = analyzeJavaScriptModuleGraph([
    { file: 'helper.ts', source: 'export function pick(value) { return value }\n' },
    { file: 'route.ts', source: "import * as helper from './helper';\nfunction safe(req, helper) { exec(helper.pick(req.query.command)) }\nfunction unsafe(req) { const command = helper.pick(req.query.command); exec(command) }\n" },
  ])
  const findings=result.candidates.filter(c=>c.rule==='shell-command-construction')
  assert.deepEqual(findings.map(c=>c.line),[3])
  assert.ok(findings[0].evidence.some(e=>e.location?.file==='helper.ts'))
})

test('Returned field precision survives assignment, destructuring and later input overwrites', () => {
  const source=`function wrap(value) { return { safe: 'date', unsafe: value } }
function route(req) {
  let input = req.query.command;
  const result = wrap(input);
  const { safe, unsafe } = result;
  input = 'date';
  exec(result.safe);
  exec(safe);
  exec(result.unsafe);
  exec(unsafe);
}`
  assert.deepEqual(commands(source).map(c=>c.line),[9,10])
})

test('Stored promises retain their return flow until awaited',()=>{
  const source=`async function input(req) { return req.query.command }
async function route(req) {
  const pending = input(req);
  exec(pending);
  exec(await pending);
}`
  assert.deepEqual(commands(source).map(c=>c.line),[5])
})

test('Known URL conversions continue to carry helper-return values',()=>{
  const source=`function input(req) { return req.query.url }
function route(req) { fetch(new URL(input(req))) }`
  assert.deepEqual(analyzeJavaScriptAst(source,'app.ts').candidates.map(c=>c.rule),['ssrf-request-sink'])
})

test('Source-controlled object keys are data and cannot alter or crash summary field maps',()=>{
  const source=`function wrap(value) { return { constructor: value, ['__proto__']: value, safe: 'date' } }
function route(req) {
  exec(wrap(req.query.command).constructor);
  exec(wrap(req.query.command)['__proto__']);
  exec(wrap(req.query.command).missing);
  exec(wrap(req.query.command).toString);
}`
  assert.deepEqual(commands(source).map(c=>c.line),[3,4])
})
