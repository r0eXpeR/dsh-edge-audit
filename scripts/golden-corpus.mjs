// 合成代码仅作为分析数据；绝不执行样本。基线和新版使用完全相同的输入、oracle 和限额。
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { tmpdir } from 'node:os'
import { performance } from 'node:perf_hooks'
const { assessDirectory } = await import(pathToFileURL(resolve(process.argv[2] ?? 'src/scanner.ts')).href)
const corpus = JSON.parse(await readFile(new URL('../tests/golden/corpus.json', import.meta.url), 'utf8'))
const scratch = await mkdtemp(join(tmpdir(), 'dsh-corpus-'))
const results = []
try {
 for (const item of corpus) {
  if (item.kind !== 'deterministic') continue
  const dir = join(scratch, item.id)
  await mkdir(dir)
  for (const [file, source] of Object.entries(item.files)) await writeFile(join(dir, file), source)
  const started = performance.now()
  const scan = await assessDirectory(dir, { maxFiles: 500, maxFileBytes: 262144 })
  const observations = scan.candidates
  const key = c => `${c.rule}:${c.file}:${c.line}`
  const expected = new Set(item.expected.map(key))
  const actual = new Set(observations.map(key))
  const truePositives = [...expected].filter(k => actual.has(k))
  const falsePositives = [...actual].filter(k => !expected.has(k))
  const missed = [...expected].filter(k => !actual.has(k))
  const invalidLocations = observations.filter(c => item.files[c.file]?.split(/\r?\n/)[c.line-1]?.trim().slice(0,240) !== c.excerpt).map(key)
  results.push({ id: item.id, durationMs: +(performance.now()-started).toFixed(3), truePositives, falsePositives, missed, invalidLocations, complete: scan.complete })
 }
} finally { await rm(scratch, { recursive: true, force: true }) }
const sum = field => results.reduce((n,r)=>n+r[field].length,0)
const tp = sum('truePositives'), fp = sum('falsePositives'), fn = sum('missed')
const report = { schemaVersion: 1, kind: 'deterministic-candidate-location-benchmark', generatedAt: new Date().toISOString(), source: process.argv[2] ?? 'src/scanner.ts', limits: { maxFiles: 500, maxFileBytes: 262144 }, cases: results, metrics: { truePositives: tp, falsePositives: fp, falseNegatives: fn, candidatePrecision: tp/(tp+fp), candidateRecall: tp/(tp+fn), invalidLocations: sum('invalidLocations'), durationMs: +results.reduce((n,r)=>n+r.durationMs,0).toFixed(3), confirmedPrecision: null, validatedRecall: null, modelTokens: null, modelCost: null }, limitations: ['候选检出和定位质量，不等同独立验证召回率或 Confirmed Precision。','semantic 样本需真实模型和独立验证；本脚本不将固定模型结果作为 benchmark。'] }
const output = process.argv[3]
if (output) await writeFile(output, JSON.stringify(report,null,2)+'\n')
console.log(JSON.stringify(report.metrics))
