import { readdir, readFile, stat, lstat, realpath } from 'node:fs/promises'
import { extname, join, relative, resolve } from 'node:path'
import { getStateDir, loadScan, readArtifact, sha256, writeArtifact } from '../state.js'
import { mutateScan } from '../scan-store.js'
import type { Config } from '../config.js'

/**
 * Read-only security knowledge base, mirroring codex-security `--knowledge-base`
 * semantics (Apache-2.0, adapted): files or directories searched recursively for
 * Markdown and plain-text documents. PDF/DOCX binaries are skipped (no parser
 * dependency); callers may pre-convert them.
 */

const TEXT_KB_EXTENSIONS = new Set(['.md', '.markdown', '.txt', '.text', '.rst', '.adoc', '.toml', '.yaml', '.yml', '.json'])
const SKIPPED_KB_DIRECTORIES = new Set(['.git', '.hg', '.svn', 'node_modules', 'dist', 'build', 'coverage'])
const MAX_KB_DOC_BYTES = 512 * 1024
const MAX_KB_TOTAL_BYTES = 8 * 1024 * 1024
const MAX_KB_DOCS = 200

export interface KnowledgeBaseDocument {
  path: string
  /** Workspace-relative display path when under the active workspace. */
  name: string
  content: string
  sha256: string
}

export interface KnowledgeBase {
  documents: KnowledgeBaseDocument[]
  /** Documents truncated or skipped due to size/type limits. */
  skipped: Array<{ path: string; reason: string }>
  /** Combined bounded prompt text: a heading per document followed by content. */
  promptText: string
}

function kbName(workspace: string, path: string): string {
  const rel = relative(workspace, path)
  return rel && !rel.startsWith('..') ? rel : path
}

async function isReadableFile(path: string): Promise<boolean> {
  try { const info = await stat(path); return info.isFile() } catch { return false }
}

async function collectKbFiles(workspace: string, candidates: string[], out: string[], skipped: Array<{ path: string; reason: string }>): Promise<void> {
  for (const candidate of candidates) {
    const resolved = resolve(workspace,candidate)
    const rel=relative(resolve(workspace),resolved)
    if(rel==='..'||rel.startsWith('../')||rel.startsWith('..\\')){skipped.push({path:candidate,reason:'Knowledge-base path is outside the active workspace.'});continue}
    if(out.length>=MAX_KB_DOCS){skipped.push({path:candidate,reason:'Knowledge-base inventory limit reached.'});continue}
    let info
    try { info = await lstat(resolved) } catch { skipped.push({ path: candidate, reason: 'Knowledge-base path is not readable.' }); continue }
    if(info.isSymbolicLink() || !((await realpath(resolved)) === (await realpath(workspace)) || (await realpath(resolved)).startsWith((await realpath(workspace))+'/'))){skipped.push({path:candidate,reason:'Knowledge-base symlinks or external paths are not trusted.'});continue}
    if (info.isFile()) {
      if (info.size > MAX_KB_DOC_BYTES) { skipped.push({ path: candidate, reason: 'Knowledge-base document exceeds the 512 KiB size limit.' }); continue }
      out.push(resolved)
    } else if (info.isDirectory()) {
      const entries = await readdir(resolved)
      for (const entry of entries.sort()) {
        if (SKIPPED_KB_DIRECTORIES.has(entry)) continue
        await collectKbFiles(workspace, [join(resolved, entry)], out, skipped)
      }
    }
  }
}

/**
 * Load the configured knowledge base. Returns an empty base (never throws) when
 * nothing is configured or every path is unreadable.
 */
export async function loadKnowledgeBase(workspace: string, configured: string[]): Promise<KnowledgeBase> {
  const docs: KnowledgeBaseDocument[] = []
  const skipped: Array<{ path: string; reason: string }> = []
  const files: string[] = []
  await collectKbFiles(workspace, configured, files, skipped)
  let total = 0
  for (const file of files) {
    if (docs.length >= MAX_KB_DOCS) { skipped.push({ path: file, reason: 'Knowledge base exceeded the 200 document limit.' }); continue }
    const extension = extname(file).toLowerCase()
    if (!TEXT_KB_EXTENSIONS.has(extension)) { skipped.push({ path: file, reason: `Unsupported knowledge-base document type "${extension}"; only Markdown and plain text are read.` }); continue }
    try {
      if (!(await isReadableFile(file))) { skipped.push({ path: file, reason: 'Knowledge-base path is not a readable file.' }); continue }
      const content = await readFile(file, 'utf8')
      if (content.length > MAX_KB_DOC_BYTES) { skipped.push({ path: file, reason: 'Knowledge-base document exceeds the 512 KiB size limit.' }); continue }
      if (total + content.length > MAX_KB_TOTAL_BYTES) { skipped.push({ path: file, reason: 'Knowledge base exceeded the 8 MiB total content limit.' }); continue }
      total += content.length
      docs.push({ path: file, name: kbName(workspace, file), content, sha256: sha256(content) })
    } catch { skipped.push({ path: file, reason: 'Knowledge-base document could not be read.' }) }
  }
  docs.sort((a, b) => a.name.localeCompare(b.name))
  const fullPromptText = docs.length
    ? docs.map(doc => `# Knowledge-base document: ${doc.name}\n\n${doc.content.trim()}`).join('\n\n---\n\n') + '\n'
    : ''
  // 完整内容供冻结和分页；自动提示词与工具 DTO 在各自输出边界截取预览。
  return { documents: docs, skipped, promptText: fullPromptText }
}

/** 各阶段读取同一份脱敏快照；续扫、验证和 Deep 子审计不能悄悄换成当前磁盘知识。 */
export async function readScanKnowledgeBase(config: Config, scanId: string): Promise<{ promptText: string; skipped: KnowledgeBase['skipped'] }> {
  const state = getStateDir(config.stateDir)
  const retained = await loadScan(state, scanId)
  if (!retained.knowledgeBaseSnapshot && retained.lifecycle !== 'completed') {
    await mutateScan(config, scanId, async scan => {
      if (scan.knowledgeBaseSnapshot) return
      let kb: { promptText: string; skipped: KnowledgeBase['skipped'] }
      if (scan.parentScanId) kb = await readScanKnowledgeBase(config, scan.parentScanId)
      else kb = await loadKnowledgeBase(scan.target, config.knowledgeBase ?? [])
      const artifactRef = await writeArtifact(scan, 'artifacts/01_context/knowledge_base.md', kb.promptText)
      scan.knowledgeBaseSnapshot = { artifactRef, sha256: sha256(await readArtifact(scan, artifactRef)), skipped: kb.skipped }
    })
  }
  const scan = await loadScan(state, scanId), snapshot = scan.knowledgeBaseSnapshot
  if (!snapshot) throw new Error('This completed legacy scan has no frozen knowledge base; current files cannot substitute for its original context.')
  const promptText = await readArtifact(scan, snapshot.artifactRef)
  if (sha256(promptText) !== snapshot.sha256) throw new Error('Frozen knowledge-base context changed after capture.')
  return { promptText, skipped: snapshot.skipped }
}
