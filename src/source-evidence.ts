import { redactSensitive } from './audit-context.js'
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import type { FileReceipt, Location, ReceiptSourceReference, ScanRecord } from './contracts.js'
import { sha256 } from './state.js'

export function safeSourcePath(root: string, path: string): string {
  if (!path || isAbsolute(path) || path.includes('\\') || path.split('/').some(p => p === '..' || p === '.')) throw new Error('Source path must be a safe repository-relative path.')
  const destination = resolve(root, path), rel = relative(resolve(root), destination)
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error('Source path is outside the scan target.')
  return destination
}
/** 源码读取拒绝符号链接和特殊文件，最多读取上限内的原始字节。 */
export async function readBoundedSource(root: string, relativePath: string, maxBytes = 10_485_760): Promise<string> {
  const path = safeSourcePath(root, relativePath)
  let component = resolve(root)
  if (!(await lstat(component)).isDirectory()) throw new Error('Source root must be a non-symlink directory.')
  for (const part of relativePath.split('/')) {
    component = resolve(component, part)
    if ((await lstat(component)).isSymbolicLink()) throw new Error('Source evidence refuses symbolic links.')
  }
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
  try {
    const before = await file.stat()
    if (!before.isFile() || before.size > maxBytes) throw new Error('Source evidence requires a bounded regular file.')
    const buffer = Buffer.allocUnsafe(before.size + 1)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await file.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await file.stat()
    if (offset !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error('Source file changed during evidence read.')
    return buffer.subarray(0, offset).toString('utf8')
  } finally { await file.close() }
}

export async function readFrozenSource(root: string, receipt: FileReceipt): Promise<string> {
  const content = await readBoundedSource(root, receipt.path)
  if (sha256(content) !== (receipt.sourceSha256 ?? receipt.sha256)) throw new Error(`Source file changed after scan receipt: ${receipt.path}.`)
  return content
}
export function boundedRange(content: string, startLine = 1, endLine?: number): { startLine: number; endLine: number; content: string } {
  const lines = content.split(/\r?\n/)
  if (!Number.isInteger(startLine) || startLine < 1 || startLine > lines.length || (endLine !== undefined && (!Number.isInteger(endLine) || endLine < startLine))) throw new Error('Invalid source line range.')
  const end = Math.min(endLine ?? startLine + 199, startLine + 399, lines.length)
  const selected=lines.slice(startLine-1,end).join('\n');if(Buffer.byteLength(selected)>32768)throw new Error('Source range exceeds the 32 KiB context budget; request fewer lines. A single oversized line must remain explicitly blocked/deferred.')
  return { startLine, endLine: end, content:selected }
}
export async function resolveSnapshotLocations(scan: ScanRecord, refs: ReceiptSourceReference[]): Promise<Location[]> {
  const cache = new Map<string, string>()
  const allowed = ['entrypoint','wrapper','propagation','root_control','sink','outcome','expected_control']
  if (!refs.length || refs.length > 100) throw new Error('Source references require one to 100 locations.')
  const result: Location[] = []
  for (const ref of refs) {
    if (!allowed.includes(ref.role) || !Number.isInteger(ref.line) || ref.line < 1) throw new Error('Invalid source reference role or line.')
    const receipt = [...scan.coverage.receipts, ...(scan.coverage.contextReceipts ?? [])].find(r => r.path === ref.file)
    if (!receipt) throw new Error(`Source reference is outside the scan receipt: ${ref.file}.`)
    if (!cache.has(ref.file)) cache.set(ref.file, await readFrozenSource(scan.evidenceRoot ?? scan.target, receipt))
    const excerpt = cache.get(ref.file)!.split(/\r?\n/)[ref.line-1]?.trim().slice(0,240)
    if (!excerpt) throw new Error('Source reference does not identify a readable source line.')
    const safeExcerpt=redactSensitive(cache.get(ref.file)!).split(/\r?\n/)[ref.line-1]?.trim().slice(0,240)
    result.push({ ...ref, excerpt,...(safeExcerpt!==excerpt?{redactedExcerpt:safeExcerpt}:{}) })
  }
  return result
}
