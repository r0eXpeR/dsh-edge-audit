import { mkdir, open, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import type { ScanRecord } from './contracts.js'
import { getStateDir, loadScan, saveScan } from './state.js'

const writes = new Map<string, Promise<void>>()
/** 同一扫描所有增量修改共享串行门；跨进程锁不静默抢占，崩溃后明确报阻断。 */
export async function mutateScan<T>(config: { stateDir: string }, scanId: string, update: (scan: ScanRecord) => T | Promise<T>): Promise<T> {
  if (!/^scan_[0-9a-f-]+$/.test(scanId)) throw new Error('Invalid scan id.')
  const state = getStateDir(config.stateDir), key = `${state}:${scanId}`
  const previous = writes.get(key) ?? Promise.resolve()
  let release!: () => void
  const barrier = new Promise<void>(r => { release = r })
  const chained = previous.then(() => barrier)
  writes.set(key, chained)
  await previous
  let lock: Awaited<ReturnType<typeof open>> | undefined
  const directory = join(state, 'scan-locks')
  const path = join(directory, `${scanId}.lock`)
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 })
    for (let attempt = 0; !lock; attempt++) {
      try { lock = await open(path, 'wx', 0o600); await lock.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString() })) }
      catch (e) { if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e; if (attempt >= 100) throw new Error('Scan is locked by another process or interrupted writer; inspect the lock before recovery.'); await delay(20) }
    }
    const scan = await loadScan(state, scanId)
    const result = await update(scan)
    await saveScan(state, scan)
    return result
  } finally {
    try {
      if (lock) {
        try { await lock.close() } finally { await rm(path, { force: true }) }
      }
    } finally {
      release()
      if (writes.get(key) === chained) writes.delete(key)
    }
  }
}
