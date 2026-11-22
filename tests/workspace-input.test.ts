import assert from 'node:assert/strict'
import { mkdtemp, rm, symlink, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { readWorkspaceInputFile } from '../src/workspace-file.ts'
import { csvFields, csvPaths } from '../src/operations.ts'
import { importFindings } from '../src/analysis.ts'

async function fixture(): Promise<{ root: string; outside: string; cleanup: () => Promise<void> }> {
  const base = await mkdtemp(join(tmpdir(), 'dsh-edge-input-'))
  const root = join(base, 'workspace'), outside = join(base, 'host-secret.txt')
  await mkdir(root)
  await writeFile(outside, 'aws_secret_access_key=HOST-ONLY-SECRET\n')
  return { root, outside, cleanup: () => rm(base, { recursive: true, force: true }) }
}

test('workspace input files refuse symbolic links that point at host secrets', async () => {
  const { root, outside, cleanup } = await fixture()
  try {
    await symlink(outside, join(root, 'targets.csv'))
    await mkdir(join(root, 'linked'))
    await symlink(outside, join(root, 'linked', 'findings.txt'))
    await assert.rejects(() => readWorkspaceInputFile(root, 'targets.csv'), /symbolic links/)
    await assert.rejects(() => readWorkspaceInputFile(root, 'linked/findings.txt'), /symbolic links/)
    await assert.rejects(() => importFindings(root, 'targets.csv'), /symbolic links/)
    await assert.rejects(() => readWorkspaceInputFile(root, '../host-secret.txt'), /inside the active workspace/)
    await assert.rejects(() => readWorkspaceInputFile(root, '.'), /inside the active workspace/)
  } finally { await cleanup() }
})

test('workspace input files enforce regular-file and size bounds', async () => {
  const { root, cleanup } = await fixture()
  try {
    await mkdir(join(root, 'dir'))
    await writeFile(join(root, 'big.json'), 'x'.repeat(2048))
    await writeFile(join(root, 'ok.json'), '[]')
    await assert.rejects(() => readWorkspaceInputFile(root, 'dir'), /regular file/)
    await assert.rejects(() => readWorkspaceInputFile(root, 'big.json', 1024), /limit/)
    assert.equal((await readWorkspaceInputFile(root, './ok.json')).content, '[]')
  } finally { await cleanup() }
})

test('bulk CSV parsing honours quoted commas, escaped quotes, BOM and comments', () => {
  assert.deepEqual(csvFields('"a,b",c'), ['a,b', 'c'])
  assert.deepEqual(csvFields('"say ""hi""",x'), ['say "hi"', 'x'])
  assert.deepEqual(csvPaths('﻿name,path\n# comment\nsvc,"services/a,b"\nweb,apps/web\n'), ['services/a,b', 'apps/web'])
  assert.deepEqual(csvPaths('src/a\nsrc/b\n'), ['src/a', 'src/b'])
  assert.throws(() => csvPaths('\n\n'), /no target paths/)
})
