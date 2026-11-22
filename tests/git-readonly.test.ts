import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { readonlyGit } from '../src/git-readonly.ts'
import { reviewGitDiff } from '../src/scanner.ts'

const git = promisify(execFile)

/** 构造一个在仓库本地配置中挂接恶意 clean/textconv 驱动的不可信仓库。 */
async function hostileRepository(): Promise<{ root: string; marker: string }> {
  const root = await mkdtemp(join(tmpdir(), 'dsh-edge-git-'))
  const marker = join(root, 'DRIVER_EXECUTED')
  const run = (...args: string[]) => git('git', args, { cwd: root, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' } })
  await run('init', '-q', '.')
  await run('config', 'user.email', 'fixture@example.invalid')
  await run('config', 'user.name', 'fixture')
  await writeFile(join(root, '.gitattributes'), '*.js filter=hostile diff=hostile\n')
  await writeFile(join(root, 'app.js'), 'export const value = 1\n')
  await run('add', '.')
  await run('commit', '-qm', 'initial')
  const payload = `sh -c 'touch "${marker}"; cat'`
  await run('config', 'filter.hostile.clean', payload)
  await run('config', 'filter.hostile.process', payload)
  await run('config', 'diff.hostile.textconv', payload)
  await run('config', 'diff.hostile.command', payload)
  // 确保 stat 信息变化，迫使 Git 对工作树文件重新运行 clean 过滤器。
  await new Promise(resolve => setTimeout(resolve, 1100))
  await writeFile(join(root, 'app.js'), 'export const value = 2\n')
  await writeFile(join(root, 'new.js'), 'export const added = true\n')
  return { root, marker }
}

test('read-only Git neutralizes repository-local filter and diff drivers during working-tree review', async () => {
  const { root, marker } = await hostileRepository()
  try {
    await readonlyGit(['status', '--porcelain'], { cwd: root, encoding: 'utf8' })
    const review = await reviewGitDiff(root, undefined, 'working_tree')
    assert.equal(existsSync(marker), false, 'a repository-local Git driver must never execute during a read-only review')
    assert.match(review.diff, /value = 2/)
    assert.ok(review.changedNames?.includes('app.js'))
    assert.ok(review.changedNames?.includes('new.js'), 'untracked text files are accounted for in changedNames')
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('read-only Git refuses driver names that cannot be neutralized through -c', async () => {
  const root = await mkdtemp(join(tmpdir(), 'dsh-edge-git-'))
  try {
    await git('git', ['init', '-q', '.'], { cwd: root })
    await writeFile(join(root, '.git', 'config'), '[filter "a=b"]\n\tclean = false\n', { flag: 'a' })
    await assert.rejects(() => readonlyGit(['status', '--porcelain'], { cwd: root, encoding: 'utf8' }), /cannot be neutralized/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

const isolatedGitEnv = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null' }

test('read-only Git ignores core.worktree that points outside the audited repository', async () => {
  const base = await mkdtemp(join(tmpdir(), 'dsh-edge-worktree-'))
  const host = join(base, 'host'), root = join(base, 'repo')
  try {
    await mkdir(join(host, '.ssh'), { recursive: true })
    await writeFile(join(host, '.ssh', 'id_rsa'), 'HOST-SECRET-MATERIAL\n')
    await mkdir(join(root, '.ssh'), { recursive: true })
    const run = (...args: string[]) => git('git', args, { cwd: root, env: isolatedGitEnv })
    await run('init', '-q', '.')
    await writeFile(join(root, '.ssh', 'id_rsa'), 'decoy\n')
    await run('add', '.')
    await run('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'initial')
    await run('config', 'core.worktree', host)
    const toplevel = await readonlyGit(['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' })
    assert.equal(await realpath(toplevel.stdout.trim()), await realpath(root))
    const review = await reviewGitDiff(root, undefined, 'working_tree')
    assert.doesNotMatch(review.diff, /HOST-SECRET-MATERIAL/)
  } finally { await rm(base, { recursive: true, force: true }) }
})

test('read-only Git refuses implicit bare repositories that redirect the worktree', async () => {
  const base = await mkdtemp(join(tmpdir(), 'dsh-edge-bare-'))
  const host = join(base, 'host'), root = join(base, 'audited')
  try {
    await mkdir(host, { recursive: true })
    await writeFile(join(host, 'secret.txt'), 'HOST-SECRET-MATERIAL\n')
    await mkdir(root, { recursive: true })
    const run = (...args: string[]) => git('git', args, { cwd: root, env: isolatedGitEnv })
    await run('init', '-q', '--bare', '.')
    await run('config', 'core.bare', 'false')
    await run('config', 'core.worktree', host)
    await assert.rejects(readonlyGit(['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' }))
  } finally { await rm(base, { recursive: true, force: true }) }
})
