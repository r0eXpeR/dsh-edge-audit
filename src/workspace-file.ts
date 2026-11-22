import { lstat, readFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'

/**
 * 读取模型/用户指定的工作区输入文件（导入清单、批量 CSV 等）。
 *
 * 被审计仓库本身是不可信输入：仓库内的符号链接可以指向 `~/.aws/credentials`
 * 之类的宿主文件。词法上的路径包含检查不足以阻止这种读取，因此这里逐级拒绝
 * 符号链接，并只接受有大小上限的常规文件。
 */
export async function readWorkspaceInputFile(workspace: string, requested: string, maxBytes = 8 * 1024 * 1024): Promise<{ path: string; content: string }> {
  const root = resolve(workspace)
  const target = resolve(root, requested)
  const rel = relative(root, target)
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error('Input file must remain inside the active workspace.')
  if ((await lstat(root)).isSymbolicLink()) throw new Error('Workspace root is a symbolic link.')
  let current = root
  for (const part of rel.split(sep)) {
    current = resolve(current, part)
    const info = await lstat(current)
    if (info.isSymbolicLink()) throw new Error('Input file paths refuse symbolic links.')
  }
  const info = await lstat(target)
  if (!info.isFile()) throw new Error('Input file must be a regular file.')
  if (info.size > maxBytes) throw new Error(`Input file exceeds the ${maxBytes}-byte limit.`)
  return { path: target, content: await readFile(target, 'utf8') }
}
