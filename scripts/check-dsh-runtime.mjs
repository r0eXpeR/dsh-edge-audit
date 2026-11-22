import { readFile, readdir } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'

const root = process.cwd()
const allowedPackages = new Set([
  '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-agent',
  '@deepseek-ai/dsh-llm',
  '@deepseek-ai/dsh-session',
  '@deepseek-ai/dsh-skill',
  '@deepseek-ai/dsh-system-prompt',
  '@deepseek-ai/dsh-tools',
  '@deepseek-ai/dsh-working-directory',
  '@deepseek-ai/dsh-util-values',
  '@deepseek-ai/schemastery',
  '@typescript-eslint/typescript-estree',
])

async function sourceFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await sourceFiles(path))
    else if (extname(entry.name) === '.ts') files.push(path)
  }
  return files
}

const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const target = '0.2.1-rc.5'
for (const [name, version] of Object.entries(manifest.peerDependencies ?? {})) {
  if (name.startsWith('@deepseek-ai/dsh-') && version !== target) throw new Error(`SDK peer must match target Desktop: ${name}@${version}`)
  if (name.startsWith('@deepseek-ai/') && manifest.peerDependenciesMeta?.[name]?.optional !== true) {
    throw new Error(`Host-owned peer must not be auto-installed into a Profile: ${name}`)
  }
  if (manifest.devDependencies?.[name] !== version) throw new Error(`Build SDK differs from declared peer: ${name}`)
}
for (const name of Object.keys(manifest.dependencies ?? {})) {
  if (name.startsWith('@deepseek-ai/')) throw new Error(`Core runtime must be supplied by Desktop, not dependencies: ${name}`)
}
const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'))
for (const [path, entry] of Object.entries(lock.packages ?? {})) {
  if (/node_modules\/@deepseek-ai\/dsh(?:-|$)/.test(path) && entry.version !== target) {
    throw new Error(`Lockfile contains a mismatched DSH SDK: ${path}@${entry.version}`)
  }
}
const declaredPackages = new Set([
  ...Object.keys(manifest.dependencies ?? {}),
  ...Object.keys(manifest.peerDependencies ?? {}),
])
for (const packageName of declaredPackages) {
  if (!allowedPackages.has(packageName)) throw new Error(`Non-DSH runtime dependency declared: ${packageName}`)
}

for (const path of await sourceFiles(join(root, 'src'))) {
  const source = await readFile(path, 'utf8')
  const imports = source.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^'\"]*?\s+from\s+)?['\"]([^'\"]+)['\"]/g)
  for (const match of imports) {
    const specifier = match[1]
    if (specifier.startsWith('.') || specifier.startsWith('node:')) continue
    if (!allowedPackages.has(specifier)) {
      throw new Error(`Non-DSH source import in ${relative(root, path)}: ${specifier}`)
    }
  }
}
