// 只操作独立副本。使用 Desktop 自带 CLI、Electron Node 和 Host，保留原始证据。
import { mkdir, readFile, writeFile, cp, readdir, realpath } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { once } from 'node:events'

const root = resolve(import.meta.dirname, '..')
const runId = new Date().toISOString().replace(/[:.]/g, '-')
const sandbox = join(root, '.sandbox', runId)
const home = join(sandbox, 'home')
const profile = join(home, 'profiles/desktop')
const app = process.env.DSH_TEST_APP ?? '/private/tmp/dsh-desktop-021rc5-sandbox/DeepSeek Harness.app'
if (!app.startsWith('/private/tmp/')) throw new Error('测试必须使用 /private/tmp 中的 Desktop 副本')
if (!(await realpath(app)).startsWith('/private/tmp/')) throw new Error('Desktop 副本不能通过符号链接指向现有安装')
const electron = join(app, 'Contents/MacOS/DeepSeek Harness')
const resources = join(app, 'Contents/Resources')
const runtime = join(resources, 'app.asar/dsh')
const support = join(resources, 'runtime')
const modules = join(runtime, 'node_modules/@deepseek-ai')
const env = {
  PATH: process.env.PATH, TMPDIR: sandbox, LANG: 'en_US.UTF-8',
  HOME: home, USERPROFILE: home, DSH_HOME: home,
  XDG_CONFIG_HOME: home, XDG_CACHE_HOME: join(home, 'cache'), XDG_STATE_HOME: home,
  APPDATA: home, LOCALAPPDATA: home,
  ELECTRON_RUN_AS_NODE: '1', NARB_NATIVE_CACHE_DIR: join(sandbox, 'native-cache'),
  DSH_CLIENT_VERSION: '0.2.1-rc.5',
  npm_config_ignore_scripts:'true',
  npm_config_userconfig: join(home, 'npmrc'), npm_config_globalconfig: join(home, 'npmrc-global'),
  npm_config_store_dir: join(sandbox, 'pnpm-store'), npm_config_enable_global_virtual_store: 'false',
}
await mkdir(profile, { recursive: true })
await writeFile(join(home, 'npmrc'), 'registry=https://registry.npmjs.org/\n')
await writeFile(join(home, 'npmrc-global'), '')
const evidence = join(root, '.artifacts/desktop', runId)
await mkdir(evidence, { recursive: true })
await writeFile(join(root, '.artifacts/desktop/latest.json'), JSON.stringify({ sandbox, evidence }, null, 2))

async function runNode(args, label) {
  const child = spawn(electron, ['--expose-internals', ...args], { env, cwd: sandbox })
  let output = ''
  for (const pipe of [child.stdout, child.stderr]) pipe.on('data', bytes => { output += bytes })
  const [code] = await once(child, 'exit')
  await writeFile(join(evidence, label + '.log'), output)
  if (code !== 0) throw new Error(label + ' failed: ' + output.slice(-4000))
  return output
}
const setup = join(sandbox, 'setup.cjs')
await writeFile(setup, `const fs = require('node:fs');
(async () => {
const boot = await import(${JSON.stringify(join(modules, 'dsh-app-boot/lib/index.js'))});
boot.initProfile(${JSON.stringify(profile)}, boot.PROFILE_TEMPLATES.web.bundles);
const descriptor = JSON.parse(fs.readFileSync(${JSON.stringify(join(runtime, 'desktop-runtime.json'))}));
const app = JSON.parse(fs.readFileSync(${JSON.stringify(join(resources, 'app.asar/package.json'))}));
if (descriptor.release.version !== '0.2.1-rc.5' || app.version !== '0.2.1-rc.5') throw new Error('Wrong Desktop target version');
for (const record of descriptor.sharedPackages) {
  if (!['@deepseek-ai/cordis','@deepseek-ai/schemastery','@deepseek-ai/dsh-agent','@deepseek-ai/dsh-tools','@deepseek-ai/dsh-llm','@deepseek-ai/dsh-session','@deepseek-ai/dsh-system-prompt'].includes(record.name)) continue;
  const pkg = JSON.parse(fs.readFileSync(${JSON.stringify(runtime)} + '/' + record.path + '/package.json'));
  if (pkg.version !== record.version) throw new Error('Runtime SDK differs from descriptor: ' + record.name);
}
const metadata = { release: descriptor.release, platform: process.platform, arch: process.arch,
  electron: process.versions.electron, node: process.versions.node, buildCommit: app.dshBuildCommit,
  sharedPackages: descriptor.sharedPackages.filter(p => ['@deepseek-ai/cordis','@deepseek-ai/schemastery','@deepseek-ai/dsh-agent','@deepseek-ai/dsh-tools','@deepseek-ai/dsh-llm','@deepseek-ai/dsh-session','@deepseek-ai/dsh-system-prompt'].includes(p.name)) };
fs.writeFileSync(${JSON.stringify(join(evidence, 'runtime.json'))}, JSON.stringify(metadata, null, 2));
console.log(JSON.stringify(metadata));
})();`)
await runNode([setup], 'runtime')

// 候选构建仅供隔离验证；没有 engines.dsh 或发布兼容性声明。
const candidate = join(sandbox, 'candidate')
await mkdir(candidate, { recursive: true })
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
delete manifest.devDependencies
await writeFile(join(candidate, 'package.json'), JSON.stringify(manifest, null, 2) + '\n')
for (const name of ['dist', 'skills', 'cordis.patch.yml', 'README.md', 'docs', 'LICENSE', 'NOTICE']) {
  await cp(join(root, name), join(candidate, name), { recursive: true })
}
const bridge = join(sandbox, 'bridge')
await mkdir(bridge, { recursive: true })
await writeFile(join(bridge, 'package.json'), JSON.stringify({
  name: 'dsh-edge-compat-bridge', version: '0.0.0', type: 'module', exports: './index.js',
  dsh: { bundle: { patch: './cordis.patch.yml' } },
}))
await cp(join(root, 'scripts/desktop-bridge.mjs'), join(bridge, 'index.js'))
await writeFile(join(bridge, 'cordis.patch.yml'), '- insert:\n    - id: dsh-edge-compat-bridge\n      name: dsh-edge-compat-bridge\n')
const cli = join(modules, 'dsh-desktop-host/lib/cli.js')
const installSource=process.env.DSH_TEST_PACKAGE?await realpath(process.env.DSH_TEST_PACKAGE):candidate
if(process.env.DSH_TEST_PACKAGE&&(!installSource.startsWith(join(root,'.artifacts/packages')+'/')||!installSource.endsWith('.tgz')))throw new Error('归档安装验收只接受本仓库 .artifacts/packages 下的 .tgz')
await runNode([cli, 'plugin', '--profile', 'desktop', 'add', 'file:' + installSource, '--ignore-scripts'], 'install')
await writeFile(join(evidence,'install-source.json'),JSON.stringify({kind:process.env.DSH_TEST_PACKAGE?'packed-tgz':'candidate-directory',path:installSource},null,2))
await runNode([cli, 'plugin', '--profile', 'desktop', 'add', 'file:' + bridge, '--ignore-scripts'], 'bridge-install')
await writeFile(join(profile, 'cordis.patch.yml'), `- id: webserver
  config:
    host: 127.0.0.1
    port: 0
- id: dsh-edge-audit
  config:
    enabled: true
    maxFiles: 30
    maxFileBytes: 32768
    stateDir: ${JSON.stringify(join(sandbox, 'state'))}
    deepScan:
      workers: auto
      stopAfterNoNew: 1
      maxDiscoveryRuns: 60
      maxTimeHours: 1
`)
// 安装结果中禁止出现任何 DSH 核心包副本。
const scoped = join(profile, 'node_modules/@deepseek-ai')
const injected = await readdir(scoped).catch(error => error.code === 'ENOENT' ? [] : Promise.reject(error))
if (injected.length) throw new Error('Profile 注入了核心包: ' + injected.join(', '))
await writeFile(join(evidence, 'profile-core-packages.json'), JSON.stringify({ injected }, null, 2))

const host = spawn(electron, ['--expose-internals', join(modules, 'dsh-desktop-host/lib/index.js'), runtime, profile,
  join(support, 'primary-runtime'), join(support, 'primary-runtime/dependencies/pnpm/bin/pnpm.mjs'), join(support, 'bin')],
{ cwd: profile, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
let log = ''
for (const pipe of [host.stdout, host.stderr]) pipe.on('data', bytes => { log += bytes })
const ready = await new Promise((ok, fail) => {
  const timeout = setTimeout(() => fail(new Error('Desktop Host startup timeout')), 60_000)
  host.on('message', message => {
    if (message.type === 'ready') { clearTimeout(timeout); ok(message) }
    if (message.type === 'fatal') { clearTimeout(timeout); fail(new Error(message.diagnostic ?? message.message)) }
  })
  host.on('exit', code => { clearTimeout(timeout); fail(new Error('Desktop Host exited: ' + code + '\n' + log.slice(-4000))) })
}).catch(async error => { host.kill(); await writeFile(join(evidence, 'host.log'), log); throw error })
try {
  const auth = await fetch(ready.url, { redirect: 'manual' })
  const cookie = auth.headers.getSetCookie().map(value => value.split(';')[0]).join('; ')
  const page = await fetch(new URL('/', ready.url), { headers: { cookie } })
  if (page.status !== 200 || !(await page.text()).includes('<html')) throw new Error('Desktop frontend failed')
  console.log('Desktop Host ready; plugin installed; frontend HTTP 200; no core packages in Profile')
  const response = await fetch(new URL('/security-compat/run', ready.url), { method: 'POST', headers: { cookie } })
  const result = await response.json()
  await writeFile(join(evidence, 'result.json'), JSON.stringify(result, null, 2))
  if (!response.ok || !result.passed) throw new Error('Desktop audit regression failed: ' + JSON.stringify(result).slice(-4000))
  console.log(JSON.stringify(result, null, 2))
} finally {
  const exited = once(host, 'exit')
  host.send({ type: 'shutdown' })
  const timer = setTimeout(() => host.kill('SIGTERM'), 30_000)
  const [exitCode] = await exited
  clearTimeout(timer)
  // 不保存 authenticatedUrl、cookie 或 IPC 的认证材料。
  await writeFile(join(evidence, 'host.log'), log.replace(/([?&](?:token|key|auth)=)[^\s&]+/gi, '$1[REDACTED]'))
  await writeFile(join(evidence, 'shutdown.json'), JSON.stringify({ exitCode }, null, 2))
}

await runNode([cli, 'plugin', '--profile', 'desktop', 'remove', 'dsh-edge-audit', 'dsh-edge-compat-bridge'], 'uninstall')
const remaining=JSON.parse(await readFile(join(profile,'package.json'),'utf8'));if(remaining.dependencies?.['dsh-edge-audit'])throw new Error('Uninstall did not remove candidate dependency')
await writeFile(join(evidence,'uninstall.json'),JSON.stringify({candidateRemoved:true,bridgeRemoved:!remaining.dependencies?.['dsh-edge-compat-bridge']},null,2))
