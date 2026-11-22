# 贡献指南

提交改动前请先阅读本文。审计结论必须能追溯到源码位置、验证记录或运行记录，证据不足时标记为“待验证”。

## 开发环境

- Node.js `>= 22.19.0`（CI 使用 Node 22）
- npm、Git
- 可选：Docker（用于沙箱集成测试）

```sh
npm ci --ignore-scripts
npm run typecheck
npm run check:skills
npm run check:dsh-runtime
npm test
npm run benchmark:golden
```

### 运行 Docker 沙箱集成测试

默认跳过这些测试。需要时先准备一个本地镜像，然后设置：

```sh
export DSH_TEST_SANDBOX_EXECUTABLE=/usr/local/bin/docker
export DSH_TEST_SANDBOX_IMAGE=sha256:<64 位镜像摘要>
npm test
```

## 提交规范

1. 先写失败的测试。 修 Bug 时，先补一个在旧代码上失败的回归测试。安全修复必须附带可复现的攻击用例（参考 `tests/git-readonly.test.ts`）。
2. 不要放宽门禁。 涉及审批（`WRITE_ACTION_APPROVALS`）、沙箱参数、凭据 Origin 绑定或输出脱敏的改动，PR 描述中要单独说明安全影响。
3. 运行时依赖由宿主提供。 `@deepseek-ai/*` 只能作为可选 peer 依赖，`scripts/check-dsh-runtime.mjs` 会校验这一点。新增第三方运行时依赖需要先讨论。
4. Skill 改动要通过校验。 修改 `skills/` 后运行 `npm run check:skills`，并同步 `skills/catalog.json`。
5. 检测规则需要基准。 新增或调整规则时，在 `tests/golden/corpus.json` 中补充正例和负例，并确认 `npm run benchmark:golden` 没有引入误报。
6. 注释使用中文，命名清晰；涉及上游改编的内容，在 `docs/security-source-attribution.md` 中记录来源和许可。

## 报告安全问题

请阅读 [SECURITY.md](SECURITY.md)，不要在公开 Issue 中披露漏洞细节。
