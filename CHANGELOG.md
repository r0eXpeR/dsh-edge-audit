# 更新日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.58.0] - 2026-11-22

### 安全修复

- **借 `core.worktree` 读取宿主文件（中危）。** 被审计仓库的 `.git/config` 可以把 `core.worktree` 指向任意宿主目录，Diff 审计执行 `git diff HEAD` 时会把宿主文件（例如 `~/.ssh/id_rsa`）与提交中的同名文件比较，内容随 diff 进入模型上下文。`readonlyGit` 现在沿父目录定位 `.git`，并用命令行的 `--git-dir`/`--work-tree` 固定仓库位置；同时启用 `safe.bareRepository=explicit`，拒绝伪装成裸仓库、在配置里重定向工作树的目录。

### 修复

- 只设置旧环境变量 `DSH_FONSHANG_AUDIT_STATE_DIR` 时，commit / branch_diff 审计的源码快照写在状态目录里，却被当成临时目录在审计结束后删除，导致之后无法恢复。改名时引入，现已修正。

### 变更

- 项目改名为 EdgeAudit（名称取自棱角社区 EdgeSecurity）。包名和插件 id 由 `dsh-fonshang-audit` 改为 `dsh-edge-audit`，8 个随包 Skill 由 `dsh-fonshang-*` 改为 `dsh-edge-*`，默认状态目录改为 `~/.dsh-edge-audit`，环境变量改为 `DSH_EDGE_AUDIT_STATE_DIR`。升级步骤见 README 的迁移一节。
- SARIF 导出不再写入 `informationUri`。原值指向上游 dsh-security-suite 的仓库，不是本项目地址。
- README 按常规项目文档重写，补充报告归档位置、Diff 分支审计示例、配置项说明和迁移说明。安装说明改为从源码构建，不再依赖发行压缩包。
- 补充上游项目 dsh-security-suite 0.54.28 的来源与许可说明（README、NOTICE、docs/security-source-attribution.md），重写来源文档，删除本地迁移过程记录。
- `package.json` 补充 `repository`、`homepage`、`bugs`。

### 兼容

- `~/.dsh-edge-audit` 不存在时依次沿用 `~/.dsh-fonshang-audit`、`~/.dsh-security-suite`。
- `DSH_FONSHANG_AUDIT_STATE_DIR` 继续有效，新变量优先。
- 外部工单和 GitHub 安全通告去重时同时识别旧版写入的 `dsh-fonshang-audit` 标记，避免升级后重复创建。
- 导出数据中的 `dsh-security-suite.*` schema 标识和指纹算法名保持不变，历史结果仍可对比。

## [0.57.0] - 2026-11-19

### 安全修复

- **Git 驱动命令执行（高危）。** 审计一个带有恶意 `.git/config` 的仓库时，`git diff HEAD`、`git status` 等工作树命令会执行仓库本地定义的 `filter.<name>.clean/process`。`readonlyGit` 现在会先枚举仓库配置中的 filter、diff、merge 驱动，用空值逐一覆盖，并对 `diff` 和 `diff-tree` 强制加上 `--no-ext-diff`。如果驱动名无法安全覆盖，就直接拒绝执行。
- **借符号链接读取宿主文件（中危）。** `security_import_findings` 和 `security_bulk_scan_csv` 此前只在词法上检查路径，仓库内的 `targets.csv -> ~/.aws/credentials` 这类链接会让宿主文件内容作为发现描述或批量条目回显给模型。现在改由新增的 `readWorkspaceInputFile` 读取：逐级拒绝符号链接，只接受常规文件，并限制大小。

### 修复

- Diff 审计：工作树中的未跟踪文本文件现在会计入 `changedNames`。因截断而未进入 diff 的文件会作为 `omitted` 记入覆盖账本，不再被静默丢弃。一条提前返回的分支此前遗漏了 `changedNames`，也一并修正。
- 批量 CSV：解析器支持带引号的字段、字段内逗号、`""` 转义、UTF-8 BOM 和 `#` 注释行，单个作业最多 500 个目标。
- `npm test` 的 glob 加上引号，避免 `sh` 在 Node 展开之前错误地预展开 `**`。

### 新增

- `validationSandbox.socket`：可选的绝对路径 Unix socket，适配 Colima、OrbStack 和 rootless Docker 等非默认 socket 位置，默认仍为 `/var/run/docker.sock`。不接受 TCP 等远程地址。

### 工程与文档

- 新增 `SECURITY.md`、`CONTRIBUTING.md`、`CHANGELOG.md`，`package.json` 补充作者与关键词。
- 重写 README：补充架构图、完整工作流、工具分组、配置参考和常见问题。
- 文档和证据文件中的本机绝对路径已脱敏，并清理了 `.DS_Store`。
