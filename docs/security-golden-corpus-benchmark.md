# Golden Corpus 评测

这是确定性候选及定位质量评测，**不是 Confirmed Precision、真实模型召回率或真实项目漏洞数量评测**。

## 样本与同条件基线

`tests/golden/corpus.json` 当前 34 个自建合成样本：31 个确定性样本、19 个目标漏洞位置；另外 3 个跨租户对象授权、修复后对象授权、Agent 工具授权样本属于 semantic 待测。数据仅被分析，评测脚本不执行这些样本。

2026-11-17 续审新增 6 个确定性样本，覆盖进程导入别名、本地和跨模块返回值，以及参数选择、作用域遮蔽和安全字段负例。用 `npm run benchmark:golden` 可在当前代码上复算指标。下方历史对照表使用扩展前的 25 个确定性样本。

语言族覆盖 JS/TS、Python、Go、PHP、Java、C#、Ruby、C、C++、Rust。包含跨文件三跳、局部变量传播、参数化 SQL、安全同名变量作用域、Python 类型标注、Gin 参数、PHP 动态 include、Function 构造器和第 1002 行入口。不是通用语言深度审计支持声明。

基线是上游 dsh-security-suite 0.54.28 的原始 `src`；与新版使用相同脚本、同一 corpus/oracle、同一解析器依赖、maxFiles 500、maxFileBytes 262144。所有输入均低于双方有效总字节限额。没有调用外部模型或目标服务。

## 实测结果

| 指标 | 基线 | 0.55.0-dev.1 |
|---|---:|---:|
| 正确目标位置 TP | 6 | 16 |
| 误报位置 FP | 5 | 0 |
| 漏掉目标位置 FN | 10 | 0 |
| 与实际源文件行不一致的位置 | 2 | 0 |
| Candidate Precision | 0.5455 | 1.0000 |
| Candidate Recall | 0.3750 | 1.0000 |
| 五个独立进程的引擎耗时中位数 | 52.491 ms | 55.721 ms |

新版耗时范围 54.166–75.507 ms，基线 51.629–55.298 ms。小样本运行存在明显噪声，不能据此宣称大仓库提速；新版分析范围增加且保留更完整证据。

原始逐样本结果：[基线](evidence/corpus-baseline.json)、[新版](evidence/corpus-current.json)、[五轮耗时](evidence/corpus-performance.json)。指标由脚本生成，没有预设提升比例。

## 实际改进

- JS/TS、Python、Go、PHP、Java 的下游摘要保留真实 Sink 文件和中间调用，而不是把深层 Sink 行号套在中间文件上。
- 修正 JS/Python 作用域同名变量串扰；结构化语言的函数目录汇总不再被后一个文件覆盖，并保持函数作用域隔离。
- 增加 typed Python 参数、Gin 参数、PHP 动态 include 和 JS Function 构造器的实际候选检测。
- 保留参数化查询等负例，不因为请求值出现在绑定参数中就当作 SQL 文本注入。
- Runtime “只打印消息”回归现在保留 Needs Validation；规则消失、测试成功和历史 Supported 均不能自动确认或宣布修复。

## 其余指标的证据状态

| 指标 | 当前证据与限制 |
|---|---|
| Confirmed Precision / Validated Recall | null；没有真实模型发现 + 独立验证的同预算对比 |
| Coverage Completeness | 账本真实读取、检查、Critic 页覆盖及缺口门禁有回归；没有全仓库真实人工 Ground Truth 比率 |
| Attack Path Validity / Evidence Completeness | 精确路径、角色、行、摘要、独立 owner、租约及运行输出门禁有正负回归；不等同真实跨服务路径有效率 |
| Duplicate Findings | 有精确/语义 reducer、独立实例保留及 provenance 回归；真实模型语义重复率未测 |
| Scan Cost / Token | null；脚本适配器不代表供应商计费。原生 usage 缺失不会当作零；现有 Token 软预算主要用于 Discovery Worker，不能声称全流水线费用硬上限 |
| Time to Finding | 仅逐样本候选分析时间；真实模型首次有效漏洞时间未测 |
| Resume Reliability | Worker/任务/Deep Job 取消续跑、并发认领及真实 Desktop 生命周期通过；没有长时间崩溃/断网统计成功率 |

## 复现

脚本默认使用当前扩展样本。复现下方旧版基线的历史数值时，需要同时使用对应历史版本的 `corpus.json`，不能把新增样本的结果混入旧表。

```sh
npm run benchmark:golden
```

如需将结果写入 JSON，运行 `npm run benchmark:golden -- src/scanner.ts /path/to/golden-result.json`。

基线副本来自上述 Git 提交的 `src`，需要同一工作区 `node_modules` 解析器。它不包含用户业务代码，不运行参考项目的脚本。业务状态机、复杂多租户、跨服务/动态调用、opaque sanitizer、原生内存/并发缺陷、实际 Prompt Injection 驱动权限滥用仍需要独立真实模型及隔离运行证据。不得将这 25 个样本的 1.0 Candidate Recall 外推为产品检出率。

## 可执行的跨文件多租户 Ground Truth

另有 `tests/golden/tenant-runtime` 完整可运行的 Node ESM 微型项目：route 层检查登录，调用 service 读取 invoice。脆弱版本只按 ID 查找，虚拟 Alice / tenant-a 可以读取 tenant-b 发票；修复版把 tenantId 纳入实际查询，拒绝越权并保留同租户正常读取。

`tests/business-runtime.test.ts` 在无网络、宿主只读的固定本地镜像中实际执行前后版本，保留 `tenant-runtime-oracle.json`。这证明样本的授权边界和修复行为，**不证明当前模型自动发现了它**，因此不将其计入 Candidate/Validated Recall。前面的 25 个样本主要是源码分析片段，不冒充全部可编译的业务项目或公开真实 CVE。
