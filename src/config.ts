import Schema from '@deepseek-ai/schemastery'

/** Mirrors codex-security `[deep_scan]` configuration (Apache-2.0, adapted). */
export interface DeepScanConfig {
  /** Concurrent discovery workers: positive integer, or 'auto' for half of available parallelism capped at six. */
  workers: number | 'auto'
  /** Subagents each deep discovery worker may spawn for file review. */
  subagents: number
  /** Stop discovery after this many complete rounds with no new findings. */
  stopAfterNoNew: number
  /** Stop discovery after this many consecutive failing worker rounds. */
  stopAfterConsecutiveErrors: number
  /** Hard cap on complete discovery rounds. */
  maxDiscoveryRuns: number
  /** Maximum discovery wall-clock hours (fractional allowed, capped at 96). */
  maxTimeHours: number
}

export interface Config {
  enabled: boolean
  maxFiles: number
  maxFileBytes: number
  maxTotalBytes?: number
  stateDir: string
  workerTimeoutMs?: number
  maxConcurrentModelWorkers?:number
  /** 单次模型批次的源码区域上限；批次间持久化进度。 */
  discoveryBatchRegions?: number
  /** 覆盖补漏波次上限；耗尽仍保留为 incomplete。 */
  maxCoverageWaves?: number
  /** Standard/Diff 整次审计的绝对墙钟上限，恢复不重置。 */
  maxAuditTimeHours?: number
  /** Standard 专项调查的并发上限，Deep 使用 subagents 覆盖。 */
  investigatorConcurrency?: number
  /** 内部父审计预算归属；不向模型或公开配置暴露。 */
  auditBudgetScanId?: string
  auditPriorContext?:string
  /** 已测 Token 的轮间软预算；并发在途请求可能超出。无计数时停止而不伪造成本。 */
  maxModelTokens?: number
  /** 仅显式引用才读取，绑定目标 Origin；不向模型公开凭据值。 */
  credentialRefs?: Array<{id:string;environment:string;origins:string[]}>
  /** 隔离验证沙箱：绝对路径 Docker 可执行文件 + sha256 固定的本地镜像；socket 为可选的绝对路径 Unix socket（默认 /var/run/docker.sock）。 */
  validationSandbox?: { executable: string; image: string;socket?:string;allowedDummyCredentialDigests?:string[] }
  /** Deep-scan engine settings, aligned with codex-security deep_scan. Optional for backward compatibility. */
  deepScan?: DeepScanConfig
  /** Read-only security knowledge base: files or directories of Markdown/text/PDF/DOCX. Optional. */
  knowledgeBase?: string[]
  /** Extra shared scan instructions (equivalent of --scan-prompt-file content). Optional. */
  scanPrompt?: string
  /** 运维方可信的误报判定指令，只注入验证者；不能替代源码证据。 */
  filterInstructions?: string
}

export const DEFAULT_DEEP_SCAN: DeepScanConfig = {
  workers: 'auto',
  subagents: 3,
  stopAfterNoNew: 6,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 60,
  maxTimeHours: 96,
}

/** Fill codex-security-aligned defaults for optional suite settings. */
export function normalizeConfig(config: Config): Config {
  return {
    ...config,
    deepScan: { ...DEFAULT_DEEP_SCAN, ...(config.deepScan ?? {}) },
    knowledgeBase: config.knowledgeBase ?? [],
    scanPrompt: config.scanPrompt ?? '',
    filterInstructions: config.filterInstructions ?? '',
  }
}

export const Config: Schema<Config> = Schema.object({
  enabled: Schema.boolean().default(true),
  maxFiles: Schema.number().min(1).max(10_000).default(500),
  maxTotalBytes:Schema.number().min(1048576).max(536870912).default(67108864),
  maxFileBytes: Schema.number().min(1_024).max(10_485_760).default(262_144),
  stateDir: Schema.string().default(''),
  maxModelTokens:Schema.number().min(1),
  maxConcurrentModelWorkers:Schema.number().min(1).max(32).default(6),
  workerTimeoutMs: Schema.number().min(1000).max(3600000).default(180000),
  discoveryBatchRegions: Schema.number().min(1).max(32).default(6),
  maxAuditTimeHours: Schema.number().min(0.01).max(96).default(4),
  maxCoverageWaves: Schema.number().min(1).max(100).default(6),
  investigatorConcurrency: Schema.number().min(1).max(8).default(5),
  credentialRefs:Schema.array(Schema.object({id:Schema.string().required(),environment:Schema.string().required(),origins:Schema.array(Schema.string()).required()})).default([]),
  validationSandbox: Schema.object({executable:Schema.string(),image:Schema.string(),socket:Schema.string(),allowedDummyCredentialDigests:Schema.array(Schema.string())}),
  deepScan: Schema.object({
    workers: Schema.union([
      Schema.const('auto' as const),
      Schema.number().min(1).max(6),
    ]).default('auto'),
    subagents: Schema.number().min(0).max(8).default(3),
    stopAfterNoNew: Schema.number().min(1).max(100).default(6),
    stopAfterConsecutiveErrors: Schema.number().min(1).max(100).default(3),
    maxDiscoveryRuns: Schema.number().min(1).max(1_000).default(60),
    maxTimeHours: Schema.number().min(0.1).max(96).default(96),
  }).default({ ...DEFAULT_DEEP_SCAN }),
  knowledgeBase: Schema.array(Schema.string()).default([]),
  scanPrompt: Schema.string().default(''),
  filterInstructions: Schema.string().default(''),
})
