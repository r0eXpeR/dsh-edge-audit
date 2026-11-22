export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type Confidence = 'high' | 'medium' | 'low'
export type FindingStatus = 'open' | 'false_positive' | 'resolved' | 'unknown'
export type CandidateDisposition = 'discovered' | 'reportable' | 'suppressed' | 'deferred' | 'not_applicable'
export type ScanLifecycle = 'queued' | 'preflight' | 'threat_model' | 'discovery' | 'validation' | 'attack_path' | 'reporting' | 'completed' | 'incomplete' | 'failed' | 'cancelled'
export type EvidenceKind = 'pattern' | 'context' | 'policy' | 'validation' | 'counterevidence' | 'attack_path' | 'runtime' | 'test'
export type LocationRole = 'entrypoint' | 'wrapper' | 'propagation' | 'root_control' | 'sink' | 'outcome' | 'expected_control'

export interface Location { redactedExcerpt?:string; file: string; line: number; excerpt: string; role?: LocationRole }
/** An exact, immutable-source location cited by a validation or attack-path receipt. */
export interface ReceiptSourceReference { file: string; line: number; role: LocationRole }
export interface Evidence { kind: EvidenceKind; detail: string; location?: Location; artifactRef?: string }

export interface RuntimeObservation {receiptRef:string;expectedInvariant:string;observedResult:string;outputExcerpt:string}
export interface ValidationRecord {
  validationPlan?:{local?:string;deployment?:string}
  resolvedProofGaps?:Array<{gap:string;resolution:string;sourceReferences:ReceiptSourceReference[]}>
  runtimeObservation?:RuntimeObservation
  method: 'static' | 'test' | 'runtime' | 'hybrid'
  conclusion: 'reportable' | 'suppressed' | 'deferred' | 'not_applicable'
  attacker: string
  entryPoint: string
  trustBoundary: string
  rootControl: string
  sink: string
  impact: string
  directEvidence: string
  counterevidence: string
  limitations: string
  confidence: Confidence
  sourceReferences: ReceiptSourceReference[]
  /** Runtime evidence receipts bound to this candidate validation, when used. */
  runtimeReceiptRefs?: string[]
  reviewer?: string
  independent?: boolean
  snapshotDigest?: string
  proofGaps?: string[]
  recordedAt: string
}

export interface AttackPathRecord {
  policyDecision?: {severity?:string;decision:string;rationale:string}
  attacker: string
  entryPoint: string
  preconditions: string
  dataflow: string
  outcome: string
  severityRationale: string
  changeConditions: string
  sourceReferences: ReceiptSourceReference[]
  reviewer?: string
  snapshotDigest?: string
  steps?: Array<{ action: string; preconditions: string; dependency: string; sourceReferences: ReceiptSourceReference[] }>
  recordedAt: string
}

export interface CandidateLedgerEntry {
  at: string
  phase: 'discovery' | 'validation' | 'attack_path' | 'finalization'
  disposition: CandidateDisposition
  summary: string
  artifactRef?: string
}

export type FindingLifecycle = 'discovered' | 'candidate' | 'investigating' | 'validating' | 'confirmed' | 'needs_validation' | 'rejected' | 'fixed' | 'reverified'
export type EvidenceLevel = 'source_backed' | 'statically_validated' | 'runtime_validated' | 'needs_validation' | 'rejected'
export interface Finding {
  finalReview?:{reviewer:string;decision:'verified'|'replaced';validationDigest:string;at:string}
  changeEvidence?:{file:string;hunk:string;explanation:string;patchSha256?:string}
  discoveryProofGaps?:string[]
  duplicateOf?:string
  priorReceipts?:Array<{validationRecord?:ValidationRecord;attackPathRecord?:AttackPathRecord;reason:string;at:string}>
  lifecycleState?: FindingLifecycle
  evidenceLevel?: EvidenceLevel
  discoveredBy?: string[]
  discoveryProvenance?: Array<{ actorId: string; jobId?: string; workerId?: string; at: string }>
  businessBoundary?: { principal: string; role: string; tenant: string; object: string; operation: string; authorizationDecision: string; invariant: string }
  revalidation?: { outcome: 'fixed' | 'still_vulnerable' | 'inconclusive'; followupScanId: string; reviewer: string; evidence: string; sourceReferences: ReceiptSourceReference[]; at: string }

  id: string
  candidateId: string
  fingerprint: string
  ruleId: string
  identity: { anchor: string; instance?: string }
  title: string
  severity: Severity
  confidence: Confidence
  cwe: string
  status: FindingStatus
  disposition: CandidateDisposition
  locations: Location[]
  rootCause: string
  validation: string
  attackPath: string
  impact: string
  remediation: string
  counterevidence: string
  evidence: Evidence[]
  ledger: CandidateLedgerEntry[]
  validationRecord?: ValidationRecord
  attackPathRecord?: AttackPathRecord
  writeup?: {
    reportPath: string
    generatedAt: string
    evidenceDigest: string
    poc: { status: 'not_generated'; rationale: string }
  }
  /** codex-security finding_triage close reason; present only when closed. */
  closeReason?: 'already_fixed' | 'wont_fix' | 'false_positive'
  /** Append-only triage audit log (codex-security finding_decisions). */
  triageDecisions?: Array<{ status: 'open' | 'closed'; closeReason?: 'already_fixed' | 'wont_fix' | 'false_positive'; note?: string; at: string }>
}

export interface FileReceipt { path: string; bytes: number; sha256: string; language: string; /** Diff 的 sha256 绑定补丁；另行绑定用于集中验证的当前源文件。 */ sourceSha256?: string }
export interface RuleReceipt { ruleId: string; pass: string; matches: number }
export interface ScanActivity { at: string; phase: 'preflight' | 'inventory' | 'policy' | 'threat_model' | 'discovery' | 'validation' | 'attack_path' | 'reduction' | 'reporting' | 'complete'; message: string }
export interface AuditTask {
  reviewType?:'candidate'|'final_record'
  id: string
  candidateId: string
  phase: 'validation' | 'attack_path'
  focus: string
  status: 'pending' | 'claimed' | 'completed' | 'cancelled'
  claim?: { owner: string; token: string; claimedAt: string; expiresAt: string }
  completedAt?: string
  receipt?: string
}

export interface TargetSnapshot {
  kind: 'git_worktree' | 'git_revision' | 'directory_snapshot' | 'git_diff'
  targetId: string
  displayName: string
  revision?: string
  /** Canonical GitHub owner/repository for a clean immutable source revision. */
  sourceRepository?: string
  baseRevision?: string
  headRevision?: string
  snapshotDigest: string
}

/** The exact Git change-set workflow represented by a diff scan. */
export type DiffScanMode = 'working_tree' | 'commit' | 'branch_diff'

export interface Preflight {
  status: 'ready' | 'warn' | 'blocked'
  checks: Array<{ id: string; status: 'pass' | 'warn' | 'blocked'; detail: string }>
  projectFiles: string[]
  languages: string[]
  suggestedCommands: string[]
}

export type CoverageUnitStatus = 'planned' | 'investigating' | 'reviewed' | 'deferred' | 'blocked' | 'out_of_scope'
export interface CoverageCheck { actorId: string; role: string; question: string; conclusion: string; sourceReferences: ReceiptSourceReference[]; limitations: string[]; at: string }
export interface CoverageUnit {
  id: string; subsystem: string; surface: string; boundary: string; attackClass: string; lifecycle: string
  path: string; startLine: number; endLine: number; anchorLine?: number; anchorColumn?: number; sha256: string; snapshotDigest: string
  status: CoverageUnitStatus; owner?: string; reason: string; checks: CoverageCheck[]
  attempts: Array<{ status: CoverageUnitStatus; owner?: string; reason: string; checks: CoverageCheck[] }>
}
export interface CoverageCriticReceipt { stage?: 'post_wave'|'final_clean'; actorId: string; at: string; ledgerDigest: string; reassignIds: string[]; missingUnits: string[]; rationale: string }
export interface AuditObservation { at: string; actorId: string; role: string; unitIds?:string[]; contextStart?:number;contextEnd?:number;contextSha256?:string; candidateId?:string;artifactRef?:string; kind: 'artifact_context_read'|'unit_context_read'|'ledger_read' | 'source_read' | 'model_assessment' | 'coverage_change' | 'failure'; path?: string; startLine?: number; endLine?: number; sha256?: string; summary: string }
export interface Coverage {
  workflow?: { waves:number; phase:'post_wave'|'repair'|'final_clean'|'completed'; repairJobId?:string; reason?:string }
  inventoryComplete?: boolean
  auditComplete?: boolean
  ledger?: CoverageUnit[]
  critics?: CoverageCriticReceipt[]
  contextReceipts?: FileReceipt[]
  changedLines?: Record<string,number[]>
  /** 不产生源码审阅项的变更：删除、重命名、二进制、排除和因上限未读取的路径。 */
  diffInventory?: {deleted:string[];renamed:Array<{from:string;to:string}>;binary:string[];excluded:string[];omitted:string[]}
  mode: 'repository' | 'scoped_path' | 'diff' | 'commit' | 'branch_diff' | 'working_tree' | 'deep_repository'
  reviewedFiles: number
  skippedFiles: number
  exclusions: string[]
  complete: boolean
  receipts: FileReceipt[]
  ruleReceipts: RuleReceipt[]
  policyFiles: string[]
  surfaces: Array<{ id: string; label: string; disposition: 'reported' | 'no_issue_found' | 'rejected' | 'not_applicable' | 'needs_follow_up'; receiptRefs: string[]; riskArea?: string; notes?: string }>
  deferred: Array<{ id: string; reason: string; paths?: string[] }>
}

export interface ScanRecord {
  /** 威胁模型由扫描器生成而非用户提供，架构审阅可据此补充。 */
  threatModelGenerated?:boolean
  followupOf?:{kind:'candidate_validation';scanId:string;candidateId:string}
  workflowRef?:{kind:'deep';jobId:string}
  blockedCredentialContext?:boolean
  findingIdentityVersion?:number
  finalRecordReviewRequired?:boolean
  parentScanId?:string
  auditDeadlineAt?:string
  auditBudget?: { maxModelTokens?:number }
  auditWorkflow?: { validationJobId?:string; attackPathJobId?:string }
  modelExecutions?: Array<{sessionId:string;actorId:string;role:string;jobId?:string;workerId?:string;at:string;terminalReason?:string;usageComplete?:boolean;toolCalls:number;usage:{inputTokens:number;outputTokens:number;cacheReadTokens:number;cacheWriteTokens:number;calls:number}|null}>
  schemaVersion: 3
  id: string
  mode: 'standard' | 'deep' | 'diff'
  lifecycle: ScanLifecycle
  target: string
  /** 精确 Git revision 的只读证据副本；原工作树仍为 target。 */
  evidenceRoot?: string
  diffArtifact?: {path:string;sha256:string}
  /** 仅在首次显式保存前保留，保存后转为密封 Artifact。 */
  pendingDiffPatch?: string
  ephemeralSnapshot?:boolean
  targetSnapshot: TargetSnapshot
  createdAt: string
  completedAt?: string
  threatModel: string
  policyGuidance: string
  policySnapshots?:import('./policy-context.js').PolicySnapshot[]
  knowledgeBaseSnapshot?:{artifactRef:string;sha256:string;skipped:Array<{path:string;reason:string}>}
  preflight: Preflight
  findings: Finding[]
  coverage: Coverage
  activity: ScanActivity[]
  auditTrail?: AuditObservation[]
  tasks: AuditTask[]
  discoveryStatus?: {driver:'deep'|'llm'|'diff';jobId:string;lifecycle:string;reason?:string}
  recipe: { mode: 'standard' | 'deep' | 'diff'; scopeRequested: boolean; passes: string[]; diffMode?: DiffScanMode; diffBase?: string; diffHead?: string }
  artifacts: { directory: string; manifest?: string; findings?: string; coverage?: string; report?: string }
  /** Derived architecture guidance; absent when no reportable finding survives finalization. */
  hardening?: {
    portfolioPath: string
    structuredPath: string
    outcome: 'structural_hardening_recommended' | 'local_remediation_preferred'
    generatedAt: string
    evidenceDigest: string
  }
  annotations?: { path: string; updatedAt: string }
  seal: string
}
