import type { Confidence } from '../contracts.js'
import { weightedLikelihood,calibrateSeverity, type AttackPathDecision, type ImpactLevel, type LikelihoodLevel, type NetworkScope } from './severity.js'

/**
 * Attack-path analysis engine, adapted from openai/codex-security
 * `skills/attack-path-analysis/references/attack-path-facts.md` and
 * `references/severity-policy.md` (Apache-2.0): the structured facts model,
 * the mechanical final policy pass, and the counterevidence checklist.
 * Pure functions; no I/O.
 */

export type Vector = NetworkScope
export type PreconditionAchievability = 'plausible' | 'unlikely' | 'unachievable' | 'unknown'
export type AttackerInputControl = 'yes' | 'plausible' | 'no' | 'unknown'
export type AuthScope = 'public' | 'internal-only' | 'admin-only' | 'unknown'
export type ImpactSurface = 'build' | 'runtime' | 'data' | 'identity' | 'network' | 'other'
export type TargetReach = 'single service' | 'base image' | 'fleet' | 'unknown'

/** Structured attack-path facts (attack-path-facts.md, adapted). */
export interface AttackPathFacts {
  assumptions: string[]
  context: { selfOnly: boolean; boundaryCrossed: boolean; evidence: string }
  inScope: { inScope: boolean; reasoning: string }
  exposure: { public: boolean; ports?: string[]; ingress?: string; evidence: string }
  identity: { serviceAccount?: string; effectivePrivileges: string }
  crossBoundaryBehavior: { verified: boolean; evidence: string }
  vector: Vector
  preconditions: { what: string[]; achievability: PreconditionAchievability; evidence: string }
  attackerInputControl: AttackerInputControl
  category: string
  mitigationsAlreadyPresent: string[]
  authScope: AuthScope
  impactSurface: ImpactSurface[]
  targetReach: TargetReach
  secretsReferences?: string
  counterevidence: string
  blindspots: string[]
  controls: string[]
  confidence: Confidence
  numberedAttackerSteps: string[]
  impact: ImpactLevel
  likelihood: LikelihoodLevel
  impactRationale: string
  likelihoodRationale: string
  finalPolicyDecision: AttackPathDecision
}

/** The counterevidence checklist (attack-path-analysis skill, adapted). */
export const COUNTEREVIDENCE_CHECKLIST: Array<{ id: string; question: string }> = [
  { id: 'in-scope-status', question: 'How does repository evidence suggest the finding is out of scope per the threat model, and why is that not dispositive?' },
  { id: 'vector', question: 'What conflicting evidence exists about the attack vector, and does it defeat attacker reachability?' },
  { id: 'auth-scope', question: 'What evidence suggests the path is internal-only, admin-only, or not attacker-reachable?' },
  { id: 'exposure', question: 'What evidence contradicts the claimed exposure, and is the surface actually public?' },
  { id: 'cross-boundary', question: 'Is the boundary crossing actually verified, or does evidence show it does not cross a meaningful boundary?' },
  { id: 'preconditions', question: 'What precondition is unrealistic or unachievable, and what evidence supports that?' },
  { id: 'impact-surface', question: 'What evidence limits the impact surface or makes the impact not meaningfully reportable?' },
]

/**
 * Mechanical final policy pass (severity-policy.md, adapted): hard
 * suppressions first, then network-scope likelihood weighting, then the
 * impact x likelihood matrix with critical escalation, then reportability.
 */
export function mechanicalPolicyPass(input: { impact: ImpactLevel; likelihood: LikelihoodLevel; vector: Vector; authScope: AuthScope; preconditions: PreconditionAchievability; attackerInputControl: AttackerInputControl; selfOnly: boolean; privilegedOnly: boolean; operatorOnly: boolean; developerOnly: boolean; physicalAccessOnly: boolean; unreachable: boolean; unrealisticPreconditions: boolean; privilegeDelta?:boolean;privilegeDeltaEvidence?:string;likelihoodOverrideReason?:string; criticalCriteria?: Parameters<typeof calibrateSeverity>[0]['criteria'] }): { severity?: 'critical' | 'high' | 'medium' | 'low' | 'ignore'; decision: AttackPathDecision; priority?: 'P0' | 'P1' | 'P2' | 'P3'; rationale: string } {
  const enums={impact:['high','medium','low','ignore','unknown'],likelihood:['high','medium','low','ignore','unknown'],vector:['remote','local_network','localhost','none','unknown'],authScope:['public','internal-only','admin-only','unknown'],preconditions:['plausible','unlikely','unachievable','unknown'],attackerInputControl:['yes','plausible','no','unknown']}
  for(const [key,values] of Object.entries(enums))if(!values.includes(input[key as keyof typeof enums]))throw new Error(`Invalid or missing attack-path policy fact: ${key}`)
  for(const key of ['selfOnly','privilegedOnly','operatorOnly','developerOnly','physicalAccessOnly','unreachable','unrealisticPreconditions'] as const)if(typeof input[key]!=='boolean')throw new Error(`Invalid or missing attack-path policy flag: ${key}`)
  if(input.privilegeDelta!==undefined&&typeof input.privilegeDelta!=='boolean')throw new Error('Privilege delta requires a boolean evidence fact.')
  if(input.privilegeDelta&&(!input.privilegeDeltaEvidence||input.privilegeDeltaEvidence.trim().length<40))throw new Error('A privilege-escalation exception requires the concrete additional authority and protected resource evidence.')
  if(input.criticalCriteria&&Object.values(input.criticalCriteria).some(v=>typeof v!=='boolean'))throw new Error('Critical criteria require boolean evidence flags.')
  const reasons: string[] = []
  // Hard suppressions from reportability facts.
  if (input.selfOnly) reasons.push('self-only impact is hard-suppressed to ignore')
  if (input.unreachable || input.attackerInputControl === 'no') reasons.push('no attacker-controlled input or unreachable path is hard-suppressed to ignore')
  if (input.unrealisticPreconditions || input.preconditions === 'unachievable') reasons.push('unachievable preconditions are hard-suppressed to ignore')
  if ((input.privilegedOnly || input.operatorOnly || input.developerOnly || input.physicalAccessOnly)&&!input.privilegeDelta) reasons.push('privileged/operator/developer/physical-access-only preconditions are hard-suppressed to ignore')
  if (reasons.length) return { severity: 'ignore', decision: 'ignore', rationale: reasons.join('; ') }
  // 影响、前提、输入控制未知才阻断确认；部署/暴露未知只影响矩阵的 unknown 列。deferred 不改写候选严重度。
  if([input.impact,input.preconditions,input.attackerInputControl].includes('unknown'))return {decision:'deferred',rationale:'Decisive impact, precondition or attacker-control facts remain unknown; independent validation must resolve them. Candidate severity is retained, not lowered.'}
  const ranks={low:1,medium:2,high:3},cap=(value:typeof input.likelihood,maximum:'low'|'medium')=>value==='high'||value==='medium'||value==='low'?(ranks[value]>ranks[maximum]?maximum:value):value
  let likelihood=(input.likelihoodOverrideReason?.trim().length??0)>=40?input.likelihood:weightedLikelihood(input.likelihood,input.vector)
  if(!input.privilegeDelta){if(input.authScope==='admin-only')likelihood=cap(likelihood,'low');else if(input.authScope==='internal-only')likelihood=cap(likelihood,'medium')}
  if(input.preconditions==='unlikely')likelihood=cap(likelihood,'low')
  const calibrated=calibrateSeverity({impact:input.impact,likelihood,scope:'none',criteria:input.criticalCriteria})
  return {severity:calibrated.severity as 'critical'|'high'|'medium'|'low'|'ignore',decision:calibrated.decision,priority:calibrated.priority,rationale:`${calibrated.rationale}; established authScope ${input.authScope}, preconditions ${input.preconditions}${input.privilegeDelta?'; demonstrated privilege delta retained':''}`}

}
