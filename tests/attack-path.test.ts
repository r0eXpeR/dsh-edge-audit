import assert from 'node:assert/strict'
import test from 'node:test'
import { COUNTEREVIDENCE_CHECKLIST, mechanicalPolicyPass, renderAttackPathFacts, type AttackPathFacts } from '../src/llm/attack-path.ts'

test('the mechanical policy pass hard-suppresses privileged-only and self-only paths', () => {
  const suppressed = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: true, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(suppressed.decision, 'ignore')
  const privileged = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: true, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(privileged.decision, 'ignore')
})

test('the mechanical policy pass keeps source-evidenced likelihood for remote exposure', () => {
  const result = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(result.severity, 'high')
  assert.equal(result.priority, 'P1')
})

test('the mechanical policy pass escalates to critical only with critical criteria', () => {
  const critical = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false, criticalCriteria: { codeExecution: true } })
  assert.equal(critical.severity, 'critical')
  assert.equal(critical.priority, 'P0')
  const noCriteria = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'yes', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(noCriteria.severity, 'high')
})

test('no attacker-controlled input is hard-suppressed', () => {
  const result = mechanicalPolicyPass({ impact: 'high', likelihood: 'high', vector: 'remote', authScope: 'public', preconditions: 'plausible', attackerInputControl: 'no', selfOnly: false, privilegedOnly: false, operatorOnly: false, developerOnly: false, physicalAccessOnly: false, unreachable: false, unrealisticPreconditions: false })
  assert.equal(result.decision, 'ignore')
})

test('the counterevidence checklist has the seven dimensions', () => {
  assert.equal(COUNTEREVIDENCE_CHECKLIST.length, 7)
  assert.deepEqual(COUNTEREVIDENCE_CHECKLIST.map(item => item.id), ['in-scope-status', 'vector', 'auth-scope', 'exposure', 'cross-boundary', 'preconditions', 'impact-surface'])
})

