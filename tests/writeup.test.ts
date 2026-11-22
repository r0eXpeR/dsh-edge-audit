import assert from 'node:assert/strict'
import test from 'node:test'
import { reportAcceptanceChecklist, WRITEUP_SECTIONS } from '../src/llm/writeup.ts'

test('the seven required headings are in report-format order', () => {
  assert.deepEqual(WRITEUP_SECTIONS.map(section => section.heading), [
    '## Executive Summary', '## Background', '## Vulnerability Details', '## Exploitability Analysis',
    '## Proof of Concept', '## Remediation', '## Summary',
  ])
})

test('the acceptance checklist covers the report-format gates', () => {
  const checklist = reportAcceptanceChecklist()
  assert.ok(checklist.length >= 10)
  assert.ok(checklist.some(item => item.id === 'provenance'))
  assert.ok(checklist.some(item => item.id === 'calibration'))
})
