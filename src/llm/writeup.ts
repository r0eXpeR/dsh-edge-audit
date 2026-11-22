/**
 * Vulnerability report format engine, adapted from openai/codex-security
 * `skills/vulnerability-writeup/references/report-format.md` and the
 * single-finding drafting prompt (Apache-2.0): the seven required headings,
 * section-order validation, the drafting prompt template, and the report
 * acceptance checklist. Pure functions; no I/O.
 */

/** The seven required report headings in order (report-format.md). */
export const WRITEUP_SECTIONS: ReadonlyArray<{ heading: string; purpose: string }> = [
  { heading: '## Executive Summary', purpose: 'Component, assessed software version, attacker position, required configuration, vulnerable operation, narrowest demonstrated impact; verified first affected release and fixed release when established.' },
  { heading: '## Background', purpose: 'Only the component behavior, named actors, controlled values, ownership, permission boundaries, and expected security behavior needed to understand the report.' },
  { heading: '## Vulnerability Details', purpose: 'The claimed trigger sequence in causal order: Mallory\'s actual controlled input, each material check/state change, and the source lines where the expected behavior is not enforced.' },
  { heading: '## Exploitability Analysis', purpose: 'The narrow primitive the evidence actually establishes, which account/privilege/tenant/process boundary it crosses under the verified preconditions, and qualified stronger routes.' },
  { heading: '## Proof of Concept', purpose: 'Real PoC artifacts, target requirements, build steps, execution safety, and the expected state; observed output only when observed.' },
  { heading: '## Remediation', purpose: 'Plain-English statement of what the fixed code must do differently, with suggested regression coverage.' },
  { heading: '## Summary', purpose: 'Restatement of verified preconditions, the actual security failure, affected versions, and demonstrated impact without escalation.' },
]


/** The report acceptance checklist (report-format.md acceptance, adapted). */
export function reportAcceptanceChecklist(): Array<{ id: string; check: string }> {
  return [
    { id: 'audience', check: 'A new reader can understand the component, named actors, and relevant security boundary.' },
    { id: 'scope', check: 'Verified release, configuration, attacker preconditions, and affected-version history are accurately bounded.' },
    { id: 'trigger', check: 'Source establishes the same trigger sequence and security failure described (or report-only with every source-dependent claim conditional).' },
    { id: 'excerpts', check: 'Every excerpt is exact, attributed to a repository-relative path and verified software version, necessary, and explained.' },
    { id: 'evidence', check: 'Source proof, inference, reported claims, and runtime observation are distinguishable.' },
    { id: 'controls', check: 'Meaningful guards, negative controls, and alternative explanations are handled.' },
    { id: 'calibration', check: 'Impact, exploit reliability, affected versions, and deployment prevalence are no stronger than the evidence.' },
    { id: 'poc', check: 'PoC, commands, output, and cleanup reflect real artifacts and actual verification; unobserved results are labeled expected.' },
    { id: 'remediation', check: 'Remediation explains in plain English what the code must do differently and suggests regression coverage.' },
    { id: 'voice', check: 'The narrative reads like a careful human researcher, not a scanner, marketing copy, or a checklist.' },
    { id: 'provenance', check: 'No author-machine-specific absolute paths, placeholder text, or fabricated details remain in the report or distributable PoC.' },
  ]
}
