import type { Finding } from '../../types/index.js'
import type { Policy } from '../policy/schema.js'
import { PolicyEngine, EvaluationResult } from '../policy/engine.js'

/**
 * Enforcement decision
 */
export type Decision = 'allow' | 'block' | 'quarantine'

/**
 * Exit codes for CLI
 */
export const ExitCodes: Record<Decision | 'error', number> = {
  allow: 0,
  block: 1,
  quarantine: 2,
  error: 3
} as const

/**
 * Result of enforcement
 */
export interface EnforcementResult {
  /** Final decision */
  decision: Decision

  /** Exit code for CLI */
  exitCode: number

  /** Evaluation result from policy engine */
  evaluation: EvaluationResult

  /** Human-readable summary */
  summary: string

  /** Reasons for the decision */
  reasons: string[]

  /** Policy that was applied */
  policyName: string

  /** Timestamp of enforcement */
  timestamp: string
}

export class Enforcer {
  private engine: PolicyEngine

  constructor(policy: Policy) {
    this.engine = new PolicyEngine(policy)
  }

  /**
   * Enforce policy on findings
   */
  enforce(findings: Finding[]): EnforcementResult {
    const evaluation = this.engine.evaluate(findings)
    const decision = this.engine.getDecision(evaluation)
    const reasons = this.buildReasons(evaluation, decision)
    const summary = this.buildSummary(evaluation, decision)

    return {
      decision,
      exitCode: ExitCodes[decision],
      evaluation,
      summary,
      reasons,
      policyName: this.engine.name,
      timestamp: new Date().toISOString()
    }
  }

  /**
   * Build human-readable reasons for the decision
   */
  private buildReasons(evaluation: EvaluationResult, decision: Decision): string[] {
    const reasons: string[] = []

    if (evaluation.hasCriticalBlock) {
      reasons.push(
        `Critical block rules triggered: ${evaluation.criticalBlockRules.join(', ')}`
      )
    }

    if (decision === 'block' && !evaluation.hasCriticalBlock) {
      reasons.push(
        `Score ${evaluation.score} is at or below block threshold ${this.engine.thresholds.block}`
      )
    }

    if (decision === 'quarantine') {
      reasons.push(
        `Score ${evaluation.score} is at or below warn threshold ${this.engine.thresholds.warn}`
      )
    }

    for (const rule of evaluation.triggeredRules) {
      reasons.push(
        `${rule.severity.toUpperCase()}: ${rule.message} (${rule.count} occurrence${rule.count > 1 ? 's' : ''})`
      )
    }

    if (evaluation.suppressedFindings.length > 0) {
      reasons.push(
        `${evaluation.suppressedFindings.length} finding(s) suppressed by exceptions`
      )
    }

    return reasons
  }

  /**
   * Build summary message
   */
  private buildSummary(evaluation: EvaluationResult, decision: Decision): string {
    const decisionText = {
      allow: 'ALLOWED',
      block: 'BLOCKED',
      quarantine: 'QUARANTINED'
    }[decision]

    const ruleCount = evaluation.triggeredRules.length
    const findingCount = evaluation.triggeredRules.reduce(
      (sum, r) => sum + r.count,
      0
    )

    if (decision === 'allow' && ruleCount === 0) {
      return `${decisionText}: No security issues detected. Score: ${evaluation.score}/100`
    }

    return `${decisionText}: ${findingCount} finding(s) from ${ruleCount} rule(s). Score: ${evaluation.score}/100`
  }

  /**
   * Get policy name
   */
  get policyName(): string {
    return this.engine.name
  }

  /**
   * Get policy thresholds
   */
  get thresholds() {
    return this.engine.thresholds
  }
}

/**
 * Create enforcer from policy
 */
export function createEnforcer(policy: Policy): Enforcer {
  return new Enforcer(policy)
}
