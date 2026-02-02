# チケット 015: Enforcer

## 概要
ポリシー評価結果に基づき、最終判定（allow/block/quarantine）を返すEnforcerを実装する

## ステータス
- [ ] 未着手

## 依存
- 013: ポリシーエンジン

## 背景（spec.mdより）
- FR-09: CLIで `allow / block / quarantine` を返す（exit code含む）
- 想定アーキテクチャ: Enforcer は allow/block/quarantine を返す（必要に応じて隔離環境を起動）

## 成果物

### src/core/enforcer/index.ts

```typescript
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
```

## Exit Codes

| Decision | Exit Code | 説明 |
|----------|-----------|------|
| allow | 0 | 安全、インストール許可 |
| block | 1 | 危険、インストール拒否 |
| quarantine | 2 | 警告、隔離実行を推奨 |
| error | 3 | スキャン失敗 |

## 使用例

```typescript
import { PolicyLoader, createEnforcer } from './core/index.js'

// Load policy
const loader = new PolicyLoader()
const policy = await loader.loadDefault()

// Create enforcer
const enforcer = createEnforcer(policy)

// Enforce on findings
const result = enforcer.enforce(findings)

console.log(`Decision: ${result.decision}`)
console.log(`Summary: ${result.summary}`)
console.log(`Exit code: ${result.exitCode}`)

// For CLI
process.exit(result.exitCode)
```

## EnforcementResult

| フィールド | 型 | 説明 |
|------------|------|------|
| decision | Decision | allow/block/quarantine |
| exitCode | number | CLI用終了コード |
| evaluation | EvaluationResult | ポリシー評価結果 |
| summary | string | 人間可読なサマリー |
| reasons | string[] | 判定理由リスト |
| policyName | string | 適用されたポリシー名 |
| timestamp | string | ISO 8601形式のタイムスタンプ |

## 完了条件
- [ ] Enforcer実装
- [ ] Exit codes定義
- [ ] 判定理由生成
- [ ] サマリー生成
- [ ] テスト作成
