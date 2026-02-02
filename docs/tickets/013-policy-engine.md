# チケット 013: ポリシーエンジン

## 概要
検出結果をポリシーに基づいて評価し、スコアを算出するエンジンを実装する

## ステータス
- [ ] 未着手

## 依存
- 012: ポリシーローダー

## 成果物

### src/core/policy/engine.ts

```typescript
import { minimatch } from 'minimatch'
import type { Finding, Severity } from '../../types/index.js'
import type { Policy, RuleDefinition } from './schema.js'

/**
 * Result of policy evaluation
 */
export interface EvaluationResult {
  /** Calculated score (0-100, starting from 100) */
  score: number

  /** Rules that triggered during evaluation */
  triggeredRules: TriggeredRule[]

  /** Whether any critical_block rule was triggered */
  hasCriticalBlock: boolean

  /** List of critical_block rules that triggered */
  criticalBlockRules: string[]

  /** Findings that were suppressed by exceptions */
  suppressedFindings: Finding[]
}

export interface TriggeredRule {
  rule: string
  severity: Severity
  weight: number
  message: string
  count: number
  findings: Finding[]
}

export class PolicyEngine {
  constructor(private policy: Policy) {}

  /**
   * Evaluate findings against the policy
   */
  evaluate(findings: Finding[]): EvaluationResult {
    // Start with perfect score
    let score = 100
    const triggeredMap = new Map<string, TriggeredRule>()
    const criticalBlockRules: string[] = []
    const suppressedFindings: Finding[] = []

    // Process each finding
    for (const finding of findings) {
      // Check if finding should be suppressed by exception
      if (this.isSuppressed(finding)) {
        suppressedFindings.push(finding)
        continue
      }

      // Get rule definition
      const ruleId = finding.rule
      const ruleDef = this.policy.rules[ruleId]

      // If no rule definition, use default based on severity
      const effectiveRule = ruleDef || this.getDefaultRule(finding.severity)

      // Skip if rule is disabled
      if (ruleDef && !ruleDef.enabled) {
        continue
      }

      // Check for critical block
      if (this.policy.critical_block.includes(ruleId)) {
        if (!criticalBlockRules.includes(ruleId)) {
          criticalBlockRules.push(ruleId)
        }
      }

      // Update triggered rules
      const existing = triggeredMap.get(ruleId)
      if (existing) {
        existing.count++
        existing.findings.push(finding)
      } else {
        triggeredMap.set(ruleId, {
          rule: ruleId,
          severity: effectiveRule.severity,
          weight: effectiveRule.weight,
          message: effectiveRule.message,
          count: 1,
          findings: [finding]
        })
      }

      // Apply weight to score (only once per unique rule)
      if (!existing) {
        score += effectiveRule.weight
      }
    }

    // Clamp score to 0-100
    score = Math.max(0, Math.min(100, score))

    return {
      score,
      triggeredRules: Array.from(triggeredMap.values()),
      hasCriticalBlock: criticalBlockRules.length > 0,
      criticalBlockRules,
      suppressedFindings
    }
  }

  /**
   * Check if a finding should be suppressed
   */
  private isSuppressed(finding: Finding): boolean {
    for (const exception of this.policy.exceptions) {
      // Check if file matches pattern
      if (minimatch(finding.location.file, exception.pattern)) {
        // Check if rule should be ignored
        if (exception.ignore.includes(finding.rule)) {
          return true
        }
      }
    }
    return false
  }

  /**
   * Get default rule definition based on severity
   */
  private getDefaultRule(severity: Severity): RuleDefinition {
    const defaultWeights: Record<Severity, number> = {
      critical: -50,
      high: -20,
      medium: -10,
      low: -5,
      info: 0
    }

    return {
      severity,
      weight: defaultWeights[severity],
      message: `${severity} severity finding`,
      enabled: true
    }
  }

  /**
   * Determine decision based on evaluation result
   */
  getDecision(result: EvaluationResult): 'allow' | 'block' | 'quarantine' {
    // Critical block takes precedence
    if (result.hasCriticalBlock) {
      return 'block'
    }

    // Check thresholds
    if (result.score <= this.policy.thresholds.block) {
      return 'block'
    }

    if (result.score <= this.policy.thresholds.warn) {
      return 'quarantine'
    }

    return 'allow'
  }

  /**
   * Get policy name
   */
  get name(): string {
    return this.policy.name
  }

  /**
   * Get policy thresholds
   */
  get thresholds() {
    return this.policy.thresholds
  }
}

/**
 * Create policy engine from policy
 */
export function createPolicyEngine(policy: Policy): PolicyEngine {
  return new PolicyEngine(policy)
}
```

### src/core/policy/index.ts

```typescript
export * from './schema.js'
export * from './loader.js'
export * from './engine.js'
```

## 評価ロジック

### 1. スコア計算
- 初期スコア: 100
- 各ルールの重み（weight）を加算
- 同じルールは一度だけカウント（重複発火しない）
- 最終スコアは 0-100 にクランプ

### 2. Critical Block
- `critical_block` に含まれるルールが発火 → 即座にblock
- スコアに関係なくブロック

### 3. 閾値判定
```
score <= block → block
score <= warn → quarantine
score > warn → allow
```

### 4. 例外処理
- `exceptions` でファイルパターンとルールを指定
- マッチした finding は評価から除外
- 除外された finding は `suppressedFindings` に記録

## 使用例

```typescript
import { PolicyLoader, PolicyEngine } from './policy/index.js'

// Load policy
const loader = new PolicyLoader()
const policy = await loader.loadDefault()

// Create engine
const engine = new PolicyEngine(policy)

// Evaluate findings
const result = engine.evaluate(findings)

// Get decision
const decision = engine.getDecision(result)

console.log(`Score: ${result.score}`)
console.log(`Decision: ${decision}`)
console.log(`Triggered rules: ${result.triggeredRules.length}`)
```

## 完了条件
- [ ] PolicyEngine実装
- [ ] スコア計算ロジック
- [ ] Critical block処理
- [ ] 例外処理
- [ ] 決定判定
- [ ] index.tsでエクスポート
- [ ] テスト作成
