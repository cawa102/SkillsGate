# チケット 011: ポリシースキーマ

## 概要
ポリシーファイルのZodスキーマ定義を作成する（002で基本定義済み、詳細化）

## ステータス
- [ ] 未着手

## 依存
- 002: 型定義

## 成果物

### src/core/policy/schema.ts

```typescript
import { z } from 'zod'

/**
 * Severity levels
 */
export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info'])
export type Severity = z.infer<typeof SeveritySchema>

/**
 * Threshold configuration
 */
export const ThresholdsSchema = z.object({
  block: z.number()
    .min(0, 'Block threshold must be >= 0')
    .max(100, 'Block threshold must be <= 100')
    .default(40)
    .describe('Score at or below which to block'),
  warn: z.number()
    .min(0, 'Warn threshold must be >= 0')
    .max(100, 'Warn threshold must be <= 100')
    .default(70)
    .describe('Score at or below which to warn')
}).refine(
  data => data.block <= data.warn,
  { message: 'Block threshold must be <= warn threshold' }
)

export type Thresholds = z.infer<typeof ThresholdsSchema>

/**
 * Rule definition
 */
export const RuleDefinitionSchema = z.object({
  severity: SeveritySchema,
  weight: z.number()
    .describe('Score adjustment when rule triggers (negative = deduction)'),
  message: z.string()
    .min(1, 'Message is required')
    .describe('Human-readable description of the rule'),
  enabled: z.boolean()
    .default(true)
    .describe('Whether this rule is active')
})

export type RuleDefinition = z.infer<typeof RuleDefinitionSchema>

/**
 * Exception pattern
 */
export const ExceptionSchema = z.object({
  pattern: z.string()
    .min(1, 'Pattern is required')
    .describe('Glob pattern to match files'),
  ignore: z.array(z.string())
    .min(1, 'At least one rule to ignore is required')
    .describe('Rule IDs to ignore for matched files'),
  reason: z.string()
    .optional()
    .describe('Explanation for this exception')
})

export type Exception = z.infer<typeof ExceptionSchema>

/**
 * Complete policy schema
 */
export const PolicySchema = z.object({
  version: z.string()
    .regex(/^\d+\.\d+(?:\.\d+)?$/, 'Version must be semver format')
    .describe('Policy version in semver format'),

  name: z.string()
    .min(1, 'Policy name is required')
    .max(50, 'Policy name too long')
    .describe('Unique identifier for this policy'),

  description: z.string()
    .optional()
    .describe('Human-readable description of policy purpose'),

  extends: z.string()
    .optional()
    .describe('Base policy to extend'),

  thresholds: ThresholdsSchema,

  critical_block: z.array(z.string())
    .default([])
    .describe('Rules that cause immediate block regardless of score'),

  rules: z.record(z.string(), RuleDefinitionSchema)
    .describe('Rule definitions keyed by rule ID'),

  exceptions: z.array(ExceptionSchema)
    .default([])
    .describe('File-specific rule exceptions')
})

export type Policy = z.infer<typeof PolicySchema>

/**
 * Validate policy content
 */
export function validatePolicy(data: unknown): Policy {
  return PolicySchema.parse(data)
}

/**
 * Validate policy with detailed errors
 */
export function validatePolicySafe(data: unknown): {
  success: boolean
  data?: Policy
  errors?: z.ZodError
} {
  const result = PolicySchema.safeParse(data)
  if (result.success) {
    return { success: true, data: result.data }
  }
  return { success: false, errors: result.error }
}

/**
 * Format validation errors for display
 */
export function formatValidationErrors(errors: z.ZodError): string[] {
  return errors.errors.map(err => {
    const path = err.path.join('.')
    return `${path}: ${err.message}`
  })
}
```

## スキーマ詳細

### Policy

| フィールド | 型 | 必須 | 説明 |
|------------|------|------|------|
| version | string | ✓ | semverフォーマット |
| name | string | ✓ | ポリシー識別子 |
| description | string | | 説明 |
| extends | string | | 継承元ポリシー |
| thresholds | Thresholds | ✓ | 閾値設定 |
| critical_block | string[] | | 即時ブロックルール |
| rules | Record<string, Rule> | ✓ | ルール定義 |
| exceptions | Exception[] | | 例外設定 |

### Thresholds

| フィールド | 型 | デフォルト | 説明 |
|------------|------|------------|------|
| block | number | 40 | この値以下でblock |
| warn | number | 70 | この値以下でwarn |

### RuleDefinition

| フィールド | 型 | 必須 | 説明 |
|------------|------|------|------|
| severity | Severity | ✓ | 重大度 |
| weight | number | ✓ | スコア調整値 |
| message | string | ✓ | 説明メッセージ |
| enabled | boolean | | 有効/無効 |

### Exception

| フィールド | 型 | 必須 | 説明 |
|------------|------|------|------|
| pattern | string | ✓ | globパターン |
| ignore | string[] | ✓ | 無視するルール |
| reason | string | | 理由 |

## 完了条件
- [ ] スキーマ定義完成
- [ ] バリデーション関数
- [ ] エラーメッセージのフォーマット
- [ ] テスト作成
