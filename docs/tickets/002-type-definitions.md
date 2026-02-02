# チケット 002: 型定義

## 概要
プロジェクト全体で使用するTypeScript型定義を作成する

## ステータス
- [x] 完了

## 依存
- 001: プロジェクト初期化

## 成果物

### 1. src/types/finding.ts
検出結果の型定義

```typescript
// Severity levels
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// Scanner types
export type ScannerType =
  | 'secret'
  | 'dependency'
  | 'static'
  | 'entrypoint'
  | 'ci-risk'
  | 'skill'

// Finding location
export interface FindingLocation {
  file: string
  line?: number
  column?: number
}

// Single finding
export interface Finding {
  scanner: ScannerType
  severity: Severity
  rule: string
  message: string
  location: FindingLocation
  evidence?: string
  metadata?: Record<string, unknown>
}

// Summary
export interface FindingSummary {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

// Scanner result
export interface ScannerResult {
  scanner: ScannerType
  findings: Finding[]
  duration: number
  error?: string
}
```

### 2. src/types/policy.ts
ポリシーの型定義（zodスキーマ含む）

```typescript
import { z } from 'zod'

export const ThresholdsSchema = z.object({
  block: z.number().min(0).max(100).default(40),
  warn: z.number().min(0).max(100).default(70)
})

export const RuleDefinitionSchema = z.object({
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  weight: z.number(),
  message: z.string(),
  enabled: z.boolean().default(true)
})

export const ExceptionSchema = z.object({
  pattern: z.string(),
  ignore: z.array(z.string())
})

export const PolicySchema = z.object({
  version: z.string(),
  name: z.string(),
  description: z.string().optional(),
  thresholds: ThresholdsSchema,
  critical_block: z.array(z.string()).default([]),
  rules: z.record(z.string(), RuleDefinitionSchema),
  exceptions: z.array(ExceptionSchema).default([])
})

export type Policy = z.infer<typeof PolicySchema>
```

### 3. src/types/report.ts
レポートの型定義

```typescript
export type Decision = 'allow' | 'block' | 'quarantine'
export type SourceType = 'git' | 'local' | 'archive'

export interface SourceInfo {
  type: SourceType
  path: string
  url?: string
  commit?: string
  hash: string
}

export interface ScanReport {
  version: string
  timestamp: string
  source: SourceInfo
  decision: Decision
  score: number
  findings: Finding[]
  summary: FindingSummary
  criticalBlockRules: string[]
  duration: number
  policyName: string
  errors: string[]
}
```

### 4. src/types/index.ts
エクスポート

```typescript
export * from './finding.js'
export * from './policy.js'
export * from './report.js'
```

## 完了条件
- [x] finding.ts作成
- [x] policy.ts作成
- [x] report.ts作成
- [x] index.ts作成
- [x] 型エラーなくビルドできる
