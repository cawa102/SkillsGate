# チケット 016: JSON Reporter

## 概要
スキャン結果をJSON形式で出力するレポーターを実装する

## ステータス
- [x] 完了

## 依存
- 002: 型定義

## 背景（spec.mdより）
- FR-10: JSON出力でCIに組み込みやすくする
- E. 出力: JSON（機械可読：CI連携用）
- NFR-01: レポート・ログに秘密情報を保存しない（マスキング）

## 成果物

### src/core/reporter/base.ts
レポーターの基底インターフェース

### src/core/reporter/json.ts
JSON形式でレポートを出力

### src/core/reporter/json.test.ts
テスト（13ケース）

## 機能

### 1. JSON生成
```typescript
const reporter = new JsonReporter()
const json = reporter.generate(report)
```

### 2. シークレットマスキング
```typescript
// デフォルトでマスク
const json = reporter.generate(report)
// AKIAIOSFODNN7EXAMPLE → AKI...[MASKED]...789

// マスクなし（内部デバッグ用）
const json = reporter.generate(report, { maskSecrets: false })
```

### 3. 出力先指定
```typescript
// ファイルに出力
await reporter.write(report, { output: '/path/to/report.json' })

// 標準出力
await reporter.write(report)

// 出力なし
await reporter.write(report, { quiet: true })
```

### 4. フォーマットオプション
```typescript
// Pretty print（デフォルト）
reporter.generate(report, { pretty: true })

// コンパクト
reporter.generate(report, { pretty: false })
```

## ScanReport構造

```typescript
interface ScanReport {
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

## 完了条件
- [x] JsonReporter実装
- [x] シークレットマスキング
- [x] Pretty print / Compact出力
- [x] ファイル/標準出力対応
- [x] テスト作成（13ケース）
