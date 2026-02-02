# チケット 004: スキャナ基盤

## 概要
全スキャナが継承する基底クラスとスキャナ統合モジュールを作成する

## ステータス
- [ ] 未着手

## 依存
- 002: 型定義
- 003: ユーティリティ関数

## 成果物

### 1. src/core/scanner/base.ts
スキャナ基底クラス

```typescript
import type { Finding, ScannerResult, ScannerType } from '../../types/index.js'

export interface ScanContext {
  rootPath: string
  files: string[]
  policy?: Policy
}

export abstract class BaseScanner {
  abstract readonly type: ScannerType
  abstract readonly name: string

  abstract scan(context: ScanContext): Promise<Finding[]>

  async execute(context: ScanContext): Promise<ScannerResult> {
    const start = Date.now()
    try {
      const findings = await this.scan(context)
      return {
        scanner: this.type,
        findings,
        duration: Date.now() - start
      }
    } catch (error) {
      return {
        scanner: this.type,
        findings: [],
        duration: Date.now() - start,
        error: error instanceof Error ? error.message : String(error)
      }
    }
  }
}
```

### 2. src/core/scanner/index.ts
スキャナ統合モジュール

```typescript
import type { ScanContext, ScannerResult } from './base.js'
import { SecretScanner } from './secret.js'
import { StaticAnalyzer } from './static.js'
import { SkillScanner } from './skill.js'
import { EntrypointDetector } from './entrypoint.js'
import { DependencyScanner } from './dependency.js'
import { CIRiskAnalyzer } from './ci-risk.js'

export class ScannerOrchestrator {
  private scanners = [
    new SecretScanner(),
    new StaticAnalyzer(),
    new SkillScanner(),
    new EntrypointDetector(),
    new DependencyScanner(),
    new CIRiskAnalyzer()
  ]

  async scan(context: ScanContext): Promise<ScannerResult[]> {
    // Run all scanners in parallel
    return Promise.all(
      this.scanners.map(scanner => scanner.execute(context))
    )
  }
}
```

### 3. src/core/scanner/utils.ts
スキャナ共通ユーティリティ

```typescript
import { readFile, readdir, stat } from 'fs/promises'
import { join, extname } from 'path'

// Get all files recursively
export async function getFiles(
  dirPath: string,
  options?: { extensions?: string[], exclude?: string[] }
): Promise<string[]>

// Read file content safely
export async function readFileContent(filePath: string): Promise<string | null>

// Check if file matches pattern
export function matchesPattern(filePath: string, pattern: string): boolean

// Get file extension
export function getExtension(filePath: string): string
```

## 完了条件
- [ ] BaseScanner抽象クラス作成
- [ ] ScanContext型定義
- [ ] ScannerOrchestrator作成
- [ ] 共通ユーティリティ作成
- [ ] 全スキャナが並列実行される
