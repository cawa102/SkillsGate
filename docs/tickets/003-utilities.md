# チケット 003: ユーティリティ関数

## 概要
プロジェクト全体で使用するユーティリティ関数を作成する

## ステータス
- [x] 完了

## 依存
- 001: プロジェクト初期化

## 成果物

### 1. src/utils/hash.ts
ハッシュ計算ユーティリティ

```typescript
import { createHash } from 'crypto'
import { readFile, readdir } from 'fs/promises'
import { join } from 'path'

// SHA-256 hash of string
export function hashString(content: string): string

// SHA-256 hash of file
export async function hashFile(filePath: string): Promise<string>

// SHA-256 hash of directory (deterministic)
export async function hashDirectory(dirPath: string): Promise<string>

// Check if path is directory
export async function isDirectory(path: string): Promise<boolean>

// Check if path is file
export async function isFile(path: string): Promise<boolean>
```

### 2. src/utils/mask.ts
秘密情報マスキング

```typescript
// Mask secret value (show prefix/suffix only)
export function maskSecret(value: string, options?: {
  prefixLength?: number
  suffixLength?: number
  maskChar?: string
}): string

// Mask all secrets in text
export function maskSecrets(text: string, patterns: RegExp[]): string

// Common secret patterns
export const SECRET_PATTERNS: RegExp[]

// Mask evidence for reports
export function maskEvidence(evidence: string): string

// Mask file path (hide username)
export function maskPath(path: string): string
```

### 3. src/utils/logger.ts
ロガー

```typescript
export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

// Configure logger
export function configureLogger(options: {
  level?: LogLevel
  quiet?: boolean
}): void

// Log methods
export function debug(message: string, ...args: unknown[]): void
export function info(message: string, ...args: unknown[]): void
export function warn(message: string, ...args: unknown[]): void
export function error(message: string, ...args: unknown[]): void
export function success(message: string): void

// Log finding with color
export function finding(severity: string, message: string, location: string): void

// Progress spinner
export function progress(message: string): { stop: (msg?: string) => void }
```

### 4. src/utils/index.ts
エクスポート

## 完了条件
- [x] hash.ts作成
- [x] mask.ts作成
- [x] logger.ts作成
- [x] index.ts作成
- [x] マスキングが正しく動作する
- [x] ハッシュが決定的である
