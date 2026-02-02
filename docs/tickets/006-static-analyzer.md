# チケット 006: Static Analyzer

## 概要
危険なAPI呼び出し、難読化、資格情報探索パターンを検出する静的解析スキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/static.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding, Severity } from '../../types/index.js'

interface StaticPattern {
  name: string
  pattern: RegExp
  severity: Severity
  message: string
  category: 'dangerous_api' | 'obfuscation' | 'credential_access'
}

const STATIC_PATTERNS: StaticPattern[] = [
  // Dangerous API calls
  {
    name: 'eval_usage',
    pattern: /\beval\s*\(/g,
    severity: 'high',
    message: 'eval() usage detected - potential code injection',
    category: 'dangerous_api'
  },
  {
    name: 'exec_usage',
    pattern: /\bexec\s*\(/g,
    severity: 'high',
    message: 'exec() usage detected - command execution',
    category: 'dangerous_api'
  },
  {
    name: 'child_process',
    pattern: /require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]/g,
    severity: 'medium',
    message: 'child_process module usage',
    category: 'dangerous_api'
  },
  {
    name: 'spawn_exec',
    pattern: /\b(?:spawn|execSync|execFileSync|spawnSync)\s*\(/g,
    severity: 'medium',
    message: 'Process spawn/exec detected',
    category: 'dangerous_api'
  },
  {
    name: 'fs_operations',
    pattern: /(?:writeFileSync|appendFileSync|unlinkSync|rmdirSync|rmSync)\s*\(/g,
    severity: 'medium',
    message: 'File system modification detected',
    category: 'dangerous_api'
  },
  {
    name: 'network_fetch',
    pattern: /\b(?:fetch|axios|request|http\.get|https\.get)\s*\(/g,
    severity: 'low',
    message: 'Network request detected',
    category: 'dangerous_api'
  },

  // Obfuscation patterns
  {
    name: 'base64_decode',
    pattern: /(?:atob|Buffer\.from)\s*\([^)]*,\s*['"]base64['"]/g,
    severity: 'medium',
    message: 'Base64 decoding detected - potential obfuscation',
    category: 'obfuscation'
  },
  {
    name: 'char_code_obfuscation',
    pattern: /String\.fromCharCode\s*\([^)]{20,}\)/g,
    severity: 'high',
    message: 'Character code obfuscation detected',
    category: 'obfuscation'
  },
  {
    name: 'hex_string',
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/g,
    severity: 'medium',
    message: 'Hex-encoded string detected',
    category: 'obfuscation'
  },
  {
    name: 'long_one_liner',
    // Line longer than 500 chars with multiple semicolons
    pattern: /^.{500,}$/gm,
    severity: 'low',
    message: 'Suspiciously long line detected',
    category: 'obfuscation'
  },

  // Credential access patterns
  {
    name: 'ssh_access',
    pattern: /~\/\.ssh|\/\.ssh\/|id_rsa|id_ed25519|authorized_keys/g,
    severity: 'critical',
    message: 'SSH credential access pattern detected',
    category: 'credential_access'
  },
  {
    name: 'aws_credentials',
    pattern: /~\/\.aws|\/\.aws\/|aws_access_key|aws_secret/gi,
    severity: 'critical',
    message: 'AWS credential access pattern detected',
    category: 'credential_access'
  },
  {
    name: 'env_file_access',
    pattern: /\.env(?:\.local|\.production|\.development)?['"]?\s*\)/g,
    severity: 'high',
    message: '.env file access detected',
    category: 'credential_access'
  },
  {
    name: 'browser_credentials',
    pattern: /(?:localStorage|sessionStorage|document\.cookie)/g,
    severity: 'medium',
    message: 'Browser credential storage access',
    category: 'credential_access'
  },
  {
    name: 'keychain_access',
    pattern: /(?:keychain|keyring|credential[_-]?store)/gi,
    severity: 'high',
    message: 'System keychain/keyring access pattern',
    category: 'credential_access'
  }
]

export class StaticAnalyzer extends BaseScanner {
  readonly type = 'static' as const
  readonly name = 'Static Analyzer'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    // Only scan code files
    const codeFiles = context.files.filter(f =>
      /\.(js|ts|jsx|tsx|py|rb|sh|bash|go|rs)$/.test(f)
    )

    for (const file of codeFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      for (const pattern of STATIC_PATTERNS) {
        let match: RegExpExecArray | null
        pattern.pattern.lastIndex = 0

        while ((match = pattern.pattern.exec(content)) !== null) {
          findings.push({
            scanner: this.type,
            severity: pattern.severity,
            rule: `static_${pattern.name}`,
            message: pattern.message,
            location: {
              file: file.replace(context.rootPath + '/', ''),
              line: this.getLineNumber(content, match.index)
            },
            evidence: match[0].slice(0, 100),
            metadata: { category: pattern.category }
          })
        }
      }
    }

    return findings
  }

  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length
  }
}
```

## 検出カテゴリ

### 1. Dangerous API (危険なAPI)
- `eval()` 使用
- `exec()` / `spawn()` 使用
- `child_process` モジュール
- ファイルシステム操作
- ネットワークリクエスト

### 2. Obfuscation (難読化)
- Base64デコード
- 文字コード難読化
- 16進数文字列
- 異常に長い1行

### 3. Credential Access (資格情報アクセス)
- SSH鍵アクセス
- AWS認証情報
- .envファイル
- ブラウザストレージ
- システムキーチェーン

## 完了条件
- [ ] StaticAnalyzer実装
- [ ] 全パターンで検出できる
- [ ] カテゴリ別に分類される
- [ ] コードファイルのみスキャン
- [ ] テスト作成（各カテゴリ）
