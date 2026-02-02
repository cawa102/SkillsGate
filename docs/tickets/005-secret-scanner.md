# チケット 005: Secret Scanner

## 概要
秘密情報（APIキー、トークン、パスワード等）を検出するスキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/secret.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding } from '../../types/index.js'
import { maskEvidence } from '../../utils/mask.js'

interface SecretPattern {
  name: string
  pattern: RegExp
  severity: 'critical' | 'high' | 'medium'
  message: string
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    message: 'AWS Access Key detected'
  },
  {
    name: 'aws_secret_key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    message: 'Potential AWS Secret Key detected'
  },

  // GitHub
  {
    name: 'github_token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub Personal Access Token detected'
  },
  {
    name: 'github_oauth',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub OAuth Token detected'
  },

  // OpenAI
  {
    name: 'openai_key',
    pattern: /sk-[a-zA-Z0-9]{48}/g,
    severity: 'critical',
    message: 'OpenAI API Key detected'
  },

  // Anthropic
  {
    name: 'anthropic_key',
    pattern: /sk-ant-[a-zA-Z0-9-]{95}/g,
    severity: 'critical',
    message: 'Anthropic API Key detected'
  },

  // Generic patterns
  {
    name: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    message: 'Private key detected'
  },
  {
    name: 'password_in_url',
    pattern: /[a-zA-Z]+:\/\/[^:]+:[^@]+@/g,
    severity: 'high',
    message: 'Password in URL detected'
  },
  {
    name: 'generic_api_key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'high',
    message: 'Generic API key pattern detected'
  },
  {
    name: 'jwt_token',
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: 'high',
    message: 'JWT token detected'
  }
]

export class SecretScanner extends BaseScanner {
  readonly type = 'secret' as const
  readonly name = 'Secret Scanner'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    for (const file of context.files) {
      const content = await readFileContent(file)
      if (!content) continue

      const lines = content.split('\n')

      for (const pattern of SECRET_PATTERNS) {
        let match: RegExpExecArray | null
        pattern.pattern.lastIndex = 0

        while ((match = pattern.pattern.exec(content)) !== null) {
          const lineNumber = this.getLineNumber(content, match.index)

          findings.push({
            scanner: this.type,
            severity: pattern.severity,
            rule: `secret_${pattern.name}`,
            message: pattern.message,
            location: {
              file: file.replace(context.rootPath + '/', ''),
              line: lineNumber
            },
            evidence: maskEvidence(match[0])
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

## 検出パターン一覧

| パターン名 | Severity | 説明 |
|-----------|----------|------|
| aws_access_key | critical | AWS Access Key ID |
| aws_secret_key | critical | AWS Secret Access Key |
| github_token | critical | GitHub PAT |
| github_oauth | critical | GitHub OAuth Token |
| openai_key | critical | OpenAI API Key |
| anthropic_key | critical | Anthropic API Key |
| private_key | critical | SSH/RSA Private Key |
| password_in_url | high | URL内のパスワード |
| generic_api_key | high | 汎用APIキーパターン |
| jwt_token | high | JWT Token |

## 完了条件
- [ ] SecretScanner実装
- [ ] 全パターンで検出できる
- [ ] 検出値がマスキングされる
- [ ] 行番号が正確
- [ ] テスト作成（各パターン）
