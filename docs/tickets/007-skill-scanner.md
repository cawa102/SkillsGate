# チケット 007: Skill Scanner

## 概要
Claude Code skills (.md) 特有の危険パターンを検出するスキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/skill.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding, Severity } from '../../types/index.js'

interface SkillPattern {
  name: string
  pattern: RegExp
  severity: Severity
  message: string
  category: 'dangerous_command' | 'external_url' | 'permission_request'
}

const SKILL_PATTERNS: SkillPattern[] = [
  // Dangerous commands
  {
    name: 'rm_rf_root',
    pattern: /rm\s+-rf\s+(?:\/|~|\$HOME|\$\{HOME\})/gi,
    severity: 'critical',
    message: 'Destructive rm -rf command targeting root or home directory',
    category: 'dangerous_command'
  },
  {
    name: 'rm_rf_generic',
    pattern: /rm\s+(?:-[rRf]+\s+)+/g,
    severity: 'high',
    message: 'Recursive/force delete command detected',
    category: 'dangerous_command'
  },
  {
    name: 'sudo_usage',
    pattern: /\bsudo\s+/g,
    severity: 'high',
    message: 'sudo usage detected - requires elevated privileges',
    category: 'dangerous_command'
  },
  {
    name: 'chmod_777',
    pattern: /chmod\s+(?:777|a\+rwx)/g,
    severity: 'high',
    message: 'chmod 777 detected - insecure permission change',
    category: 'dangerous_command'
  },
  {
    name: 'curl_bash',
    pattern: /curl\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical',
    message: 'curl | bash pattern detected - arbitrary code execution',
    category: 'dangerous_command'
  },
  {
    name: 'wget_bash',
    pattern: /wget\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical',
    message: 'wget | bash pattern detected - arbitrary code execution',
    category: 'dangerous_command'
  },
  {
    name: 'bash_c',
    pattern: /(?:bash|sh|zsh)\s+-c\s+['"][^'"]+['"]/g,
    severity: 'medium',
    message: 'Shell command execution with -c flag',
    category: 'dangerous_command'
  },
  {
    name: 'dd_command',
    pattern: /\bdd\s+.*(?:if|of)=/g,
    severity: 'high',
    message: 'dd command detected - can overwrite disk data',
    category: 'dangerous_command'
  },
  {
    name: 'mkfs_command',
    pattern: /\bmkfs\./g,
    severity: 'critical',
    message: 'mkfs command detected - filesystem format',
    category: 'dangerous_command'
  },

  // External URL patterns
  {
    name: 'suspicious_download',
    pattern: /(?:curl|wget|fetch)\s+(?:-[a-zA-Z]+\s+)*['"]?https?:\/\/(?!(?:github\.com|githubusercontent\.com|npmjs\.org|pypi\.org))[^\s'"]+/gi,
    severity: 'medium',
    message: 'Download from non-standard source',
    category: 'external_url'
  },
  {
    name: 'short_url',
    pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly)\/[a-zA-Z0-9]+/gi,
    severity: 'high',
    message: 'Shortened URL detected - destination unknown',
    category: 'external_url'
  },
  {
    name: 'ip_address_url',
    pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    severity: 'high',
    message: 'Direct IP address URL detected',
    category: 'external_url'
  },
  {
    name: 'base64_url',
    pattern: /https?:\/\/[a-zA-Z0-9+/]{50,}={0,2}/g,
    severity: 'high',
    message: 'Potentially encoded URL detected',
    category: 'external_url'
  },

  // Permission requests
  {
    name: 'file_access_home',
    pattern: /(?:read|write|access|open)\s+.*(?:~\/|\/home\/|\$HOME)/gi,
    severity: 'medium',
    message: 'Home directory access requested',
    category: 'permission_request'
  },
  {
    name: 'network_permission',
    pattern: /(?:connect|socket|listen|bind)\s+.*(?:port|:)\s*\d+/gi,
    severity: 'medium',
    message: 'Network permission requested',
    category: 'permission_request'
  },
  {
    name: 'env_var_access',
    pattern: /\$(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)/gi,
    severity: 'high',
    message: 'Sensitive environment variable access',
    category: 'permission_request'
  },
  {
    name: 'sensitive_path_access',
    pattern: /(?:\/etc\/(?:passwd|shadow|sudoers)|\/var\/log|\/proc\/)/g,
    severity: 'high',
    message: 'Sensitive system path access',
    category: 'permission_request'
  }
]

export class SkillScanner extends BaseScanner {
  readonly type = 'skill' as const
  readonly name = 'Skill Scanner'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    // Focus on markdown files for skill scanning
    const skillFiles = context.files.filter(f => /\.md$/i.test(f))

    for (const file of skillFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      for (const pattern of SKILL_PATTERNS) {
        let match: RegExpExecArray | null
        pattern.pattern.lastIndex = 0

        while ((match = pattern.pattern.exec(content)) !== null) {
          findings.push({
            scanner: this.type,
            severity: pattern.severity,
            rule: `skill_${pattern.name}`,
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

### 1. Dangerous Commands (危険コマンド)
| パターン | Severity | 説明 |
|----------|----------|------|
| rm_rf_root | critical | rm -rf / または ~ |
| rm_rf_generic | high | rm -rf 汎用 |
| sudo_usage | high | sudo使用 |
| chmod_777 | high | 危険な権限変更 |
| curl_bash | critical | curl \| bash |
| wget_bash | critical | wget \| bash |
| dd_command | high | ddコマンド |
| mkfs_command | critical | mkfsコマンド |

### 2. External URL (外部URL)
| パターン | Severity | 説明 |
|----------|----------|------|
| suspicious_download | medium | 非標準ソースからのダウンロード |
| short_url | high | 短縮URL |
| ip_address_url | high | IPアドレス直接指定 |
| base64_url | high | エンコードされたURL |

### 3. Permission Requests (権限要求)
| パターン | Severity | 説明 |
|----------|----------|------|
| file_access_home | medium | ホームディレクトリアクセス |
| network_permission | medium | ネットワーク権限 |
| env_var_access | high | 機密環境変数アクセス |
| sensitive_path_access | high | 機密パスアクセス |

## 完了条件
- [ ] SkillScanner実装
- [ ] .mdファイルをスキャン対象とする
- [ ] 全パターンで検出できる
- [ ] カテゴリ別に分類される
- [ ] テスト作成（各カテゴリ）
