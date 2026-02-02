# チケット 008: Entrypoint Detector

## 概要
インストール時に自動実行されるエントリーポイントを検出するスキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/entrypoint.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding } from '../../types/index.js'
import { readFileContent } from './utils.js'

interface EntrypointPattern {
  file: string | RegExp
  patterns: Array<{
    name: string
    pattern: RegExp
    severity: 'critical' | 'high' | 'medium'
    message: string
  }>
}

const ENTRYPOINT_CONFIGS: EntrypointPattern[] = [
  // package.json scripts
  {
    file: 'package.json',
    patterns: [
      {
        name: 'npm_postinstall',
        pattern: /"postinstall"\s*:\s*"([^"]+)"/,
        severity: 'high',
        message: 'npm postinstall script detected - runs automatically after install'
      },
      {
        name: 'npm_preinstall',
        pattern: /"preinstall"\s*:\s*"([^"]+)"/,
        severity: 'high',
        message: 'npm preinstall script detected - runs before install'
      },
      {
        name: 'npm_prepare',
        pattern: /"prepare"\s*:\s*"([^"]+)"/,
        severity: 'medium',
        message: 'npm prepare script detected'
      },
      {
        name: 'npm_prepublish',
        pattern: /"prepublish"\s*:\s*"([^"]+)"/,
        severity: 'medium',
        message: 'npm prepublish script detected'
      }
    ]
  },

  // Python setup.py
  {
    file: 'setup.py',
    patterns: [
      {
        name: 'python_setup',
        pattern: /(?:install_requires|setup\s*\()/,
        severity: 'medium',
        message: 'Python setup.py detected - may execute code during install'
      },
      {
        name: 'python_cmdclass',
        pattern: /cmdclass\s*=\s*\{/,
        severity: 'high',
        message: 'Custom install commands in setup.py'
      }
    ]
  },

  // Makefile
  {
    file: /Makefile$/i,
    patterns: [
      {
        name: 'makefile_install',
        pattern: /^install\s*:/m,
        severity: 'medium',
        message: 'Makefile install target detected'
      },
      {
        name: 'makefile_all',
        pattern: /^all\s*:/m,
        severity: 'low',
        message: 'Makefile all target detected'
      }
    ]
  },

  // Shell scripts
  {
    file: /(?:install|setup|bootstrap)\.sh$/i,
    patterns: [
      {
        name: 'install_script',
        pattern: /.+/,
        severity: 'high',
        message: 'Installation shell script detected'
      }
    ]
  },

  // Docker
  {
    file: 'Dockerfile',
    patterns: [
      {
        name: 'docker_run',
        pattern: /^RUN\s+(.+)/m,
        severity: 'medium',
        message: 'Docker RUN command detected'
      },
      {
        name: 'docker_entrypoint',
        pattern: /^ENTRYPOINT\s+(.+)/m,
        severity: 'medium',
        message: 'Docker ENTRYPOINT detected'
      }
    ]
  }
]

// Dangerous patterns in any file
const DANGEROUS_PATTERNS = [
  {
    name: 'curl_pipe_bash',
    pattern: /curl\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical' as const,
    message: 'curl | bash pattern - arbitrary remote code execution'
  },
  {
    name: 'wget_pipe_bash',
    pattern: /wget\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical' as const,
    message: 'wget | bash pattern - arbitrary remote code execution'
  },
  {
    name: 'python_exec_url',
    pattern: /python[3]?\s+-c\s+['"].*(?:urllib|requests).*exec/gi,
    severity: 'critical' as const,
    message: 'Python remote code execution pattern'
  }
]

export class EntrypointDetector extends BaseScanner {
  readonly type = 'entrypoint' as const
  readonly name = 'Entrypoint Detector'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    for (const file of context.files) {
      const relativePath = file.replace(context.rootPath + '/', '')
      const content = await readFileContent(file)
      if (!content) continue

      // Check entrypoint configs
      for (const config of ENTRYPOINT_CONFIGS) {
        const matches = typeof config.file === 'string'
          ? relativePath.endsWith(config.file)
          : config.file.test(relativePath)

        if (matches) {
          for (const pattern of config.patterns) {
            const match = content.match(pattern.pattern)
            if (match) {
              findings.push({
                scanner: this.type,
                severity: pattern.severity,
                rule: `entrypoint_${pattern.name}`,
                message: pattern.message,
                location: { file: relativePath },
                evidence: match[1] || match[0]
              })
            }
          }
        }
      }

      // Check dangerous patterns in all files
      for (const pattern of DANGEROUS_PATTERNS) {
        let match: RegExpExecArray | null
        pattern.pattern.lastIndex = 0

        while ((match = pattern.pattern.exec(content)) !== null) {
          findings.push({
            scanner: this.type,
            severity: pattern.severity,
            rule: `entrypoint_${pattern.name}`,
            message: pattern.message,
            location: {
              file: relativePath,
              line: this.getLineNumber(content, match.index)
            },
            evidence: match[0]
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

## 検出対象

### 1. package.json
- postinstall
- preinstall
- prepare
- prepublish

### 2. setup.py (Python)
- setup() 呼び出し
- cmdclass カスタムコマンド

### 3. Makefile
- install ターゲット
- all ターゲット

### 4. シェルスクリプト
- install.sh
- setup.sh
- bootstrap.sh

### 5. Docker
- RUN コマンド
- ENTRYPOINT

### 6. 危険パターン（全ファイル）
- curl | bash
- wget | bash
- Python remote exec

## 完了条件
- [ ] EntrypointDetector実装
- [ ] 各ファイルタイプで検出できる
- [ ] 危険パターンは全ファイルでスキャン
- [ ] テスト作成
