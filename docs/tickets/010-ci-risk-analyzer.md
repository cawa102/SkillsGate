# チケット 010: CI Risk Analyzer

## 概要
GitHub Actions等のCI/CD設定ファイルを解析し、危険な設定を検出するスキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/ci-risk.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding, Severity } from '../../types/index.js'
import { readFileContent } from './utils.js'
import yaml from 'js-yaml'

interface CIRiskPattern {
  name: string
  check: (content: unknown) => boolean
  severity: Severity
  message: string
}

export class CIRiskAnalyzer extends BaseScanner {
  readonly type = 'ci-risk' as const
  readonly name = 'CI Risk Analyzer'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    // GitHub Actions workflows
    const workflowFiles = context.files.filter(f =>
      /\.github\/workflows\/.*\.ya?ml$/.test(f)
    )

    for (const file of workflowFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      const relativePath = file.replace(context.rootPath + '/', '')

      try {
        const workflow = yaml.load(content) as Record<string, unknown>
        findings.push(...this.analyzeGitHubWorkflow(workflow, relativePath))
      } catch {
        findings.push({
          scanner: this.type,
          severity: 'info',
          rule: 'ci_parse_error',
          message: 'Failed to parse workflow file',
          location: { file: relativePath }
        })
      }
    }

    // GitLab CI
    const gitlabFiles = context.files.filter(f => f.endsWith('.gitlab-ci.yml'))
    for (const file of gitlabFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      const relativePath = file.replace(context.rootPath + '/', '')
      findings.push(...this.analyzeGitLabCI(content, relativePath))
    }

    return findings
  }

  private analyzeGitHubWorkflow(
    workflow: Record<string, unknown>,
    file: string
  ): Finding[] {
    const findings: Finding[] = []

    // Check permissions
    const permissions = workflow.permissions as Record<string, string> | string
    if (permissions === 'write-all') {
      findings.push({
        scanner: this.type,
        severity: 'high',
        rule: 'ci_write_all_permissions',
        message: 'Workflow has write-all permissions',
        location: { file }
      })
    }

    // Check jobs
    const jobs = workflow.jobs as Record<string, Record<string, unknown>> | undefined
    if (jobs) {
      for (const [jobName, job] of Object.entries(jobs)) {
        // Check for secrets exposure
        const steps = job.steps as Array<Record<string, unknown>> | undefined
        if (steps) {
          for (const step of steps) {
            const run = step.run as string | undefined
            if (run) {
              // Check for secret exposure in logs
              if (/echo.*\$\{\{\s*secrets\./.test(run)) {
                findings.push({
                  scanner: this.type,
                  severity: 'critical',
                  rule: 'ci_secret_exposure',
                  message: `Potential secret exposure in job ${jobName}`,
                  location: { file },
                  evidence: run.slice(0, 100)
                })
              }

              // Check for dangerous commands
              if (/curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh)/.test(run)) {
                findings.push({
                  scanner: this.type,
                  severity: 'high',
                  rule: 'ci_remote_script_execution',
                  message: `Remote script execution in job ${jobName}`,
                  location: { file }
                })
              }
            }

            // Check external actions
            const uses = step.uses as string | undefined
            if (uses) {
              // Unpinned action
              if (!uses.includes('@') || uses.endsWith('@main') || uses.endsWith('@master')) {
                findings.push({
                  scanner: this.type,
                  severity: 'medium',
                  rule: 'ci_unpinned_action',
                  message: `Unpinned action in job ${jobName}: ${uses}`,
                  location: { file }
                })
              }

              // Third-party action without SHA
              if (!uses.startsWith('actions/') && !/@[a-f0-9]{40}$/.test(uses)) {
                findings.push({
                  scanner: this.type,
                  severity: 'medium',
                  rule: 'ci_third_party_action',
                  message: `Third-party action without SHA pin: ${uses}`,
                  location: { file }
                })
              }
            }
          }
        }

        // Check for pull_request_target
        const on = workflow.on as Record<string, unknown> | string | string[]
        if (typeof on === 'object' && on !== null && 'pull_request_target' in on) {
          findings.push({
            scanner: this.type,
            severity: 'high',
            rule: 'ci_pull_request_target',
            message: 'Workflow uses pull_request_target - potential injection risk',
            location: { file }
          })
        }
      }
    }

    return findings
  }

  private analyzeGitLabCI(content: string, file: string): Finding[] {
    const findings: Finding[] = []

    try {
      const config = yaml.load(content) as Record<string, unknown>

      // Check for unsafe patterns
      for (const [key, value] of Object.entries(config)) {
        if (key === 'variables') {
          // Check for sensitive variables in plain text
          const vars = value as Record<string, string>
          for (const [varName, varValue] of Object.entries(vars)) {
            if (/password|secret|token|key/i.test(varName) && typeof varValue === 'string') {
              findings.push({
                scanner: this.type,
                severity: 'high',
                rule: 'ci_plaintext_secret',
                message: `Potential plaintext secret: ${varName}`,
                location: { file }
              })
            }
          }
        }

        // Check job scripts
        if (typeof value === 'object' && value !== null && 'script' in value) {
          const scripts = (value as Record<string, unknown>).script
          if (Array.isArray(scripts)) {
            for (const script of scripts) {
              if (typeof script === 'string' && /curl.*\|.*sh|wget.*\|.*sh/.test(script)) {
                findings.push({
                  scanner: this.type,
                  severity: 'high',
                  rule: 'ci_remote_script_execution',
                  message: `Remote script execution in job ${key}`,
                  location: { file }
                })
              }
            }
          }
        }
      }
    } catch {
      findings.push({
        scanner: this.type,
        severity: 'info',
        rule: 'ci_parse_error',
        message: 'Failed to parse GitLab CI file',
        location: { file }
      })
    }

    return findings
  }
}
```

## 検出項目

### GitHub Actions

| ルール | Severity | 説明 |
|--------|----------|------|
| ci_write_all_permissions | high | write-all権限 |
| ci_secret_exposure | critical | シークレットのログ出力 |
| ci_remote_script_execution | high | curl\|bash パターン |
| ci_unpinned_action | medium | 固定されていないアクション |
| ci_third_party_action | medium | SHA固定なしのサードパーティ |
| ci_pull_request_target | high | pull_request_targetの使用 |

### GitLab CI

| ルール | Severity | 説明 |
|--------|----------|------|
| ci_plaintext_secret | high | 平文のシークレット |
| ci_remote_script_execution | high | curl\|bash パターン |

## 完了条件
- [ ] CIRiskAnalyzer実装
- [ ] GitHub Actionsの解析
- [ ] GitLab CIの解析
- [ ] YAMLパースエラーハンドリング
- [ ] テスト作成
