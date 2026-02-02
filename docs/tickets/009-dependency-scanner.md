# チケット 009: Dependency Scanner

## 概要
依存関係ファイルを解析し、既知の脆弱性を検出するスキャナを実装する

## ステータス
- [ ] 未着手

## 依存
- 004: スキャナ基盤

## 成果物

### src/core/scanner/dependency.ts

```typescript
import { BaseScanner, ScanContext } from './base.js'
import type { Finding } from '../../types/index.js'
import { readFileContent } from './utils.js'

interface DependencyFile {
  pattern: RegExp
  parser: (content: string) => ParsedDependencies
  lockFile?: string
}

interface ParsedDependencies {
  name: string
  dependencies: Array<{
    name: string
    version: string
    dev?: boolean
  }>
}

interface OSVVulnerability {
  id: string
  summary: string
  severity: string
  affected: Array<{
    package: { name: string; ecosystem: string }
    ranges: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>
  }>
}

const DEPENDENCY_FILES: DependencyFile[] = [
  {
    pattern: /package\.json$/,
    lockFile: 'package-lock.json',
    parser: parsePackageJson
  },
  {
    pattern: /requirements\.txt$/,
    lockFile: 'requirements.txt', // Same file acts as lock
    parser: parseRequirementsTxt
  },
  {
    pattern: /go\.mod$/,
    lockFile: 'go.sum',
    parser: parseGoMod
  },
  {
    pattern: /Cargo\.toml$/,
    lockFile: 'Cargo.lock',
    parser: parseCargoToml
  }
]

export class DependencyScanner extends BaseScanner {
  readonly type = 'dependency' as const
  readonly name = 'Dependency Scanner'

  private osvApiUrl = 'https://api.osv.dev/v1/query'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    for (const depFile of DEPENDENCY_FILES) {
      const matchingFiles = context.files.filter(f => depFile.pattern.test(f))

      for (const file of matchingFiles) {
        const content = await readFileContent(file)
        if (!content) continue

        const relativePath = file.replace(context.rootPath + '/', '')

        try {
          const parsed = depFile.parser(content)

          // Check for lock file existence
          if (depFile.lockFile) {
            const lockExists = context.files.some(f =>
              f.endsWith(depFile.lockFile!)
            )
            if (!lockExists) {
              findings.push({
                scanner: this.type,
                severity: 'medium',
                rule: 'dependency_no_lockfile',
                message: `Lock file missing for ${relativePath}`,
                location: { file: relativePath }
              })
            }
          }

          // Check vulnerabilities via OSV API
          const vulns = await this.checkVulnerabilities(parsed.dependencies)
          findings.push(...vulns.map(v => ({
            scanner: this.type as const,
            severity: this.mapSeverity(v.severity),
            rule: `dependency_vuln_${v.id}`,
            message: `${v.summary} (${v.id})`,
            location: { file: relativePath },
            metadata: {
              vulnId: v.id,
              package: v.package,
              version: v.version
            }
          })))

        } catch (error) {
          findings.push({
            scanner: this.type,
            severity: 'info',
            rule: 'dependency_parse_error',
            message: `Failed to parse ${relativePath}`,
            location: { file: relativePath }
          })
        }
      }
    }

    return findings
  }

  private async checkVulnerabilities(
    deps: Array<{ name: string; version: string }>
  ): Promise<Array<{ id: string; summary: string; severity: string; package: string; version: string }>> {
    const results: Array<{ id: string; summary: string; severity: string; package: string; version: string }> = []

    // Query OSV API in batches
    for (const dep of deps) {
      try {
        const response = await fetch(this.osvApiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            package: { name: dep.name, ecosystem: 'npm' },
            version: dep.version
          })
        })

        if (response.ok) {
          const data = await response.json() as { vulns?: OSVVulnerability[] }
          if (data.vulns) {
            for (const vuln of data.vulns) {
              results.push({
                id: vuln.id,
                summary: vuln.summary,
                severity: this.extractSeverity(vuln),
                package: dep.name,
                version: dep.version
              })
            }
          }
        }
      } catch {
        // Skip if API unavailable (offline mode)
      }
    }

    return results
  }

  private extractSeverity(vuln: OSVVulnerability): string {
    return vuln.severity || 'UNKNOWN'
  }

  private mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'critical'
      case 'HIGH': return 'high'
      case 'MEDIUM': case 'MODERATE': return 'medium'
      default: return 'low'
    }
  }
}

// Parser functions
function parsePackageJson(content: string): ParsedDependencies {
  const pkg = JSON.parse(content)
  const deps: Array<{ name: string; version: string; dev?: boolean }> = []

  if (pkg.dependencies) {
    for (const [name, version] of Object.entries(pkg.dependencies)) {
      deps.push({ name, version: String(version) })
    }
  }
  if (pkg.devDependencies) {
    for (const [name, version] of Object.entries(pkg.devDependencies)) {
      deps.push({ name, version: String(version), dev: true })
    }
  }

  return { name: pkg.name || 'unknown', dependencies: deps }
}

function parseRequirementsTxt(content: string): ParsedDependencies {
  const deps: Array<{ name: string; version: string }> = []
  const lines = content.split('\n')

  for (const line of lines) {
    const match = line.match(/^([a-zA-Z0-9_-]+)(?:[=<>~!]+(.+))?/)
    if (match) {
      deps.push({ name: match[1], version: match[2] || '*' })
    }
  }

  return { name: 'python-project', dependencies: deps }
}

function parseGoMod(content: string): ParsedDependencies {
  const deps: Array<{ name: string; version: string }> = []
  const requireMatch = content.match(/require\s*\(([\s\S]*?)\)/g)

  if (requireMatch) {
    for (const block of requireMatch) {
      const lines = block.split('\n')
      for (const line of lines) {
        const match = line.match(/^\s*([^\s]+)\s+v?([^\s]+)/)
        if (match) {
          deps.push({ name: match[1], version: match[2] })
        }
      }
    }
  }

  return { name: 'go-module', dependencies: deps }
}

function parseCargoToml(content: string): ParsedDependencies {
  const deps: Array<{ name: string; version: string }> = []
  const lines = content.split('\n')
  let inDeps = false

  for (const line of lines) {
    if (line.match(/^\[dependencies\]/)) {
      inDeps = true
      continue
    }
    if (line.match(/^\[/)) {
      inDeps = false
      continue
    }
    if (inDeps) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/)
      if (match) {
        deps.push({ name: match[1], version: match[2] })
      }
    }
  }

  return { name: 'rust-crate', dependencies: deps }
}
```

## サポートファイル

| ファイル | ロックファイル | エコシステム |
|----------|----------------|--------------|
| package.json | package-lock.json | npm |
| requirements.txt | - | PyPI |
| go.mod | go.sum | Go |
| Cargo.toml | Cargo.lock | crates.io |

## 機能

### 1. ロックファイル確認
- ロックファイルが存在しない場合は警告

### 2. 脆弱性チェック (OSV API)
- オンライン時のみ実行
- オフライン時はスキップ（エラーにしない）

### 3. パース失敗時
- infoレベルで報告
- スキャン全体は続行

## 完了条件
- [ ] DependencyScanner実装
- [ ] 各ファイル形式のパーサー実装
- [ ] OSV APIとの連携
- [ ] オフラインモード対応
- [ ] テスト作成
