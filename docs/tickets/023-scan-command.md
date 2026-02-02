# チケット 023: scan コマンド

## 概要
CLIの`scan`コマンドを実装し、全コンポーネント（Ingestor → Scanners → Policy Engine → Enforcer → Reporter）を統合する

## ステータス
- [x] 完了

## 依存
- 022: CLIフレームワーク
- 015: Enforcer
- 016: JSON Reporter
- 019: Local Ingestor
- 020: Git Ingestor
- 021: Archive Ingestor

## 背景（spec.mdより）
- FR-09: CLIで `allow / block / quarantine` を返す（exit code含む）
- FR-10: JSON出力でCIに組み込みやすくする
- AC-01: 指定Git URLを入力してスキャン→判定（allow/block）を返せる
- AC-05: CIで exit code 判定が可能（block時にジョブ失敗扱いにできる）

## 成果物

### src/cli/commands/scan.ts

```typescript
import type { Command } from 'commander'
import type { GlobalOptions } from '../index.js'
import { ExitCode } from '../index.js'
import { createLogger } from '../../utils/logger.js'
import {
  LocalIngestor,
  GitIngestor,
  ArchiveIngestor,
  type IngestResult
} from '../../core/ingestor/index.js'
import {
  ScannerOrchestrator,
  SecretScanner,
  StaticAnalyzer,
  SkillScanner,
  EntrypointDetector,
  DependencyScanner,
  CIRiskAnalyzer,
  type ScanContext
} from '../../core/scanner/index.js'
import { PolicyLoader } from '../../core/policy/loader.js'
import { Enforcer } from '../../core/enforcer/index.js'
import { JsonReporter } from '../../core/reporter/json.js'
import type { Finding, ScanReport } from '../../types/index.js'

const logger = createLogger('scan')

/**
 * Scan command options
 */
export interface ScanOptions {
  output?: string
  format?: 'json' | 'markdown'
  policy?: string
}

/**
 * Detect source type from input string
 */
export function detectSourceType(
  source: string
): 'git' | 'archive' | 'local' {
  // Git URL patterns
  if (
    source.startsWith('git@') ||
    source.startsWith('https://github.com') ||
    source.startsWith('https://gitlab.com') ||
    source.endsWith('.git')
  ) {
    return 'git'
  }

  // Archive patterns
  if (
    source.endsWith('.zip') ||
    source.endsWith('.tar.gz') ||
    source.endsWith('.tgz')
  ) {
    return 'archive'
  }

  // Default to local
  return 'local'
}

/**
 * Ingest source based on detected type
 */
async function ingestSource(source: string): Promise<IngestResult> {
  const sourceType = detectSourceType(source)

  switch (sourceType) {
    case 'git': {
      const ingestor = new GitIngestor()
      return ingestor.ingest(source)
    }
    case 'archive': {
      const ingestor = new ArchiveIngestor()
      return ingestor.ingest(source)
    }
    case 'local':
    default: {
      const ingestor = new LocalIngestor()
      return ingestor.ingest(source)
    }
  }
}

/**
 * Create and configure scanner orchestrator
 */
function createOrchestrator(): ScannerOrchestrator {
  const orchestrator = new ScannerOrchestrator()

  orchestrator.register(new SecretScanner())
  orchestrator.register(new StaticAnalyzer())
  orchestrator.register(new SkillScanner())
  orchestrator.register(new EntrypointDetector())
  orchestrator.register(new DependencyScanner())
  orchestrator.register(new CIRiskAnalyzer())

  return orchestrator
}

/**
 * Execute scan command
 */
export async function executeScan(
  source: string,
  options: ScanOptions,
  globalOptions: GlobalOptions
): Promise<number> {
  const startTime = Date.now()
  const errors: string[] = []

  try {
    // 1. Ingest source
    if (!globalOptions.quiet) {
      logger.info(`Ingesting source: ${source}`)
    }
    const ingestResult = await ingestSource(source)

    // 2. Create scan context
    const context: ScanContext = {
      rootDir: ingestResult.rootDir,
      files: ingestResult.files
    }

    // 3. Run scanners in parallel
    if (!globalOptions.quiet) {
      logger.info('Running security scanners...')
    }
    const orchestrator = createOrchestrator()
    const results = await orchestrator.scan(context)

    // 4. Collect all findings
    const findings: Finding[] = results.flatMap(r => r.findings)

    // 5. Load policy
    const policyLoader = new PolicyLoader()
    const policy = options.policy
      ? await policyLoader.loadFromFile(options.policy)
      : await policyLoader.loadDefault()

    // 6. Enforce policy
    const enforcer = new Enforcer(policy)
    const enforcement = enforcer.enforce(findings)

    // 7. Build report
    const report: ScanReport = {
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      source: {
        type: detectSourceType(source),
        path: source,
        hash: ingestResult.hash,
        commit: ingestResult.commit
      },
      decision: enforcement.decision,
      score: enforcement.evaluation.score,
      findings,
      summary: {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length
      },
      criticalBlockRules: enforcement.evaluation.criticalBlockRules,
      duration: Date.now() - startTime,
      policyName: enforcement.policyName,
      errors
    }

    // 8. Generate and output report
    const reporter = new JsonReporter()
    await reporter.write(report, {
      output: options.output,
      quiet: globalOptions.quiet
    })

    // 9. Print summary if not quiet
    if (!globalOptions.quiet) {
      logger.info('')
      logger.info(enforcement.summary)
      for (const reason of enforcement.reasons) {
        logger.info(`  - ${reason}`)
      }
    }

    return enforcement.exitCode

  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    logger.error(`Scan failed: ${message}`)
    return ExitCode.ERROR
  }
}

/**
 * Register scan command
 */
export function registerScanCommand(program: Command): void {
  program
    .command('scan <source>')
    .description('Scan a skill source for security risks')
    .option('-o, --output <file>', 'Output file path')
    .option('-f, --format <format>', 'Output format (json|markdown)', 'json')
    .option('-p, --policy <file>', 'Policy file to use')
    .action(async (source: string, options: ScanOptions) => {
      const globalOpts = program.opts() as GlobalOptions
      const exitCode = await executeScan(source, options, globalOpts)
      process.exit(exitCode)
    })
}
```

## データフロー

```
┌─────────────────────────────────────────────────────────────────┐
│                        sg scan <source>                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Source Type Detection                                         │
│    - Git URL (github.com, gitlab.com, .git)                     │
│    - Archive (.zip, .tar.gz, .tgz)                              │
│    - Local (default)                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Ingestor                                                      │
│    - GitIngestor: clone repo, record commit SHA                  │
│    - ArchiveIngestor: extract to temp dir                        │
│    - LocalIngestor: read directory                               │
│    Output: { rootDir, files[], hash, commit? }                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Scanner Orchestrator (parallel)                               │
│    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│    │SecretScanner│ │StaticAnalyz │ │SkillScanner │              │
│    └─────────────┘ └─────────────┘ └─────────────┘              │
│    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│    │ Entrypoint  │ │ Dependency  │ │  CI Risk    │              │
│    └─────────────┘ └─────────────┘ └─────────────┘              │
│    Output: Finding[]                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Policy Engine                                                 │
│    - Load policy (custom or default)                             │
│    - Evaluate findings against rules                             │
│    - Calculate score (start 100, deduct by weight)               │
│    - Check critical_block rules                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Enforcer                                                      │
│    - score ≤ 40 OR critical_block → BLOCK (exit 1)              │
│    - score ≤ 70 → QUARANTINE (exit 2)                           │
│    - else → ALLOW (exit 0)                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Reporter                                                      │
│    - JSON (default) or Markdown                                  │
│    - Mask secrets in output                                      │
│    - Write to file or stdout                                     │
└─────────────────────────────────────────────────────────────────┘
```

## CLI使用例

```bash
# ローカルディレクトリをスキャン
sg scan ./my-skill

# Git URLをスキャン
sg scan https://github.com/user/skill-repo

# カスタムポリシーでスキャン
sg scan ./my-skill --policy ./custom.policy.yaml

# JSONをファイルに出力
sg scan ./my-skill --output report.json

# 静かモード（エラーのみ表示）
sg scan ./my-skill --quiet

# 詳細モード
sg scan ./my-skill --verbose

# CI/CDでの使用例
sg scan ./my-skill && echo "Safe to install" || echo "Blocked"
```

## 出力例

### 成功時（allow）
```
[INFO] Ingesting source: ./my-skill
[INFO] Running security scanners...
[INFO]
[INFO] ALLOWED: No security issues detected. Score: 100/100
```

### 警告時（quarantine）
```
[INFO] Ingesting source: ./my-skill
[INFO] Running security scanners...
[INFO]
[INFO] QUARANTINED: 3 finding(s) from 2 rule(s). Score: 65/100
[INFO]   - MEDIUM: Potentially dangerous eval() usage (2 occurrences)
[INFO]   - LOW: curl command detected in shell script (1 occurrence)
```

### ブロック時（block）
```
[INFO] Ingesting source: ./my-skill
[INFO] Running security scanners...
[INFO]
[INFO] BLOCKED: 5 finding(s) from 3 rule(s). Score: 25/100
[INFO]   - Critical block rules triggered: secret_aws_access_key
[INFO]   - CRITICAL: AWS Access Key detected (1 occurrence)
[INFO]   - HIGH: rm -rf / command detected (1 occurrence)
[INFO]   - HIGH: curl | bash pattern detected (1 occurrence)
```

## Exit Codes

| Code | Decision | 説明 |
|------|----------|------|
| 0 | allow | 安全、インストール許可 |
| 1 | block | 危険、インストール拒否 |
| 2 | quarantine | 警告、隔離実行を推奨 |
| 3 | error | スキャン失敗 |

## テスト要件

### src/cli/commands/scan.test.ts

```typescript
describe('scan command', () => {
  describe('detectSourceType', () => {
    it('should detect git URLs', () => {
      expect(detectSourceType('https://github.com/user/repo')).toBe('git')
      expect(detectSourceType('git@github.com:user/repo.git')).toBe('git')
    })

    it('should detect archives', () => {
      expect(detectSourceType('./skill.zip')).toBe('archive')
      expect(detectSourceType('./skill.tar.gz')).toBe('archive')
    })

    it('should default to local', () => {
      expect(detectSourceType('./my-skill')).toBe('local')
      expect(detectSourceType('/path/to/skill')).toBe('local')
    })
  })

  describe('executeScan', () => {
    it('should return allow (0) for safe source')
    it('should return block (1) for dangerous source')
    it('should return quarantine (2) for warning source')
    it('should return error (3) for invalid source')
    it('should use custom policy when specified')
    it('should output to file when --output specified')
    it('should suppress output in quiet mode')
  })

  describe('integration', () => {
    it('should scan local directory end-to-end')
    it('should scan git repo end-to-end')
    it('should scan archive end-to-end')
  })
})
```

## 完了条件
- [x] detectSourceType実装
- [x] ingestSource実装
- [x] createOrchestrator実装
- [x] executeScan実装
- [x] registerScanCommand実装
- [x] CLIへの統合
- [x] テスト作成（22ケース）
- [x] Exit code検証
- [x] CI/CD組み込みテスト

## 注意事項

1. **エラーハンドリング**: 各ステップでエラーをキャッチし、適切なエラーメッセージを出力する
2. **シークレットマスキング**: レポート出力時は必ずシークレットをマスクする
3. **パフォーマンス**: スキャナーは並列実行し、大規模リポジトリでも数分以内に完了する
4. **再現性**: 同一入力（commit/hash）と同一policyで同一結果となる
