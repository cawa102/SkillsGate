# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SkillGate (`sg`) is a security scanner CLI for Claude Code skills (.md files). It performs pre-installation security audits by scanning for secrets, dangerous commands, vulnerable dependencies, and other security risks.

## Commands

```bash
pnpm install          # Install dependencies
pnpm build            # Compile TypeScript to dist/
pnpm test             # Run all tests
pnpm test:watch       # Run tests in watch mode
pnpm test:coverage    # Run tests with coverage report
vitest run src/core/scanner/secret.test.ts  # Run single test file
```

## Architecture

### Data Flow
```
Source (Git/Local/Archive) → Ingestor → Scanners (parallel) → Policy Engine → Enforcer → Reporter
```

### Core Modules (`src/core/`)

**Ingestor** - Source acquisition and normalization
- `git.ts` - Clone repos, record commit SHA
- `local.ts` - Read local directories
- `archive.ts` - Extract zip/tar.gz

**Scanner Layer** - Parallel security checks (all implement `BaseScanner`)
- `secret.ts` - Detect leaked keys, tokens, credentials (AWS, GitHub, OpenAI, etc.)
- `static.ts` - Dangerous API calls (eval, exec, child_process), obfuscation, credential access patterns
- `skill.ts` - Claude Code skill-specific risks (rm -rf, curl|bash, sudo, chmod 777)
- `entrypoint.ts` - Auto-execution points (postinstall, setup.py, Makefile)
- `dependency.ts` - Parse lock files, query OSV API for vulnerabilities
- `ci-risk.ts` - GitHub Actions/GitLab CI dangerous patterns

**Policy Engine** (`src/core/policy/`)
- Policies are YAML files with Zod validation
- Score starts at 100, rules deduct points via `weight`
- `critical_block` rules cause immediate block regardless of score
- Thresholds: score ≤ 40 → block, score ≤ 70 → quarantine, else → allow

**Enforcer** - Returns decision based on policy evaluation

**Reporter** - JSON and Markdown output with masked secrets

### CLI Commands (`src/cli/commands/`)
- `scan <source>` - Main scan command
- `init` - Generate default policy file
- `validate <policy>` - Validate policy YAML

### Exit Codes
- 0: allow (safe)
- 1: block (installation blocked)
- 2: quarantine (sandboxed execution recommended)
- 3: error (scan failed)

## Key Types

```typescript
// Finding from any scanner
interface Finding {
  scanner: ScannerType  // 'secret' | 'dependency' | 'static' | 'entrypoint' | 'ci-risk' | 'skill'
  severity: Severity    // 'critical' | 'high' | 'medium' | 'low' | 'info'
  rule: string          // e.g., 'secret_aws_access_key'
  message: string
  location: { file: string; line?: number }
  evidence?: string     // Always masked if sensitive
}

// Policy structure (YAML)
interface Policy {
  thresholds: { block: number; warn: number }
  critical_block: string[]  // Rules that cause immediate block
  rules: Record<string, { severity, weight, message, enabled }>
  exceptions: Array<{ pattern: string; ignore: string[] }>
}
```

## Development Notes

- All scanners extend `BaseScanner` and implement `scan(context): Promise<Finding[]>`
- Secrets in reports must always be masked via `maskEvidence()` from `src/utils/mask.ts`
- Policy files are validated with Zod schemas in `src/types/policy.ts`

## Documentation Reference

開発時は必ず `docs/` 配下のドキュメントを参照すること：

| ドキュメント | 内容 |
|-------------|------|
| `docs/spec.md` | 要件定義書（SoW）- 機能要件、非機能要件、受入基準 |
| `docs/tickets/000-overview.md` | チケット一覧と実装順序 |
| `docs/tickets/001-030` | 各機能の詳細仕様とコード例 |

新機能実装時は該当チケットを読み、完了条件を満たしているか確認する。
