# SkillGate 開発チケット一覧

## プロジェクト概要
Claude Code skills (.md) のセキュリティチェックを行うCLIツール「sg」

## チケット構成

### Phase 1: Foundation（基盤）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [001](./001-project-setup.md) | プロジェクト初期化 | - | P0 |
| [002](./002-type-definitions.md) | 型定義 | 001 | P0 |
| [003](./003-utilities.md) | ユーティリティ関数 | 001 | P0 |

### Phase 2: Core Scanners（スキャナ）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [004](./004-scanner-base.md) | スキャナ基盤 | 002, 003 | P0 |
| [005](./005-secret-scanner.md) | Secret Scanner | 004 | P0 |
| [006](./006-static-analyzer.md) | Static Analyzer | 004 | P0 |
| [007](./007-skill-scanner.md) | Skill Scanner | 004 | P0 |
| [008](./008-entrypoint-detector.md) | Entrypoint Detector | 004 | P1 |
| [009](./009-dependency-scanner.md) | Dependency Scanner | 004 | P1 |
| [010](./010-ci-risk-analyzer.md) | CI Risk Analyzer | 004 | P1 |

### Phase 3: Policy & Reporting（ポリシー・レポート）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [011](./011-policy-schema.md) | ポリシースキーマ | 002 | P0 |
| [012](./012-policy-loader.md) | ポリシーローダー | 011 | P0 |
| [013](./013-policy-engine.md) | ポリシーエンジン | 012 | P0 |
| [014](./014-default-policy.md) | デフォルトポリシー | 011 | P0 |
| [015](./015-enforcer.md) | Enforcer | 013 | P0 |
| [016](./016-json-reporter.md) | JSON Reporter | 002 | P0 |
| [017](./017-markdown-reporter.md) | Markdown Reporter | 016 | P1 |

### Phase 4: Ingestor（入力処理）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [018](./018-ingestor-base.md) | Ingestor基盤 | 003 | P0 |
| [019](./019-local-ingestor.md) | Local Ingestor | 018 | P0 |
| [020](./020-git-ingestor.md) | Git Ingestor | 018 | P1 |
| [021](./021-archive-ingestor.md) | Archive Ingestor | 018 | P2 |

### Phase 5: CLI（コマンドライン）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [022](./022-cli-framework.md) | CLIフレームワーク | 003 | P0 |
| [023](./023-scan-command.md) | scan コマンド | 022, 015, 016, 019 | P0 |
| [024](./024-init-command.md) | init コマンド | 022, 014 | P1 |
| [025](./025-validate-command.md) | validate コマンド | 022, 012 | P1 |

### Phase 6: Testing（テスト）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [026](./026-test-fixtures.md) | テストフィクスチャ | - | P0 |
| [027](./027-unit-tests.md) | ユニットテスト | 026 | P0 |
| [028](./028-integration-tests.md) | 統合テスト | 027 | P1 |

### Phase 7: Documentation（ドキュメント）
| チケット | タイトル | 依存 | 優先度 |
|----------|----------|------|--------|
| [029](./029-spec-update.md) | spec.md更新 | - | P1 |
| [030](./030-readme.md) | README作成 | 023 | P1 |

## 優先度の定義
- **P0**: MVP必須（これがないとリリースできない）
- **P1**: 重要（リリース前に実装推奨）
- **P2**: あると良い（後回し可能）

## 実装順序（推奨）
1. 001 → 002 → 003（基盤）
2. 004 → 005, 006, 007（コアスキャナ並列）
3. 011 → 012 → 013 → 014 → 015（ポリシー）
4. 016（レポーター）
5. 018 → 019（Ingestor）
6. 022 → 023（CLI）
7. 026 → 027（テスト）
8. 残りのP1, P2チケット
