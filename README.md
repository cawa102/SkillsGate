# SkillGate

<div align="center">

**Security Scanner for Claude Code Skills**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-404%20passing-brightgreen.svg)](#testing)

</div>

---

## Overview

SkillGate (`sg`) is a pre-installation security scanner for Claude Code skills, MCP servers, and agent extensions. It performs multi-layer security audits before installation to protect your local environment from supply chain attacks, credential theft, and malicious code execution.

### Why SkillGate?

AI agent extensions (skills) are not just configuration files—they contain **executable code, dependencies, and operational procedures** that run in your local environment. Your machine has API keys, SSH keys, browser credentials, and `.env` files that could be compromised by malicious skills.

SkillGate acts as a **security gate** that:
- Scans for leaked secrets and credentials
- Detects dangerous commands (`rm -rf /`, `curl | bash`, etc.)
- Identifies vulnerable dependencies
- Analyzes CI/CD configuration risks
- Enforces security policies before installation

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/skillgate.git](https://github.com/cawa102/SkillsGate.git
cd skillgate

# Install dependencies
npm install

# Build
npm run build

# Link globally (optional)
npm link
```

### Basic Usage

```bash
# Scan a local directory
sg scan ./my-skill

# Scan a GitHub repository
sg scan https://github.com/user/skill-repo

# Scan an archive
sg scan ./skill.zip

# Output to file
sg scan ./my-skill --output report.json

# Use markdown format
sg scan ./my-skill --format markdown

# Custom policy
sg scan ./my-skill --policy ./custom.policy.yaml
```

---

## Features

### Multi-Layer Security Scanning

| Scanner | What It Detects |
|---------|-----------------|
| **Secret Scanner** | AWS keys, GitHub tokens, API keys, passwords, private keys |
| **Static Analyzer** | `eval()`, `exec()`, credential access patterns, obfuscation |
| **Skill Scanner** | `rm -rf /`, `curl \| bash`, `sudo`, `chmod 777` |
| **Entrypoint Detector** | `postinstall` scripts, `setup.py`, Makefile auto-execution |
| **Dependency Scanner** | Known vulnerabilities via OSV API |
| **CI Risk Analyzer** | GitHub Actions/GitLab CI dangerous patterns |

### Policy-Based Enforcement

```yaml
# Example policy
name: my-policy
version: "1.0"
thresholds:
  block: 40    # Score <= 40 → BLOCK
  warn: 70     # Score <= 70 → QUARANTINE
critical_block:
  - secret_aws_access_key
  - skill_rm_rf_root
  - skill_curl_bash
rules:
  secret_github_token:
    severity: critical
    weight: 30
    message: "GitHub token detected"
```

### Exit Codes for CI/CD

| Code | Decision | Description |
|------|----------|-------------|
| `0` | ALLOW | Safe to install |
| `1` | BLOCK | Installation blocked |
| `2` | QUARANTINE | Sandboxed execution recommended |
| `3` | ERROR | Scan failed |

```bash
# CI/CD integration
sg scan ./skill --quiet && echo "Safe" || echo "Blocked"
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      sg scan <source>                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Ingestor (Local / Git / Archive)                           │
│  → Normalize source, compute hash, record commit SHA        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Scanner Orchestrator (Parallel Execution)                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ Secret   │ │ Static   │ │ Skill    │ │ Entrypoint│       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
│  ┌──────────┐ ┌──────────┐                                  │
│  │Dependency│ │ CI Risk  │                                  │
│  └──────────┘ └──────────┘                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Policy Engine                                              │
│  → Evaluate findings against rules                          │
│  → Calculate score (start 100, deduct by weight)            │
│  → Check critical_block rules                               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Enforcer                                                   │
│  → ALLOW (score > 70)                                       │
│  → QUARANTINE (40 < score <= 70)                            │
│  → BLOCK (score <= 40 OR critical_block triggered)          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Reporter (JSON / Markdown)                                 │
│  → Mask secrets in output                                   │
│  → Generate audit trail                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## CLI Commands

### `sg scan <source>`

Scan a skill source for security risks.

```bash
sg scan <source> [options]

Options:
  -o, --output <file>   Output file path
  -f, --format <format> Output format (json|markdown) [default: json]
  -p, --policy <file>   Policy file to use
  -v, --verbose         Enable verbose output
  -q, --quiet           Suppress output except errors
```

### `sg init`

Generate a default policy configuration file.

```bash
sg init [options]

Options:
  -o, --output <file>  Output file path [default: skillgate.policy.yaml]
  --force              Overwrite existing file
```

### `sg validate <policy>`

Validate a policy configuration file.

```bash
sg validate <policy>
```

---

## Output Examples

### JSON Output (Safe Skill)

```json
{
  "version": "1.0.0",
  "timestamp": "2026-02-02T22:41:58.319Z",
  "source": {
    "type": "local",
    "path": "./my-skill",
    "hash": "1b2f6b3953c9924424b0011aaf3bbf659efdc3325664e21a58e20dcc871c5118"
  },
  "decision": "allow",
  "score": 100,
  "findings": [],
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "policyName": "skillgate-default"
}
```

### Markdown Output (Blocked Skill)

```markdown
# SkillGate Security Report
**Decision:** 🚫 **BLOCK**

## Summary
| Metric | Value |
|--------|-------|
| Score | **30**/100 |
| Policy | skillgate-default |

### Findings by Severity
| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 1 |

## Findings
### 🔴 Critical: Destructive rm -rf command
- **File:** SKILL.md:4
- **Evidence:** `rm -rf /`
```

---

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npx vitest run src/core/scanner/secret.test.ts

# Watch mode
npm run test:watch
```

**Test Coverage:** 404 tests across 23 test files

---

## Project Structure

```
skillgate/
├── src/
│   ├── cli/              # CLI commands
│   │   ├── commands/     # scan, init, validate
│   │   └── index.ts      # Entry point
│   ├── core/
│   │   ├── ingestor/     # Source acquisition (local, git, archive)
│   │   ├── scanner/      # Security scanners (6 types)
│   │   ├── policy/       # Policy engine and loader
│   │   ├── enforcer/     # Decision making
│   │   └── reporter/     # JSON and Markdown output
│   ├── types/            # TypeScript type definitions
│   └── utils/            # Utilities (hash, mask, logger)
├── policies/             # Default policy files
├── docs/                 # Documentation and tickets
└── package.json
```

---

## Security Philosophy

1. **Secure by Default** — Block dangerous patterns unless explicitly allowed
2. **Policy as Code** — Security rules in version-controlled YAML files
3. **Transparency** — Every decision has a clear audit trail
4. **Defense in Depth** — Multiple scanners catch different attack vectors
5. **Secret Protection** — Never log or output actual secrets (always masked)

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests first (TDD required)
4. Implement your feature
5. Run tests (`npm test`)
6. Commit (`git commit -m 'feat: add amazing feature'`)
7. Push (`git push origin feature/amazing-feature`)
8. Open a Pull Request

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [Commander.js](https://github.com/tj/commander.js) - CLI framework
- [Zod](https://github.com/colinhacks/zod) - Schema validation
- [simple-git](https://github.com/steveukx/git-js) - Git operations
- [Vitest](https://vitest.dev/) - Testing framework
