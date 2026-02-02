import { BaseScanner, type ScanContext } from './base.js'
import type { Finding, Severity } from '../../types/index.js'
import { readFileContent } from './utils.js'

interface EntrypointPattern {
  file: string | RegExp
  patterns: Array<{
    name: string
    pattern: RegExp
    severity: Severity
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
        pattern: /.+/s,
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

/**
 * Entrypoint Detector Scanner
 *
 * Detects auto-execution entry points that run during installation:
 * - npm scripts (postinstall, preinstall, prepare)
 * - Python setup.py with custom commands
 * - Makefiles with install targets
 * - Installation shell scripts
 * - Docker build commands
 * - Dangerous patterns like curl | bash
 */
export class EntrypointDetector extends BaseScanner {
  readonly type = 'entrypoint' as const
  readonly name = 'Entrypoint Detector'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    for (const file of context.files) {
      const relativePath = this.getRelativePath(file, context.rootPath)
      const content = await readFileContent(file)
      if (!content) continue

      // Check entrypoint configs
      this.scanEntrypointConfigs(content, relativePath, findings)

      // Check dangerous patterns in all files
      this.scanDangerousPatterns(content, relativePath, findings)
    }

    return findings
  }

  private scanEntrypointConfigs(
    content: string,
    relativePath: string,
    findings: Finding[]
  ): void {
    for (const config of ENTRYPOINT_CONFIGS) {
      const matches =
        typeof config.file === 'string'
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
              evidence: match[1] || match[0].slice(0, 100)
            })
          }
        }
      }
    }
  }

  private scanDangerousPatterns(
    content: string,
    relativePath: string,
    findings: Finding[]
  ): void {
    for (const pattern of DANGEROUS_PATTERNS) {
      // Reset regex state for global patterns
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags)

      let match: RegExpExecArray | null
      while ((match = regex.exec(content)) !== null) {
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

  private getRelativePath(file: string, rootPath: string): string {
    if (file.startsWith(rootPath)) {
      return file.slice(rootPath.length + 1)
    }
    return file
  }

  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length
  }
}

/**
 * Create a new EntrypointDetector instance
 */
export function createEntrypointDetector(): EntrypointDetector {
  return new EntrypointDetector()
}
