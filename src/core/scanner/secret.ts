import { BaseScanner, type ScanContext } from './base.js'
import { readFileContent } from './utils.js'
import type { Finding, Severity } from '../../types/index.js'
import { maskEvidence } from '../../utils/mask.js'

interface SecretPattern {
  readonly name: string
  readonly pattern: RegExp
  readonly severity: Severity
  readonly message: string
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
  // AWS
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    message: 'AWS Access Key detected'
  },
  {
    name: 'aws_secret_key',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    message: 'Potential AWS Secret Key detected'
  },

  // GitHub - all token types
  {
    name: 'github_token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub Personal Access Token detected'
  },
  {
    name: 'github_oauth',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub OAuth Token detected'
  },
  {
    name: 'github_user_to_server',
    pattern: /ghu_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub User-to-Server Token detected'
  },
  {
    name: 'github_server_to_server',
    pattern: /ghs_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub Server-to-Server Token detected'
  },
  {
    name: 'github_refresh',
    pattern: /ghr_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    message: 'GitHub Refresh Token detected'
  },

  // OpenAI (including project-scoped keys, but not sk-ant- which is Anthropic)
  {
    name: 'openai_key',
    pattern: /sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{20,}/g,
    severity: 'critical',
    message: 'OpenAI API Key detected'
  },

  // Anthropic
  {
    name: 'anthropic_key',
    pattern: /sk-ant-[a-zA-Z0-9-]{95}/g,
    severity: 'critical',
    message: 'Anthropic API Key detected'
  },

  // Private keys
  {
    name: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    message: 'Private key detected'
  },

  // Password in URL
  {
    name: 'password_in_url',
    pattern: /[a-zA-Z]+:\/\/[^:]+:[^@]+@/g,
    severity: 'high',
    message: 'Password in URL detected'
  },

  // Generic API key patterns
  {
    name: 'generic_api_key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    severity: 'high',
    message: 'Generic API key pattern detected'
  },

  // JWT tokens
  {
    name: 'jwt_token',
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    severity: 'high',
    message: 'JWT token detected'
  }
] as const

/** Maximum file size to scan (1MB) */
const MAX_FILE_SIZE = 1_000_000

/**
 * Scanner for detecting secrets and sensitive information in code
 */
export class SecretScanner extends BaseScanner {
  readonly type = 'secret' as const
  readonly name = 'Secret Scanner'

  /**
   * Scan files for leaked secrets and credentials
   * @param context - Scan context containing files and root path
   * @returns Array of findings for detected secrets
   */
  async scan(context: ScanContext): Promise<Finding[]> {
    const allFindings = await Promise.all(
      context.files.map(async (file) => {
        const content = await readFileContent(file)
        if (!content) return []

        const contentToScan = content.length > MAX_FILE_SIZE
          ? content.slice(0, MAX_FILE_SIZE)
          : content

        return this.scanContent(contentToScan, file, context.rootPath)
      })
    )

    return allFindings.flat()
  }

  private scanContent(content: string, filePath: string, rootPath: string): Finding[] {
    const findings: Finding[] = []
    const relativePath = filePath.replace(rootPath + '/', '')

    for (const secretPattern of SECRET_PATTERNS) {
      // Reset regex lastIndex for each file
      const pattern = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags)

      let match: RegExpExecArray | null
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index)
        const matchedText = match[0]

        findings.push({
          scanner: this.type,
          severity: secretPattern.severity,
          rule: `secret_${secretPattern.name}`,
          message: secretPattern.message,
          location: {
            file: relativePath,
            line: lineNumber
          },
          evidence: maskEvidence(matchedText)
        })
      }
    }

    return findings
  }

  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length
  }
}
