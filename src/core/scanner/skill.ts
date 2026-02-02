import { BaseScanner, type ScanContext } from './base.js'
import { readFileContent } from './utils.js'
import type { Finding, Severity } from '../../types/index.js'

type SkillCategory = 'dangerous_command' | 'external_url' | 'permission_request'

interface SkillPattern {
  readonly name: string
  readonly pattern: RegExp
  readonly severity: Severity
  readonly message: string
  readonly category: SkillCategory
}

const SKILL_PATTERNS: readonly SkillPattern[] = [
  // Dangerous commands
  {
    name: 'rm_rf_root',
    pattern: /rm\s+-rf\s+(?:\/|~|\$HOME|\$\{HOME\})/gi,
    severity: 'critical',
    message: 'Destructive rm -rf command targeting root or home directory',
    category: 'dangerous_command'
  },
  {
    name: 'rm_rf_generic',
    pattern: /rm\s+(?:-[rRf]+\s+)+/g,
    severity: 'high',
    message: 'Recursive/force delete command detected',
    category: 'dangerous_command'
  },
  {
    name: 'sudo_usage',
    pattern: /\bsudo\s+/g,
    severity: 'high',
    message: 'sudo usage detected - requires elevated privileges',
    category: 'dangerous_command'
  },
  {
    name: 'chmod_777',
    pattern: /chmod\s+(?:777|a\+rwx)/g,
    severity: 'high',
    message: 'chmod 777 detected - insecure permission change',
    category: 'dangerous_command'
  },
  {
    name: 'curl_bash',
    pattern: /curl\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical',
    message: 'curl | bash pattern detected - arbitrary code execution',
    category: 'dangerous_command'
  },
  {
    name: 'wget_bash',
    pattern: /wget\s+[^|]*\|\s*(?:bash|sh|zsh)/gi,
    severity: 'critical',
    message: 'wget | bash pattern detected - arbitrary code execution',
    category: 'dangerous_command'
  },
  {
    name: 'bash_c',
    pattern: /(?:bash|sh|zsh)\s+-c\s+['"][^'"]+['"]/g,
    severity: 'medium',
    message: 'Shell command execution with -c flag',
    category: 'dangerous_command'
  },
  {
    name: 'dd_command',
    pattern: /\bdd\s+.*(?:if|of)=/g,
    severity: 'high',
    message: 'dd command detected - can overwrite disk data',
    category: 'dangerous_command'
  },
  {
    name: 'mkfs_command',
    pattern: /\bmkfs\./g,
    severity: 'critical',
    message: 'mkfs command detected - filesystem format',
    category: 'dangerous_command'
  },

  // External URL patterns
  {
    name: 'suspicious_download',
    pattern: /(?:curl|wget|fetch)\s+(?:-[a-zA-Z]+\s+)*['"]?https?:\/\/(?!(?:github\.com|githubusercontent\.com|npmjs\.org|pypi\.org))[^\s'"]+/gi,
    severity: 'medium',
    message: 'Download from non-standard source',
    category: 'external_url'
  },
  {
    name: 'short_url',
    pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly)\/[a-zA-Z0-9]+/gi,
    severity: 'high',
    message: 'Shortened URL detected - destination unknown',
    category: 'external_url'
  },
  {
    name: 'ip_address_url',
    pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    severity: 'high',
    message: 'Direct IP address URL detected',
    category: 'external_url'
  },
  {
    name: 'base64_url',
    pattern: /https?:\/\/[a-zA-Z0-9+/]{50,}={0,2}/g,
    severity: 'high',
    message: 'Potentially encoded URL detected',
    category: 'external_url'
  },

  // Permission requests
  {
    name: 'file_access_home',
    pattern: /(?:read|write|access|open)\s+.*(?:~\/|\/home\/|\$HOME)/gi,
    severity: 'medium',
    message: 'Home directory access requested',
    category: 'permission_request'
  },
  {
    name: 'network_permission',
    pattern: /(?:connect|socket|listen|bind)\s+.*(?:port|:)\s*\d+/gi,
    severity: 'medium',
    message: 'Network permission requested',
    category: 'permission_request'
  },
  {
    name: 'env_var_access',
    pattern: /\$(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)/gi,
    severity: 'high',
    message: 'Sensitive environment variable access',
    category: 'permission_request'
  },
  {
    name: 'sensitive_path_access',
    pattern: /(?:\/etc\/(?:passwd|shadow|sudoers)|\/var\/log|\/proc\/)/g,
    severity: 'high',
    message: 'Sensitive system path access',
    category: 'permission_request'
  }
] as const

/** Maximum evidence length in findings */
const MAX_EVIDENCE_LENGTH = 100

/**
 * Scanner for Claude Code skill-specific dangerous patterns
 */
export class SkillScanner extends BaseScanner {
  readonly type = 'skill' as const
  readonly name = 'Skill Scanner'

  /**
   * Scan markdown files for skill-specific dangerous patterns
   * @param context - Scan context containing files and root path
   * @returns Array of findings for detected issues
   */
  async scan(context: ScanContext): Promise<Finding[]> {
    const skillFiles = context.files.filter(f => /\.md$/i.test(f))

    const allFindings = await Promise.all(
      skillFiles.map(async (file) => {
        const content = await readFileContent(file)
        if (!content) return []
        return this.scanContent(content, file, context.rootPath)
      })
    )

    return allFindings.flat()
  }

  private scanContent(content: string, filePath: string, rootPath: string): Finding[] {
    const findings: Finding[] = []
    const relativePath = filePath.replace(rootPath + '/', '')

    for (const skillPattern of SKILL_PATTERNS) {
      const pattern = new RegExp(skillPattern.pattern.source, skillPattern.pattern.flags)

      let match: RegExpExecArray | null
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index)
        const evidence = match[0].slice(0, MAX_EVIDENCE_LENGTH)

        findings.push({
          scanner: this.type,
          severity: skillPattern.severity,
          rule: `skill_${skillPattern.name}`,
          message: skillPattern.message,
          location: {
            file: relativePath,
            line: lineNumber
          },
          evidence,
          metadata: { category: skillPattern.category }
        })
      }
    }

    return findings
  }

  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length
  }
}
