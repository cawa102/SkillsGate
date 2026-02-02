import { BaseScanner, type ScanContext } from './base.js'
import { readFileContent } from './utils.js'
import type { Finding, Severity } from '../../types/index.js'
import { maskEvidence } from '../../utils/mask.js'

type PatternCategory = 'dangerous_api' | 'obfuscation' | 'credential_access'

interface StaticPattern {
  readonly name: string
  readonly pattern: RegExp
  readonly severity: Severity
  readonly message: string
  readonly category: PatternCategory
}

const STATIC_PATTERNS: readonly StaticPattern[] = [
  // Dangerous API calls
  {
    name: 'eval_usage',
    pattern: /\beval\s*[\(\s]/g,
    severity: 'high',
    message: 'eval() usage detected - potential code injection',
    category: 'dangerous_api'
  },
  {
    name: 'exec_usage',
    pattern: /\bexec\s*\(/g,
    severity: 'high',
    message: 'exec() usage detected - command execution',
    category: 'dangerous_api'
  },
  {
    name: 'child_process',
    pattern: /require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]/g,
    severity: 'medium',
    message: 'child_process module usage',
    category: 'dangerous_api'
  },
  {
    name: 'spawn_exec',
    pattern: /\b(?:spawn|execSync|execFileSync|spawnSync)\s*\(/g,
    severity: 'medium',
    message: 'Process spawn/exec detected',
    category: 'dangerous_api'
  },
  {
    name: 'fs_operations',
    pattern: /(?:writeFileSync|appendFileSync|unlinkSync|rmdirSync|rmSync)\s*\(/g,
    severity: 'medium',
    message: 'File system modification detected',
    category: 'dangerous_api'
  },
  {
    name: 'network_fetch',
    pattern: /\b(?:fetch|axios|request|http\.get|https\.get)\s*\(/g,
    severity: 'low',
    message: 'Network request detected',
    category: 'dangerous_api'
  },

  // Obfuscation patterns
  {
    name: 'base64_decode',
    // Limited character count to prevent ReDoS
    pattern: /(?:atob|Buffer\.from)\s*\([^)]{0,200}?(?:,\s*['"]base64['"])?/g,
    severity: 'medium',
    message: 'Base64 decoding detected - potential obfuscation',
    category: 'obfuscation'
  },
  {
    name: 'char_code_obfuscation',
    pattern: /String\.fromCharCode\s*\([^)]{20,}\)/g,
    severity: 'high',
    message: 'Character code obfuscation detected',
    category: 'obfuscation'
  },
  {
    name: 'hex_string',
    pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/g,
    severity: 'medium',
    message: 'Hex-encoded string detected',
    category: 'obfuscation'
  },
  {
    name: 'long_one_liner',
    pattern: /^.{500,}$/gm,
    severity: 'low',
    message: 'Suspiciously long line detected',
    category: 'obfuscation'
  },

  // Credential access patterns
  {
    name: 'ssh_access',
    pattern: /~\/\.ssh|\/\.ssh\/|id_rsa|id_ed25519|authorized_keys/g,
    severity: 'critical',
    message: 'SSH credential access pattern detected',
    category: 'credential_access'
  },
  {
    name: 'aws_credentials',
    pattern: /~\/\.aws|\/\.aws\/|aws_access_key|aws_secret/gi,
    severity: 'critical',
    message: 'AWS credential access pattern detected',
    category: 'credential_access'
  },
  {
    name: 'env_file_access',
    pattern: /['"]\.env(?:\.local|\.production|\.development)?['"]/g,
    severity: 'high',
    message: '.env file access detected',
    category: 'credential_access'
  },
  {
    name: 'browser_credentials',
    pattern: /(?:localStorage|sessionStorage|document\.cookie)/g,
    severity: 'medium',
    message: 'Browser credential storage access',
    category: 'credential_access'
  },
  {
    name: 'keychain_access',
    pattern: /(?:keychain|keyring|credential[_-]?store)/gi,
    severity: 'high',
    message: 'System keychain/keyring access pattern',
    category: 'credential_access'
  }
] as const

/** Code file extensions to scan */
const CODE_EXTENSIONS = /\.(js|ts|jsx|tsx|py|rb|sh|bash|go|rs)$/

/** Maximum evidence length in findings */
const MAX_EVIDENCE_LENGTH = 100

/**
 * Static analyzer for detecting dangerous API calls, obfuscation, and credential access
 */
export class StaticAnalyzer extends BaseScanner {
  readonly type = 'static' as const
  readonly name = 'Static Analyzer'

  /**
   * Scan files for dangerous patterns
   * @param context - Scan context containing files and root path
   * @returns Array of findings for detected issues
   */
  async scan(context: ScanContext): Promise<Finding[]> {
    const codeFiles = context.files.filter(f => CODE_EXTENSIONS.test(f))

    const allFindings = await Promise.all(
      codeFiles.map(async (file) => {
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

    for (const staticPattern of STATIC_PATTERNS) {
      const pattern = new RegExp(staticPattern.pattern.source, staticPattern.pattern.flags)

      let match: RegExpExecArray | null
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = this.getLineNumber(content, match.index)
        const rawEvidence = match[0].slice(0, MAX_EVIDENCE_LENGTH)
        // Mask evidence for credential access patterns
        const evidence = staticPattern.category === 'credential_access'
          ? maskEvidence(rawEvidence)
          : rawEvidence

        findings.push({
          scanner: this.type,
          severity: staticPattern.severity,
          rule: `static_${staticPattern.name}`,
          message: staticPattern.message,
          location: {
            file: relativePath,
            line: lineNumber
          },
          evidence,
          metadata: { category: staticPattern.category }
        })
      }
    }

    return findings
  }

  private getLineNumber(content: string, index: number): number {
    return content.slice(0, index).split('\n').length
  }
}
