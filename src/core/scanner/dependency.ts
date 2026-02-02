import { BaseScanner, type ScanContext } from './base.js'
import type { Finding, Severity } from '../../types/index.js'
import { readFileContent } from './utils.js'

interface ParsedDependencies {
  name: string
  ecosystem: string
  dependencies: Array<{
    name: string
    version: string
    dev?: boolean
  }>
}

interface DependencyFile {
  pattern: RegExp
  lockFile?: string
  ecosystem: string
  parser: (content: string) => ParsedDependencies
}

interface OSVVulnerability {
  id: string
  summary: string
  severity?: Array<{
    type: string
    score: string
  }>
  affected?: Array<{
    package: { name: string; ecosystem: string }
    ranges?: Array<{
      type: string
      events: Array<{ introduced?: string; fixed?: string }>
    }>
  }>
}

interface OSVResponse {
  vulns?: OSVVulnerability[]
}

interface VulnerabilityResult {
  id: string
  summary: string
  severity: string
  package: string
  version: string
}

// Parser functions
function parsePackageJson(content: string): ParsedDependencies {
  const pkg = JSON.parse(content) as {
    name?: string
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }
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

  return { name: pkg.name || 'unknown', ecosystem: 'npm', dependencies: deps }
}

function parseRequirementsTxt(content: string): ParsedDependencies {
  const deps: Array<{ name: string; version: string }> = []
  const lines = content.split('\n')

  for (const line of lines) {
    const trimmed = line.trim()
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue

    const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:[=<>~!]+(.+))?/)
    if (match) {
      deps.push({ name: match[1], version: match[2] || '*' })
    }
  }

  return { name: 'python-project', ecosystem: 'PyPI', dependencies: deps }
}

function parseGoMod(content: string): ParsedDependencies {
  const deps: Array<{ name: string; version: string }> = []
  const seen = new Set<string>()

  // Match require blocks
  const requireBlockMatch = content.match(/require\s*\(([\s\S]*?)\)/g)
  if (requireBlockMatch) {
    for (const block of requireBlockMatch) {
      // Extract only the content inside parentheses
      const innerContent = block.replace(/require\s*\(/, '').replace(/\)$/, '')
      const lines = innerContent.split('\n')
      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('//')) continue
        const match = trimmed.match(/^([^\s]+)\s+v?([^\s]+)/)
        if (match) {
          const key = `${match[1]}@${match[2]}`
          if (!seen.has(key)) {
            seen.add(key)
            deps.push({ name: match[1], version: match[2] })
          }
        }
      }
    }
  }

  // Match single-line require (only if no block was found for this dep)
  const singleRequires = content.matchAll(/^require\s+([^\s(]+)\s+v?([^\s]+)/gm)
  for (const match of singleRequires) {
    const key = `${match[1]}@${match[2]}`
    if (!seen.has(key)) {
      seen.add(key)
      deps.push({ name: match[1], version: match[2] })
    }
  }

  return { name: 'go-module', ecosystem: 'Go', dependencies: deps }
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
      // Simple version: name = "version"
      const simpleMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/)
      if (simpleMatch) {
        deps.push({ name: simpleMatch[1], version: simpleMatch[2] })
        continue
      }
      // Table version: name = { version = "version" }
      const tableMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/)
      if (tableMatch) {
        deps.push({ name: tableMatch[1], version: tableMatch[2] })
      }
    }
  }

  return { name: 'rust-crate', ecosystem: 'crates.io', dependencies: deps }
}

const DEPENDENCY_FILES: DependencyFile[] = [
  {
    pattern: /package\.json$/,
    lockFile: 'package-lock.json',
    ecosystem: 'npm',
    parser: parsePackageJson
  },
  {
    pattern: /requirements\.txt$/,
    ecosystem: 'PyPI',
    parser: parseRequirementsTxt
  },
  {
    pattern: /go\.mod$/,
    lockFile: 'go.sum',
    ecosystem: 'Go',
    parser: parseGoMod
  },
  {
    pattern: /Cargo\.toml$/,
    lockFile: 'Cargo.lock',
    ecosystem: 'crates.io',
    parser: parseCargoToml
  }
]

/**
 * Dependency Scanner
 *
 * Scans dependency files for:
 * - Missing lock files
 * - Known vulnerabilities via OSV API
 *
 * Supported formats:
 * - package.json (npm)
 * - requirements.txt (PyPI)
 * - go.mod (Go)
 * - Cargo.toml (crates.io)
 */
export class DependencyScanner extends BaseScanner {
  readonly type = 'dependency' as const
  readonly name = 'Dependency Scanner'

  private osvApiUrl = 'https://api.osv.dev/v1/query'
  private enableOsvApi: boolean

  constructor(options?: { enableOsvApi?: boolean }) {
    super()
    this.enableOsvApi = options?.enableOsvApi ?? true
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    for (const depFile of DEPENDENCY_FILES) {
      const matchingFiles = context.files.filter((f) => depFile.pattern.test(f))

      for (const file of matchingFiles) {
        const content = await readFileContent(file)
        if (!content) continue

        const relativePath = this.getRelativePath(file, context.rootPath)

        try {
          const parsed = depFile.parser(content)

          // Check for lock file existence
          if (depFile.lockFile) {
            const lockExists = context.files.some((f) =>
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
          if (this.enableOsvApi && parsed.dependencies.length > 0) {
            const vulns = await this.checkVulnerabilities(
              parsed.dependencies,
              parsed.ecosystem
            )
            for (const v of vulns) {
              findings.push({
                scanner: this.type,
                severity: this.mapSeverity(v.severity),
                rule: `dependency_vuln_${v.id.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
                message: `${v.summary} (${v.id})`,
                location: { file: relativePath },
                metadata: {
                  vulnId: v.id,
                  package: v.package,
                  version: v.version
                }
              })
            }
          }
        } catch {
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
    deps: Array<{ name: string; version: string }>,
    ecosystem: string
  ): Promise<VulnerabilityResult[]> {
    const results: VulnerabilityResult[] = []

    // Query OSV API for each dependency
    for (const dep of deps) {
      // Skip version ranges for now (only check exact versions)
      const version = this.normalizeVersion(dep.version)
      if (!version) continue

      try {
        const response = await fetch(this.osvApiUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            package: { name: dep.name, ecosystem },
            version
          })
        })

        if (response.ok) {
          const data = (await response.json()) as OSVResponse
          if (data.vulns) {
            for (const vuln of data.vulns) {
              results.push({
                id: vuln.id,
                summary: vuln.summary || 'No description available',
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

  private normalizeVersion(version: string): string | null {
    // Remove common prefixes
    const cleaned = version.replace(/^[~^>=<]+/, '').trim()

    // Skip wildcards
    if (cleaned === '*' || cleaned === 'latest') return null

    return cleaned || null
  }

  private extractSeverity(vuln: OSVVulnerability): string {
    if (vuln.severity && vuln.severity.length > 0) {
      // Try to find CVSS score
      const cvss = vuln.severity.find((s) => s.type === 'CVSS_V3')
      if (cvss) {
        const score = parseFloat(cvss.score)
        if (score >= 9.0) return 'CRITICAL'
        if (score >= 7.0) return 'HIGH'
        if (score >= 4.0) return 'MEDIUM'
        return 'LOW'
      }
    }
    return 'UNKNOWN'
  }

  private mapSeverity(severity: string): Severity {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'critical'
      case 'HIGH':
        return 'high'
      case 'MEDIUM':
      case 'MODERATE':
        return 'medium'
      case 'LOW':
        return 'low'
      default:
        return 'info'
    }
  }

  private getRelativePath(file: string, rootPath: string): string {
    if (file.startsWith(rootPath)) {
      return file.slice(rootPath.length + 1)
    }
    return file
  }
}

/**
 * Create a new DependencyScanner instance
 */
export function createDependencyScanner(options?: {
  enableOsvApi?: boolean
}): DependencyScanner {
  return new DependencyScanner(options)
}

// Export parsers for testing
export const parsers = {
  parsePackageJson,
  parseRequirementsTxt,
  parseGoMod,
  parseCargoToml
}
