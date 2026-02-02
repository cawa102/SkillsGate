import { writeFile } from 'node:fs/promises'
import type { ScanReport, Finding, Severity } from '../../types/index.js'
import { maskFindingEvidence } from '../../utils/mask.js'
import type { Reporter, JsonReportOptions } from './base.js'

/**
 * Extended report options for Markdown reporter
 */
export type MarkdownReportOptions = JsonReportOptions

/**
 * Get decision emoji and label
 */
function getDecisionBadge(decision: string): { emoji: string; label: string } {
  const badges: Record<string, { emoji: string; label: string }> = {
    allow: { emoji: '✅', label: 'ALLOW' },
    block: { emoji: '🚫', label: 'BLOCK' },
    quarantine: { emoji: '⚠️', label: 'QUARANTINE' }
  }
  return badges[decision] ?? { emoji: '❓', label: decision.toUpperCase() }
}

/**
 * Get severity emoji
 */
function getSeverityEmoji(severity: Severity): string {
  const emojis: Record<Severity, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: 'ℹ️'
  }
  return emojis[severity]
}

/**
 * Format duration in seconds
 */
function formatDuration(ms: number): string {
  return (ms / 1000).toFixed(2)
}

/**
 * Group findings by severity
 */
function groupFindingsBySeverity(findings: readonly Finding[]): Map<Severity, Finding[]> {
  const groups = new Map<Severity, Finding[]>()
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

  for (const severity of severityOrder) {
    groups.set(severity, [])
  }

  for (const finding of findings) {
    const group = groups.get(finding.severity)
    if (group) {
      group.push(finding)
    }
  }

  return groups
}

/**
 * Generate source information section
 */
function generateSourceSection(report: ScanReport): string {
  const lines: string[] = [
    '## Source Information',
    '',
    '| Property | Value |',
    '|----------|-------|',
    `| Type | ${report.source.type} |`,
    `| Path | \`${report.source.path}\` |`
  ]

  if (report.source.url) {
    lines.push(`| URL | ${report.source.url} |`)
  }

  if (report.source.commit) {
    lines.push(`| Commit | \`${report.source.commit}\` |`)
  }

  lines.push(`| Hash | \`${report.source.hash}\` |`)
  lines.push('')

  return lines.join('\n')
}

/**
 * Generate summary section
 */
function generateSummarySection(report: ScanReport): string {
  const lines: string[] = [
    '## Summary',
    '',
    '| Metric | Value |',
    '|--------|-------|',
    `| Score | **${report.score}**/100 |`,
    `| Policy | ${report.policyName} |`,
    `| Duration | ${formatDuration(report.duration)}s |`,
    '',
    '### Findings by Severity',
    '',
    '| Severity | Count |',
    '|----------|-------|',
    `| 🔴 Critical | ${report.summary.critical} |`,
    `| 🟠 High | ${report.summary.high} |`,
    `| 🟡 Medium | ${report.summary.medium} |`,
    `| 🔵 Low | ${report.summary.low} |`,
    `| ℹ️ Info | ${report.summary.info} |`,
    ''
  ]

  return lines.join('\n')
}

/**
 * Generate finding item
 */
function generateFindingItem(finding: Finding, maskSecrets: boolean): string {
  const processedFinding = maskSecrets ? maskFindingEvidence(finding) : finding
  const location = processedFinding.location.line
    ? `${processedFinding.location.file}:${processedFinding.location.line}`
    : processedFinding.location.file

  const lines: string[] = [
    `#### ${processedFinding.rule}`,
    '',
    `**Scanner:** ${processedFinding.scanner}`,
    `**Location:** \`${location}\``,
    '',
    processedFinding.message
  ]

  if (processedFinding.evidence) {
    lines.push('', '```', processedFinding.evidence, '```')
  }

  lines.push('')

  return lines.join('\n')
}

/**
 * Generate findings section
 */
function generateFindingsSection(findings: readonly Finding[], maskSecrets: boolean): string {
  if (findings.length === 0) {
    return '## Findings\n\n✅ No security issues found.\n'
  }

  const lines: string[] = ['## Findings', '']
  const grouped = groupFindingsBySeverity(findings)

  for (const [severity, severityFindings] of grouped) {
    if (severityFindings.length === 0) {
      continue
    }

    const emoji = getSeverityEmoji(severity)
    lines.push(`### ${emoji} ${severity.charAt(0).toUpperCase() + severity.slice(1)} (${severityFindings.length})`)
    lines.push('')

    for (const finding of severityFindings) {
      lines.push(generateFindingItem(finding, maskSecrets))
    }
  }

  return lines.join('\n')
}

/**
 * Generate critical block rules section
 */
function generateCriticalBlockSection(rules: readonly string[]): string {
  if (rules.length === 0) {
    return ''
  }

  const lines: string[] = [
    '## Critical Block Rules Triggered',
    '',
    'The following rules caused an immediate block:',
    ''
  ]

  for (const rule of rules) {
    lines.push(`- \`${rule}\``)
  }

  lines.push('')

  return lines.join('\n')
}

/**
 * Generate errors section
 */
function generateErrorsSection(errors: readonly string[]): string {
  if (errors.length === 0) {
    return ''
  }

  const lines: string[] = [
    '## Errors',
    '',
    'The following errors occurred during scanning:',
    ''
  ]

  for (const error of errors) {
    lines.push(`- ${error}`)
  }

  lines.push('')

  return lines.join('\n')
}

/**
 * Markdown Reporter for scan results
 *
 * Outputs scan reports in Markdown format for human consumption.
 * Automatically masks sensitive data in evidence fields.
 */
export class MarkdownReporter implements Reporter {
  private readonly defaultOptions: MarkdownReportOptions = {
    format: 'markdown',
    maskSecrets: true
  }

  /**
   * Generate Markdown string from scan report
   */
  generate(report: ScanReport, options?: Partial<MarkdownReportOptions>): string {
    const opts = { ...this.defaultOptions, ...options }
    const { emoji, label } = getDecisionBadge(report.decision)

    const sections: string[] = [
      '# SkillGate Security Report',
      '',
      `**Decision:** ${emoji} **${label}**`,
      '',
      `*Generated: ${report.timestamp}*`,
      `*Version: ${report.version}*`,
      '',
      '---',
      '',
      generateSourceSection(report),
      generateSummarySection(report),
      generateCriticalBlockSection(report.criticalBlockRules),
      generateFindingsSection(report.findings, opts.maskSecrets ?? true),
      generateErrorsSection(report.errors),
      '---',
      '',
      '*Report generated by SkillGate*'
    ]

    return sections.filter(Boolean).join('\n')
  }

  /**
   * Write report to file or stdout
   */
  async write(report: ScanReport, options?: Partial<MarkdownReportOptions>): Promise<void> {
    const opts = { ...this.defaultOptions, ...options }
    const markdown = this.generate(report, opts)

    if (opts.output) {
      await writeFile(opts.output, markdown, 'utf-8')
    } else if (!opts.quiet) {
      process.stdout.write(markdown + '\n')
    }
  }
}

/**
 * Create a new Markdown reporter instance
 */
export function createMarkdownReporter(): MarkdownReporter {
  return new MarkdownReporter()
}
