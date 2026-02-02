import { writeFile } from 'node:fs/promises'
import type { ScanReport } from '../../types/index.js'
import { maskFindingEvidence } from '../../utils/mask.js'
import type { Reporter, JsonReportOptions } from './base.js'

/**
 * Mask sensitive data in a scan report
 */
function maskReport(report: ScanReport): ScanReport {
  return {
    ...report,
    findings: report.findings.map(maskFindingEvidence)
  }
}

/**
 * JSON Reporter for scan results
 *
 * Outputs scan reports in JSON format for machine consumption.
 * Automatically masks sensitive data in evidence fields.
 */
export class JsonReporter implements Reporter {
  private readonly defaultOptions: JsonReportOptions = {
    format: 'json',
    pretty: true,
    maskSecrets: true
  }

  /**
   * Generate JSON string from scan report
   */
  generate(report: ScanReport, options?: Partial<JsonReportOptions>): string {
    const opts = { ...this.defaultOptions, ...options }

    const outputReport = opts.maskSecrets ? maskReport(report) : report

    if (opts.pretty) {
      return JSON.stringify(outputReport, null, 2)
    }

    return JSON.stringify(outputReport)
  }

  /**
   * Write report to file or stdout
   */
  async write(report: ScanReport, options?: Partial<JsonReportOptions>): Promise<void> {
    const opts = { ...this.defaultOptions, ...options }
    const json = this.generate(report, opts)

    if (opts.output) {
      await writeFile(opts.output, json, 'utf-8')
    } else if (!opts.quiet) {
      process.stdout.write(json + '\n')
    }
  }
}

/**
 * Create a new JSON reporter instance
 */
export function createJsonReporter(): JsonReporter {
  return new JsonReporter()
}
