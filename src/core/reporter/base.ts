import type { ScanReport, ReportOptions } from '../../types/index.js'

/**
 * Base interface for all reporters
 */
export interface Reporter {
  /**
   * Generate a report from scan results
   */
  generate(report: ScanReport, options?: Partial<ReportOptions>): string

  /**
   * Write report to file or stdout
   */
  write(report: ScanReport, options?: Partial<ReportOptions>): Promise<void>
}

/**
 * Extended report options with format-specific settings
 */
export interface JsonReportOptions extends ReportOptions {
  /** Pretty print JSON with indentation */
  pretty?: boolean
  /** Mask sensitive data in evidence fields */
  maskSecrets?: boolean
}
