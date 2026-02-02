import type { Finding, ScannerResult, ScannerType, Policy } from '../../types/index.js'

/**
 * Context provided to scanners during execution
 */
export interface ScanContext {
  /** Root path of the project being scanned */
  rootPath: string
  /** List of files to scan */
  files: string[]
  /** Optional policy for filtering/configuration */
  policy?: Policy
}

/**
 * Abstract base class for all scanners
 * All scanner implementations must extend this class
 */
export abstract class BaseScanner {
  /** Unique identifier for this scanner type */
  abstract readonly type: ScannerType
  /** Human-readable name of this scanner */
  abstract readonly name: string

  /**
   * Perform the actual scan logic
   * Implementations must override this method
   * @param context - Scan context with files and configuration
   * @returns Array of findings detected by this scanner
   */
  abstract scan(context: ScanContext): Promise<Finding[]>

  /**
   * Execute the scanner with error handling and timing
   * @param context - Scan context with files and configuration
   * @returns Scanner result with findings, duration, and potential error
   */
  async execute(context: ScanContext): Promise<ScannerResult> {
    const start = Date.now()
    try {
      const findings = await this.scan(context)
      return {
        scanner: this.type,
        findings,
        duration: Date.now() - start
      }
    } catch (error) {
      return {
        scanner: this.type,
        findings: [],
        duration: Date.now() - start,
        error: error instanceof Error ? error.message : String(error)
      }
    }
  }
}
