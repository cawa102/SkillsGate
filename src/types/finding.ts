/**
 * Severity levels for security findings
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/**
 * Scanner types that can generate findings
 */
export type ScannerType =
  | 'secret'
  | 'dependency'
  | 'static'
  | 'entrypoint'
  | 'ci-risk'
  | 'skill'

/**
 * Location information for a finding
 */
export interface FindingLocation {
  file: string
  line?: number
  column?: number
  endLine?: number
  endColumn?: number
}

/**
 * A single security finding from a scanner
 */
export interface Finding {
  /** Scanner that detected this finding */
  scanner: ScannerType

  /** Severity level */
  severity: Severity

  /** Rule identifier that triggered this finding */
  rule: string

  /** Human-readable message describing the finding */
  message: string

  /** Location where the finding was detected */
  location: FindingLocation

  /** Evidence (masked if contains sensitive data) */
  evidence?: string

  /** Additional metadata */
  metadata?: Record<string, unknown>
}

/**
 * Summary of findings by severity
 */
export interface FindingSummary {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

/**
 * Result from a single scanner
 */
export interface ScannerResult {
  scanner: ScannerType
  findings: Finding[]
  duration: number
  error?: string
}
