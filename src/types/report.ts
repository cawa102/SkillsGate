import type { Finding, FindingSummary } from './finding.js'

/**
 * Decision made by the enforcer
 */
export type Decision = 'allow' | 'block' | 'quarantine'

/**
 * Source type for the scanned content
 */
export type SourceType = 'git' | 'local' | 'archive'

/**
 * Information about the scanned source
 */
export interface SourceInfo {
  type: SourceType
  path: string
  url?: string
  commit?: string
  hash: string
}

/**
 * Complete scan report
 */
export interface ScanReport {
  /** Report version */
  version: string

  /** Timestamp of the scan */
  timestamp: string

  /** Source information */
  source: SourceInfo

  /** Final decision */
  decision: Decision

  /** Calculated score (0-100) */
  score: number

  /** All findings from scanners */
  findings: Finding[]

  /** Summary of findings by severity */
  summary: FindingSummary

  /** Rules that triggered critical block */
  criticalBlockRules: string[]

  /** Scan duration in milliseconds */
  duration: number

  /** Policy used for evaluation */
  policyName: string

  /** Any errors encountered */
  errors: string[]
}

/**
 * Options for report generation
 */
export interface ReportOptions {
  format: 'json' | 'markdown'
  output?: string
  quiet?: boolean
}
