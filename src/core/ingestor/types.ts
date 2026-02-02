/**
 * Source types for ingestion
 */
export type SourceType = 'local' | 'git' | 'archive'

/**
 * Input source specification
 */
export interface IngestorSource {
  /** Type of source */
  type: SourceType

  /** Path, URL, or archive location */
  location: string

  /** Git-specific: branch, tag, or commit SHA */
  ref?: string
}

/**
 * Options for ingestion process
 */
export interface IngestorOptions {
  /** Working directory for temporary files */
  workDir?: string

  /** Whether to clean up temporary files after ingestion */
  cleanup?: boolean

  /** Timeout in milliseconds */
  timeout?: number

  /** Files/directories to exclude (glob patterns) */
  exclude?: string[]
}

/**
 * Metadata about the ingested source
 */
export interface SourceMetadata {
  /** Type of source that was ingested */
  type: SourceType

  /** Original location/URL */
  originalLocation: string

  /** Git commit SHA (if applicable) */
  commitSha?: string

  /** Git branch or tag (if applicable) */
  ref?: string

  /** Archive format (if applicable) */
  archiveFormat?: 'zip' | 'tar' | 'tar.gz' | 'tgz'

  /** Timestamp of ingestion */
  ingestedAt: string
}

/**
 * A single file in the ingested source
 */
export interface IngestedFile {
  /** Relative path from root */
  path: string

  /** Absolute path on filesystem */
  absolutePath: string

  /** File size in bytes */
  size: number

  /** SHA-256 hash of file content */
  hash: string
}

/**
 * Context produced by ingestion, used by scanners
 */
export interface IngestContext {
  /** Root directory of ingested source */
  rootDir: string

  /** SHA-256 hash of entire source */
  sourceHash: string

  /** List of all files */
  files: IngestedFile[]

  /** Metadata about the source */
  metadata: SourceMetadata

  /** Total size in bytes */
  totalSize: number

  /** Total file count */
  fileCount: number
}

/**
 * Result of ingestion operation
 */
export interface IngestResult {
  /** Whether ingestion was successful */
  success: boolean

  /** Context for scanners (if successful) */
  context?: IngestContext

  /** Error message (if failed) */
  error?: string

  /** Duration in milliseconds */
  duration: number
}
