import { readFile, readdir, stat } from 'fs/promises'
import { join, relative } from 'path'
import { createHash } from 'crypto'
import type {
  IngestContext,
  IngestResult,
  IngestedFile,
  IngestorOptions,
  IngestorSource,
  SourceMetadata,
  SourceType
} from './types.js'

/**
 * Default options for ingestion
 */
const DEFAULT_OPTIONS: Required<IngestorOptions> = {
  workDir: '/tmp/skillgate',
  cleanup: true,
  timeout: 60000,
  exclude: [
    'node_modules',
    '.git',
    '__pycache__',
    '.pytest_cache',
    'dist',
    'build',
    '.next',
    'coverage'
  ]
}

/**
 * Default file size limit (50MB)
 */
const MAX_FILE_SIZE = 50 * 1024 * 1024

/**
 * Abstract base class for all ingestors
 */
export abstract class BaseIngestor {
  protected readonly options: Required<IngestorOptions>
  protected readonly sourceType: SourceType

  constructor(sourceType: SourceType, options?: IngestorOptions) {
    this.sourceType = sourceType
    this.options = { ...DEFAULT_OPTIONS, ...options }
  }

  /**
   * Main entry point for ingestion
   * Handles timing, error handling, and calls the concrete implementation
   */
  async ingest(source: IngestorSource): Promise<IngestResult> {
    const startTime = Date.now()

    try {
      const context = await this.doIngest(source)
      return {
        success: true,
        context,
        duration: Date.now() - startTime
      }
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err)
      return {
        success: false,
        error,
        duration: Date.now() - startTime
      }
    }
  }

  /**
   * Abstract method to be implemented by concrete ingestors
   */
  protected abstract doIngest(source: IngestorSource): Promise<IngestContext>

  /**
   * Build IngestContext from a root directory
   */
  protected async buildContext(
    rootDir: string,
    metadata: SourceMetadata
  ): Promise<IngestContext> {
    const files = await this.collectFiles(rootDir)
    const sourceHash = await this.computeSourceHash(files)
    const totalSize = files.reduce((sum, f) => sum + f.size, 0)

    return {
      rootDir,
      sourceHash,
      files,
      metadata,
      totalSize,
      fileCount: files.length
    }
  }

  /**
   * Recursively collect all files from a directory
   */
  protected async collectFiles(
    rootDir: string,
    currentDir?: string
  ): Promise<IngestedFile[]> {
    const dir = currentDir ?? rootDir
    const files: IngestedFile[] = []

    const entries = await readdir(dir, { withFileTypes: true })

    for (const entry of entries) {
      const absolutePath = join(dir, entry.name)
      const relativePath = relative(rootDir, absolutePath)

      if (this.shouldExclude(entry.name, relativePath)) {
        continue
      }

      if (entry.isDirectory()) {
        const subFiles = await this.collectFiles(rootDir, absolutePath)
        files.push(...subFiles)
      } else if (entry.isFile()) {
        const fileInfo = await this.processFile(absolutePath, relativePath)
        if (fileInfo) {
          files.push(fileInfo)
        }
      }
    }

    return files
  }

  /**
   * Process a single file and return its info
   */
  private async processFile(
    absolutePath: string,
    relativePath: string
  ): Promise<IngestedFile | null> {
    try {
      const stats = await stat(absolutePath)

      if (stats.size > MAX_FILE_SIZE) {
        return null
      }

      const content = await readFile(absolutePath)
      const hash = createHash('sha256').update(content).digest('hex')

      return {
        path: relativePath,
        absolutePath,
        size: stats.size,
        hash
      }
    } catch {
      return null
    }
  }

  /**
   * Check if a file/directory should be excluded
   */
  protected shouldExclude(name: string, relativePath: string): boolean {
    // Allow .github directory but exclude other hidden files/directories
    if (name.startsWith('.')) {
      if (name === '.github' || relativePath.startsWith('.github/')) {
        return false
      }
      return true
    }

    for (const pattern of this.options.exclude) {
      // Check if name matches pattern exactly
      if (name === pattern) {
        return true
      }
      // Check if any path segment matches pattern exactly
      const segments = relativePath.split('/')
      if (segments.some(segment => segment === pattern)) {
        return true
      }
    }

    return false
  }

  /**
   * Compute a deterministic hash of all files
   */
  private async computeSourceHash(files: IngestedFile[]): Promise<string> {
    const hash = createHash('sha256')

    const sortedFiles = [...files].sort((a, b) => a.path.localeCompare(b.path))

    for (const file of sortedFiles) {
      hash.update(file.path)
      hash.update(file.hash)
    }

    return hash.digest('hex')
  }

  /**
   * Create base metadata
   */
  protected createMetadata(
    source: IngestorSource,
    extra?: Partial<SourceMetadata>
  ): SourceMetadata {
    return {
      type: this.sourceType,
      originalLocation: source.location,
      ingestedAt: new Date().toISOString(),
      ...extra
    }
  }
}
