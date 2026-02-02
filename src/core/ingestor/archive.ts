import { exec } from 'child_process'
import { mkdir, rm, stat } from 'fs/promises'
import { join, extname, basename } from 'path'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import { BaseIngestor } from './base.js'
import type {
  IngestContext,
  IngestorOptions,
  IngestorSource,
  SourceMetadata
} from './types.js'

const execAsync = promisify(exec)

type ArchiveFormat = 'zip' | 'tar' | 'tar.gz' | 'tgz'

/**
 * Ingestor for archive files (zip, tar, tar.gz, tgz)
 */
export class ArchiveIngestor extends BaseIngestor {
  constructor(options?: IngestorOptions) {
    super('archive', options)
  }

  /**
   * Ingest an archive file
   */
  protected async doIngest(source: IngestorSource): Promise<IngestContext> {
    const { location } = source

    await this.validateArchive(location)

    const format = this.detectFormat(location)
    const extractDir = await this.createExtractDir()

    try {
      await this.extractArchive(location, extractDir, format)

      const metadata = this.createMetadata(source, {
        archiveFormat: format
      })

      const context = await this.buildContext(extractDir, metadata)

      if (this.options.cleanup) {
        await this.cleanup(extractDir)
      }

      return context
    } catch (err) {
      await this.cleanup(extractDir)
      throw err
    }
  }

  /**
   * Validate that the archive file exists
   */
  private async validateArchive(path: string): Promise<void> {
    try {
      const stats = await stat(path)
      if (!stats.isFile()) {
        throw new Error(`Path is not a file: ${path}`)
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException
      if (error.code === 'ENOENT') {
        throw new Error(`Archive file does not exist: ${path}`)
      }
      throw err
    }
  }

  /**
   * Detect archive format from file extension
   */
  private detectFormat(filePath: string): ArchiveFormat {
    const fileName = basename(filePath).toLowerCase()

    if (fileName.endsWith('.tar.gz')) {
      return 'tar.gz'
    }
    if (fileName.endsWith('.tgz')) {
      return 'tgz'
    }
    if (fileName.endsWith('.tar')) {
      return 'tar'
    }
    if (fileName.endsWith('.zip')) {
      return 'zip'
    }

    throw new Error(`Unsupported archive format: ${extname(filePath)}`)
  }

  /**
   * Create a unique directory for extraction
   */
  private async createExtractDir(): Promise<string> {
    const dirName = `sg-archive-${randomUUID().slice(0, 8)}`
    const extractDir = join(this.options.workDir, dirName)
    await mkdir(extractDir, { recursive: true })
    return extractDir
  }

  /**
   * Extract archive to the specified directory
   */
  private async extractArchive(
    archivePath: string,
    destDir: string,
    format: ArchiveFormat
  ): Promise<void> {
    try {
      const command = this.getExtractCommand(archivePath, destDir, format)
      await execAsync(command, { timeout: this.options.timeout })
    } catch (err) {
      const error = err as Error & { stderr?: string }
      const message = error.stderr || error.message
      throw new Error(`Failed to extract archive: ${message}`)
    }
  }

  /**
   * Get the appropriate extraction command for the format
   */
  private getExtractCommand(
    archivePath: string,
    destDir: string,
    format: ArchiveFormat
  ): string {
    switch (format) {
      case 'zip':
        return `unzip -q "${archivePath}" -d "${destDir}"`
      case 'tar':
        return `tar -xf "${archivePath}" -C "${destDir}"`
      case 'tar.gz':
      case 'tgz':
        return `tar -xzf "${archivePath}" -C "${destDir}"`
    }
  }

  /**
   * Clean up the extracted directory
   */
  private async cleanup(dir: string): Promise<void> {
    try {
      await rm(dir, { recursive: true, force: true })
    } catch {
      // Ignore cleanup errors
    }
  }

  /**
   * Override createMetadata to include archive-specific fields
   */
  protected override createMetadata(
    source: IngestorSource,
    extra?: Partial<SourceMetadata>
  ): SourceMetadata {
    return {
      type: 'archive',
      originalLocation: source.location,
      ingestedAt: new Date().toISOString(),
      ...extra
    }
  }
}
