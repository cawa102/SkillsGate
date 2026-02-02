import { stat } from 'fs/promises'
import { BaseIngestor } from './base.js'
import type {
  IngestContext,
  IngestorOptions,
  IngestorSource
} from './types.js'

/**
 * Ingestor for local directories
 */
export class LocalIngestor extends BaseIngestor {
  constructor(options?: IngestorOptions) {
    super('local', options)
  }

  /**
   * Ingest a local directory
   */
  protected async doIngest(source: IngestorSource): Promise<IngestContext> {
    const { location } = source

    await this.validateDirectory(location)

    const metadata = this.createMetadata(source)
    return this.buildContext(location, metadata)
  }

  /**
   * Validate that the path exists and is a directory
   */
  private async validateDirectory(path: string): Promise<void> {
    try {
      const stats = await stat(path)

      if (!stats.isDirectory()) {
        throw new Error(`Path is not a directory: ${path}`)
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes('not a directory')) {
        throw err
      }

      const error = err as NodeJS.ErrnoException
      if (error.code === 'ENOENT') {
        throw new Error(`Directory does not exist: ${path}`)
      }

      throw new Error(`Cannot access directory: ${path}`)
    }
  }
}
