import { exec } from 'child_process'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import { BaseIngestor } from './base.js'
import type {
  IngestContext,
  IngestorOptions,
  IngestorSource
} from './types.js'

const execAsync = promisify(exec)

/**
 * Ingestor for Git repositories
 */
export class GitIngestor extends BaseIngestor {
  constructor(options?: IngestorOptions) {
    super('git', options)
  }

  /**
   * Ingest a Git repository
   */
  protected async doIngest(source: IngestorSource): Promise<IngestContext> {
    const { location, ref } = source
    const cloneDir = await this.createCloneDir()

    try {
      await this.cloneRepository(location, cloneDir, ref)

      if (ref) {
        await this.checkoutRef(cloneDir, ref)
      }

      const commitSha = await this.getCommitSha(cloneDir)

      const metadata = this.createMetadata(source, {
        commitSha,
        ref
      })

      const context = await this.buildContext(cloneDir, metadata)

      if (this.options.cleanup) {
        await this.cleanup(cloneDir)
      }

      return context
    } catch (err) {
      await this.cleanup(cloneDir)
      throw err
    }
  }

  /**
   * Create a unique directory for cloning
   */
  private async createCloneDir(): Promise<string> {
    const dirName = `sg-git-${randomUUID().slice(0, 8)}`
    const cloneDir = join(this.options.workDir, dirName)
    await mkdir(cloneDir, { recursive: true })
    return cloneDir
  }

  /**
   * Clone a repository to the specified directory
   */
  private async cloneRepository(url: string, destDir: string, ref?: string): Promise<void> {
    try {
      // Use full clone if ref is specified (needed for branches/tags)
      // Use shallow clone for default branch only
      const depthFlag = ref ? '' : '--depth 1'
      await execAsync(`git clone ${depthFlag} "${url}" "${destDir}"`, {
        timeout: this.options.timeout
      })
    } catch (err) {
      const error = err as Error & { stderr?: string }
      const message = error.stderr || error.message
      throw new Error(`Failed to clone repository: ${message}`)
    }
  }

  /**
   * Checkout a specific ref (branch, tag, or commit SHA)
   */
  private async checkoutRef(repoDir: string, ref: string): Promise<void> {
    try {
      // First, fetch all refs if needed for full checkout
      await execAsync('git fetch --all --tags', {
        cwd: repoDir,
        timeout: this.options.timeout
      })

      await execAsync(`git checkout "${ref}"`, {
        cwd: repoDir,
        timeout: this.options.timeout
      })
    } catch (err) {
      const error = err as Error & { stderr?: string }
      const message = error.stderr || error.message
      throw new Error(`Failed to checkout ref '${ref}': ${message}`)
    }
  }

  /**
   * Get the current commit SHA
   */
  private async getCommitSha(repoDir: string): Promise<string> {
    try {
      const { stdout } = await execAsync('git rev-parse HEAD', {
        cwd: repoDir
      })
      return stdout.trim()
    } catch {
      throw new Error('Failed to get commit SHA')
    }
  }

  /**
   * Clean up the cloned directory
   */
  private async cleanup(dir: string): Promise<void> {
    try {
      await rm(dir, { recursive: true, force: true })
    } catch {
      // Ignore cleanup errors
    }
  }
}
