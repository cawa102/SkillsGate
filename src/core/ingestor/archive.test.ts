import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, rm, writeFile } from 'fs/promises'
import { join } from 'path'
import { execSync } from 'child_process'
import { ArchiveIngestor } from './archive.js'

const TEST_DIR = '/tmp/skillgate-test-archive-ingestor'
const SOURCE_DIR = join(TEST_DIR, 'source')
const ARCHIVE_DIR = join(TEST_DIR, 'archives')
const WORK_DIR = join(TEST_DIR, 'work')

/**
 * Helper to create test source files
 */
async function createSourceFiles(): Promise<void> {
  await mkdir(join(SOURCE_DIR, 'src'), { recursive: true })
  await writeFile(join(SOURCE_DIR, 'README.md'), '# Test Project')
  await writeFile(join(SOURCE_DIR, 'package.json'), '{"name": "test"}')
  await writeFile(join(SOURCE_DIR, 'src', 'index.ts'), 'export const foo = 1')
}

/**
 * Create a zip archive
 */
function createZipArchive(name: string): string {
  const archivePath = join(ARCHIVE_DIR, name)
  execSync(`cd "${SOURCE_DIR}" && zip -r "${archivePath}" .`, { stdio: 'pipe' })
  return archivePath
}

/**
 * Create a tar archive
 */
function createTarArchive(name: string): string {
  const archivePath = join(ARCHIVE_DIR, name)
  execSync(`tar -cf "${archivePath}" -C "${SOURCE_DIR}" .`, { stdio: 'pipe' })
  return archivePath
}

/**
 * Create a tar.gz archive
 */
function createTarGzArchive(name: string): string {
  const archivePath = join(ARCHIVE_DIR, name)
  execSync(`tar -czf "${archivePath}" -C "${SOURCE_DIR}" .`, { stdio: 'pipe' })
  return archivePath
}

describe('ArchiveIngestor', () => {
  beforeEach(async () => {
    await mkdir(SOURCE_DIR, { recursive: true })
    await mkdir(ARCHIVE_DIR, { recursive: true })
    await mkdir(WORK_DIR, { recursive: true })
    await createSourceFiles()
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('zip archives', () => {
    it('should extract and ingest a zip archive', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.success).toBe(true)
      expect(result.context).toBeDefined()
      expect(result.context?.fileCount).toBe(3)
    })

    it('should detect zip format in metadata', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.archiveFormat).toBe('zip')
    })

    it('should collect all files from zip', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      const paths = result.context?.files.map(f => f.path).sort()
      expect(paths).toContain('README.md')
      expect(paths).toContain('package.json')
      expect(paths).toContain('src/index.ts')
    })
  })

  describe('tar archives', () => {
    it('should extract and ingest a tar archive', async () => {
      const archivePath = createTarArchive('test.tar')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.success).toBe(true)
      expect(result.context?.fileCount).toBe(3)
    })

    it('should detect tar format in metadata', async () => {
      const archivePath = createTarArchive('test.tar')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.archiveFormat).toBe('tar')
    })
  })

  describe('tar.gz archives', () => {
    it('should extract and ingest a tar.gz archive', async () => {
      const archivePath = createTarGzArchive('test.tar.gz')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.success).toBe(true)
      expect(result.context?.fileCount).toBe(3)
    })

    it('should detect tar.gz format in metadata', async () => {
      const archivePath = createTarGzArchive('test.tar.gz')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.archiveFormat).toBe('tar.gz')
    })

    it('should handle .tgz extension', async () => {
      const archivePath = createTarGzArchive('test.tgz')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.success).toBe(true)
      expect(result.context?.metadata.archiveFormat).toBe('tgz')
    })
  })

  describe('error handling', () => {
    it('should return error for non-existent file', async () => {
      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: '/nonexistent/archive.zip'
      })

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })

    it('should return error for unsupported format', async () => {
      const invalidPath = join(ARCHIVE_DIR, 'test.rar')
      await writeFile(invalidPath, 'fake rar content')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: invalidPath
      })

      expect(result.success).toBe(false)
      expect(result.error).toContain('Unsupported archive format')
    })

    it('should return error for corrupted archive', async () => {
      const corruptPath = join(ARCHIVE_DIR, 'corrupt.zip')
      await writeFile(corruptPath, 'not a valid zip file')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: corruptPath
      })

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })
  })

  describe('metadata', () => {
    it('should set source type to archive', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.type).toBe('archive')
    })

    it('should record original location', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.originalLocation).toBe(archivePath)
    })

    it('should not have git-specific metadata', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.context?.metadata.commitSha).toBeUndefined()
      expect(result.context?.metadata.ref).toBeUndefined()
    })
  })

  describe('cleanup', () => {
    it('should clean up extracted directory by default', async () => {
      const archivePath = createZipArchive('test.zip')

      const ingestor = new ArchiveIngestor({ workDir: WORK_DIR, cleanup: true })
      const result = await ingestor.ingest({
        type: 'archive',
        location: archivePath
      })

      expect(result.success).toBe(true)
    })
  })
})
