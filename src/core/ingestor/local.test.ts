import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, rm, writeFile, symlink } from 'fs/promises'
import { join } from 'path'
import { LocalIngestor } from './local.js'

const TEST_DIR = '/tmp/skillgate-test-local-ingestor'

describe('LocalIngestor', () => {
  beforeEach(async () => {
    await mkdir(TEST_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('ingest', () => {
    it('should successfully ingest a local directory', async () => {
      await writeFile(join(TEST_DIR, 'index.ts'), 'export const foo = 1')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.success).toBe(true)
      expect(result.context).toBeDefined()
      expect(result.context?.rootDir).toBe(TEST_DIR)
    })

    it('should return error for non-existent directory', async () => {
      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: '/path/that/does/not/exist'
      })

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })

    it('should return error when path is a file instead of directory', async () => {
      const filePath = join(TEST_DIR, 'file.txt')
      await writeFile(filePath, 'content')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: filePath
      })

      expect(result.success).toBe(false)
      expect(result.error).toContain('not a directory')
    })

    it('should collect all files recursively', async () => {
      await mkdir(join(TEST_DIR, 'src', 'components'), { recursive: true })
      await writeFile(join(TEST_DIR, 'package.json'), '{}')
      await writeFile(join(TEST_DIR, 'src', 'index.ts'), 'export {}')
      await writeFile(join(TEST_DIR, 'src', 'components', 'Button.tsx'), 'export {}')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(3)
      const paths = result.context?.files.map(f => f.path).sort()
      expect(paths).toEqual([
        'package.json',
        'src/components/Button.tsx',
        'src/index.ts'
      ])
    })

    it('should handle empty directory', async () => {
      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.success).toBe(true)
      expect(result.context?.fileCount).toBe(0)
      expect(result.context?.files).toEqual([])
    })
  })

  describe('metadata', () => {
    it('should set source type to local', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.metadata.type).toBe('local')
    })

    it('should record original location', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.metadata.originalLocation).toBe(TEST_DIR)
    })

    it('should not have git-specific metadata', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.metadata.commitSha).toBeUndefined()
      expect(result.context?.metadata.ref).toBeUndefined()
    })
  })

  describe('options', () => {
    it('should respect custom exclude patterns', async () => {
      await mkdir(join(TEST_DIR, 'logs'), { recursive: true })
      await writeFile(join(TEST_DIR, 'logs', 'debug.log'), 'log data')
      await writeFile(join(TEST_DIR, 'app.ts'), 'code')

      const ingestor = new LocalIngestor({ exclude: ['logs'] })
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('app.ts')
    })

    it('should exclude default patterns', async () => {
      await mkdir(join(TEST_DIR, 'node_modules', 'lodash'), { recursive: true })
      await writeFile(join(TEST_DIR, 'node_modules', 'lodash', 'index.js'), 'module')
      await writeFile(join(TEST_DIR, 'index.js'), 'app')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('index.js')
    })
  })

  describe('file handling', () => {
    it('should compute correct file hash', async () => {
      const content = 'test content'
      await writeFile(join(TEST_DIR, 'test.txt'), content)

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.files[0].hash).toHaveLength(64)
    })

    it('should record correct file size', async () => {
      const content = 'hello world'
      await writeFile(join(TEST_DIR, 'test.txt'), content)

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.files[0].size).toBe(Buffer.byteLength(content))
    })

    it('should handle symlinks gracefully', async () => {
      await writeFile(join(TEST_DIR, 'original.txt'), 'content')
      await symlink(
        join(TEST_DIR, 'original.txt'),
        join(TEST_DIR, 'link.txt')
      )

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      // Should only include the original file, not the symlink
      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('original.txt')
    })

    it('should handle special characters in filenames', async () => {
      await writeFile(join(TEST_DIR, 'file with spaces.txt'), 'content')
      await writeFile(join(TEST_DIR, 'file-with-dashes.txt'), 'content')
      await writeFile(join(TEST_DIR, 'file_with_underscores.txt'), 'content')

      const ingestor = new LocalIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(3)
    })
  })

  describe('deterministic behavior', () => {
    it('should produce same hash for same content', async () => {
      await writeFile(join(TEST_DIR, 'a.txt'), 'content-a')
      await writeFile(join(TEST_DIR, 'b.txt'), 'content-b')

      const ingestor = new LocalIngestor()
      const result1 = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })
      const result2 = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result1.context?.sourceHash).toBe(result2.context?.sourceHash)
    })
  })
})
