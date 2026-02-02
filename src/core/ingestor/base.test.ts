import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, rm, writeFile } from 'fs/promises'
import { join } from 'path'
import { BaseIngestor } from './base.js'
import type {
  IngestContext,
  IngestorSource,
  SourceType
} from './types.js'

// Concrete implementation for testing abstract class
class TestIngestor extends BaseIngestor {
  constructor(options?: { exclude?: string[] }) {
    super('local', options)
  }

  protected async doIngest(source: IngestorSource): Promise<IngestContext> {
    const metadata = this.createMetadata(source)
    return this.buildContext(source.location, metadata)
  }
}

// Test fixtures directory
const TEST_DIR = '/tmp/skillgate-test-ingestor'

describe('BaseIngestor', () => {
  beforeEach(async () => {
    await mkdir(TEST_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('ingest', () => {
    it('should return success result with context on successful ingestion', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'hello world')

      const ingestor = new TestIngestor()
      const source: IngestorSource = {
        type: 'local',
        location: TEST_DIR
      }

      const result = await ingestor.ingest(source)

      expect(result.success).toBe(true)
      expect(result.context).toBeDefined()
      expect(result.context?.rootDir).toBe(TEST_DIR)
      expect(result.context?.fileCount).toBe(1)
      expect(result.duration).toBeGreaterThanOrEqual(0)
      expect(result.error).toBeUndefined()
    })

    it('should return error result on failure', async () => {
      const ingestor = new TestIngestor()
      const source: IngestorSource = {
        type: 'local',
        location: '/nonexistent/path/that/does/not/exist'
      }

      const result = await ingestor.ingest(source)

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
      expect(result.context).toBeUndefined()
      expect(result.duration).toBeGreaterThanOrEqual(0)
    })

    it('should measure execution duration', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new TestIngestor()
      const source: IngestorSource = {
        type: 'local',
        location: TEST_DIR
      }

      const result = await ingestor.ingest(source)

      expect(result.duration).toBeGreaterThanOrEqual(0)
    })
  })

  describe('buildContext', () => {
    it('should collect all files in directory', async () => {
      await writeFile(join(TEST_DIR, 'file1.txt'), 'content1')
      await writeFile(join(TEST_DIR, 'file2.txt'), 'content2')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(2)
      expect(result.context?.files.map(f => f.path).sort()).toEqual([
        'file1.txt',
        'file2.txt'
      ])
    })

    it('should recursively collect files in subdirectories', async () => {
      await mkdir(join(TEST_DIR, 'subdir'), { recursive: true })
      await writeFile(join(TEST_DIR, 'root.txt'), 'root')
      await writeFile(join(TEST_DIR, 'subdir', 'nested.txt'), 'nested')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(2)
      expect(result.context?.files.map(f => f.path).sort()).toEqual([
        'root.txt',
        'subdir/nested.txt'
      ])
    })

    it('should compute correct file hashes', async () => {
      const content = 'test content for hashing'
      await writeFile(join(TEST_DIR, 'hash-test.txt'), content)

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      const file = result.context?.files.find(f => f.path === 'hash-test.txt')
      expect(file?.hash).toBeDefined()
      expect(file?.hash).toHaveLength(64) // SHA-256 hex = 64 chars
    })

    it('should compute deterministic source hash', async () => {
      await writeFile(join(TEST_DIR, 'a.txt'), 'content-a')
      await writeFile(join(TEST_DIR, 'b.txt'), 'content-b')

      const ingestor = new TestIngestor()
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

    it('should calculate total size correctly', async () => {
      const content1 = 'hello'
      const content2 = 'world!'
      await writeFile(join(TEST_DIR, 'file1.txt'), content1)
      await writeFile(join(TEST_DIR, 'file2.txt'), content2)

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.totalSize).toBe(
        Buffer.byteLength(content1) + Buffer.byteLength(content2)
      )
    })
  })

  describe('shouldExclude', () => {
    it('should exclude hidden directories by default', async () => {
      await mkdir(join(TEST_DIR, '.hidden'), { recursive: true })
      await writeFile(join(TEST_DIR, '.hidden', 'secret.txt'), 'secret')
      await writeFile(join(TEST_DIR, 'visible.txt'), 'visible')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('visible.txt')
    })

    it('should exclude node_modules by default', async () => {
      await mkdir(join(TEST_DIR, 'node_modules', 'pkg'), { recursive: true })
      await writeFile(join(TEST_DIR, 'node_modules', 'pkg', 'index.js'), 'code')
      await writeFile(join(TEST_DIR, 'src.js'), 'source')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('src.js')
    })

    it('should allow .github directory', async () => {
      await mkdir(join(TEST_DIR, '.github', 'workflows'), { recursive: true })
      await writeFile(
        join(TEST_DIR, '.github', 'workflows', 'ci.yml'),
        'name: CI'
      )

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('.github/workflows/ci.yml')
    })

    it('should respect custom exclude patterns', async () => {
      await mkdir(join(TEST_DIR, 'vendor'), { recursive: true })
      await writeFile(join(TEST_DIR, 'vendor', 'lib.js'), 'vendor code')
      await writeFile(join(TEST_DIR, 'app.js'), 'app code')

      const ingestor = new TestIngestor({ exclude: ['vendor'] })
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.fileCount).toBe(1)
      expect(result.context?.files[0].path).toBe('app.js')
    })
  })

  describe('metadata', () => {
    it('should include correct source type', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.metadata.type).toBe('local')
    })

    it('should include original location', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.metadata.originalLocation).toBe(TEST_DIR)
    })

    it('should include ingestion timestamp', async () => {
      await writeFile(join(TEST_DIR, 'test.txt'), 'content')

      const before = new Date().toISOString()
      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })
      const after = new Date().toISOString()

      const ingestedAt = result.context?.metadata.ingestedAt
      expect(ingestedAt).toBeDefined()
      expect(ingestedAt! >= before).toBe(true)
      expect(ingestedAt! <= after).toBe(true)
    })
  })

  describe('IngestedFile', () => {
    it('should include relative path', async () => {
      await mkdir(join(TEST_DIR, 'src'), { recursive: true })
      await writeFile(join(TEST_DIR, 'src', 'index.ts'), 'export {}')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      const file = result.context?.files.find(f => f.path === 'src/index.ts')
      expect(file).toBeDefined()
      expect(file?.path).toBe('src/index.ts')
    })

    it('should include absolute path', async () => {
      await writeFile(join(TEST_DIR, 'file.txt'), 'content')

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.files[0].absolutePath).toBe(
        join(TEST_DIR, 'file.txt')
      )
    })

    it('should include file size', async () => {
      const content = 'exactly 20 bytes!!!'
      await writeFile(join(TEST_DIR, 'sized.txt'), content)

      const ingestor = new TestIngestor()
      const result = await ingestor.ingest({
        type: 'local',
        location: TEST_DIR
      })

      expect(result.context?.files[0].size).toBe(Buffer.byteLength(content))
    })
  })
})
