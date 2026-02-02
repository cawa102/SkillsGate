import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, writeFile, rm } from 'fs/promises'
import { join } from 'path'
import {
  getFiles,
  readFileContent,
  matchesPattern,
  getExtension
} from './utils.js'

const TEST_DIR = '/tmp/skillgate-test-utils'

describe('Scanner Utils', () => {
  beforeEach(async () => {
    await mkdir(TEST_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('getFiles', () => {
    it('should return all files in a directory', async () => {
      await writeFile(join(TEST_DIR, 'file1.ts'), 'content1')
      await writeFile(join(TEST_DIR, 'file2.ts'), 'content2')

      const files = await getFiles(TEST_DIR)

      expect(files).toHaveLength(2)
      expect(files).toContain(join(TEST_DIR, 'file1.ts'))
      expect(files).toContain(join(TEST_DIR, 'file2.ts'))
    })

    it('should recursively get files from subdirectories', async () => {
      await mkdir(join(TEST_DIR, 'sub'), { recursive: true })
      await writeFile(join(TEST_DIR, 'root.ts'), 'root')
      await writeFile(join(TEST_DIR, 'sub', 'nested.ts'), 'nested')

      const files = await getFiles(TEST_DIR)

      expect(files).toHaveLength(2)
      expect(files).toContain(join(TEST_DIR, 'root.ts'))
      expect(files).toContain(join(TEST_DIR, 'sub', 'nested.ts'))
    })

    it('should filter by extensions', async () => {
      await writeFile(join(TEST_DIR, 'script.ts'), 'ts')
      await writeFile(join(TEST_DIR, 'script.js'), 'js')
      await writeFile(join(TEST_DIR, 'style.css'), 'css')

      const files = await getFiles(TEST_DIR, { extensions: ['.ts', '.js'] })

      expect(files).toHaveLength(2)
      expect(files).toContain(join(TEST_DIR, 'script.ts'))
      expect(files).toContain(join(TEST_DIR, 'script.js'))
      expect(files).not.toContain(join(TEST_DIR, 'style.css'))
    })

    it('should exclude specified directories', async () => {
      await mkdir(join(TEST_DIR, 'node_modules'), { recursive: true })
      await mkdir(join(TEST_DIR, 'src'), { recursive: true })
      await writeFile(join(TEST_DIR, 'node_modules', 'dep.js'), 'dep')
      await writeFile(join(TEST_DIR, 'src', 'app.ts'), 'app')

      const files = await getFiles(TEST_DIR, { exclude: ['node_modules'] })

      expect(files).toHaveLength(1)
      expect(files).toContain(join(TEST_DIR, 'src', 'app.ts'))
    })

    it('should return empty array for empty directory', async () => {
      const files = await getFiles(TEST_DIR)
      expect(files).toEqual([])
    })

    it('should return empty array for non-existent directory', async () => {
      const files = await getFiles('/non/existent/path')
      expect(files).toEqual([])
    })
  })

  describe('readFileContent', () => {
    it('should read file content as string', async () => {
      const content = 'Hello, World!'
      await writeFile(join(TEST_DIR, 'test.txt'), content)

      const result = await readFileContent(join(TEST_DIR, 'test.txt'))

      expect(result).toBe(content)
    })

    it('should return null for non-existent file', async () => {
      const result = await readFileContent('/non/existent/file.txt')
      expect(result).toBeNull()
    })

    it('should handle UTF-8 content', async () => {
      const content = '日本語テスト 🎉'
      await writeFile(join(TEST_DIR, 'utf8.txt'), content)

      const result = await readFileContent(join(TEST_DIR, 'utf8.txt'))

      expect(result).toBe(content)
    })

    it('should handle empty files', async () => {
      await writeFile(join(TEST_DIR, 'empty.txt'), '')

      const result = await readFileContent(join(TEST_DIR, 'empty.txt'))

      expect(result).toBe('')
    })
  })

  describe('matchesPattern', () => {
    it('should match exact filename', () => {
      expect(matchesPattern('package.json', 'package.json')).toBe(true)
    })

    it('should match glob pattern with wildcard', () => {
      expect(matchesPattern('src/index.ts', '*.ts')).toBe(true)
      expect(matchesPattern('src/index.js', '*.ts')).toBe(false)
    })

    it('should match glob pattern with double wildcard', () => {
      expect(matchesPattern('src/deep/nested/file.ts', '**/*.ts')).toBe(true)
      expect(matchesPattern('file.ts', '**/*.ts')).toBe(true)
    })

    it('should match directory patterns', () => {
      expect(matchesPattern('node_modules/pkg/index.js', 'node_modules/**')).toBe(true)
      expect(matchesPattern('src/pkg/index.js', 'node_modules/**')).toBe(false)
    })

    it('should be case-sensitive', () => {
      expect(matchesPattern('FILE.ts', '*.ts')).toBe(true)
      expect(matchesPattern('FILE.TS', '*.ts')).toBe(false)
    })
  })

  describe('getExtension', () => {
    it('should return file extension with dot', () => {
      expect(getExtension('file.ts')).toBe('.ts')
      expect(getExtension('file.test.ts')).toBe('.ts')
    })

    it('should return empty string for files without extension', () => {
      expect(getExtension('Makefile')).toBe('')
      expect(getExtension('Dockerfile')).toBe('')
    })

    it('should handle paths with directories', () => {
      expect(getExtension('src/utils/helper.js')).toBe('.js')
      expect(getExtension('/absolute/path/file.md')).toBe('.md')
    })

    it('should handle hidden files', () => {
      expect(getExtension('.gitignore')).toBe('')
      expect(getExtension('.eslintrc.json')).toBe('.json')
    })
  })
})
