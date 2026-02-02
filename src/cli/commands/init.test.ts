import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { initCommand, InitOptions, DEFAULT_OUTPUT_FILENAME } from './init.js'

vi.mock('fs')

describe('init command', () => {
  const mockFs = vi.mocked(fs)

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('DEFAULT_OUTPUT_FILENAME', () => {
    it('should be skillgate.policy.yaml', () => {
      expect(DEFAULT_OUTPUT_FILENAME).toBe('skillgate.policy.yaml')
    })
  })

  describe('initCommand', () => {
    it('should create policy file at default location', async () => {
      mockFs.existsSync.mockReturnValue(false)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')
      mockFs.writeFileSync.mockImplementation(() => {})

      const result = await initCommand({})

      expect(result.success).toBe(true)
      expect(result.outputPath).toContain('skillgate.policy.yaml')
      expect(mockFs.writeFileSync).toHaveBeenCalled()
    })

    it('should create policy file at custom location', async () => {
      mockFs.existsSync.mockReturnValue(false)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')
      mockFs.writeFileSync.mockImplementation(() => {})

      const options: InitOptions = { output: 'custom.yaml' }
      const result = await initCommand(options)

      expect(result.success).toBe(true)
      expect(result.outputPath).toContain('custom.yaml')
    })

    it('should fail if file exists without force flag', async () => {
      mockFs.existsSync.mockReturnValue(true)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')

      const result = await initCommand({})

      expect(result.success).toBe(false)
      expect(result.error).toContain('already exists')
    })

    it('should overwrite file with force flag', async () => {
      mockFs.existsSync.mockReturnValue(true)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')
      mockFs.writeFileSync.mockImplementation(() => {})

      const options: InitOptions = { force: true }
      const result = await initCommand(options)

      expect(result.success).toBe(true)
      expect(mockFs.writeFileSync).toHaveBeenCalled()
    })

    it('should handle write errors gracefully', async () => {
      mockFs.existsSync.mockReturnValue(false)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')
      mockFs.writeFileSync.mockImplementation(() => {
        throw new Error('Permission denied')
      })

      const result = await initCommand({})

      expect(result.success).toBe(false)
      expect(result.error).toContain('Permission denied')
    })

    it('should handle missing default policy file', async () => {
      mockFs.existsSync.mockReturnValue(false)
      mockFs.readFileSync.mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory')
      })

      const result = await initCommand({})

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })

    it('should create parent directories if needed', async () => {
      mockFs.existsSync.mockReturnValue(false)
      mockFs.readFileSync.mockReturnValue('version: "1.0"')
      mockFs.writeFileSync.mockImplementation(() => {})
      mockFs.mkdirSync.mockImplementation(() => undefined)

      const options: InitOptions = { output: 'config/policies/my.yaml' }
      const result = await initCommand(options)

      expect(result.success).toBe(true)
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(
        expect.stringContaining('config/policies'),
        { recursive: true }
      )
    })
  })
})
