import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { join } from 'path'
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { createProgram, ExitCode } from './index.js'

const fixturesPath = join(import.meta.dirname, '../core/policy/__fixtures__')

describe('CLI Framework', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockExit: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockConsoleInfo: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mockConsoleError: any

  beforeEach(() => {
    mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called')
    })
    mockConsoleInfo = vi.spyOn(console, 'info').mockImplementation(() => {})
    mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    mockExit.mockRestore()
    mockConsoleInfo.mockRestore()
    mockConsoleError.mockRestore()
  })

  describe('ExitCode', () => {
    it('should have correct exit codes', () => {
      expect(ExitCode.ALLOW).toBe(0)
      expect(ExitCode.BLOCK).toBe(1)
      expect(ExitCode.QUARANTINE).toBe(2)
      expect(ExitCode.ERROR).toBe(3)
    })
  })

  describe('createProgram', () => {
    it('should create a program with correct name', () => {
      const program = createProgram()

      expect(program.name()).toBe('sg')
    })

    it('should have version set', () => {
      const program = createProgram()

      expect(program.version()).toBe('1.0.0')
    })

    it('should have global options', () => {
      const program = createProgram()
      const options = program.options

      const optionNames = options.map((opt) => opt.long)
      expect(optionNames).toContain('--verbose')
      expect(optionNames).toContain('--quiet')
      expect(optionNames).toContain('--config')
    })

    it('should have scan command', () => {
      const program = createProgram()
      const scanCmd = program.commands.find((cmd) => cmd.name() === 'scan')

      expect(scanCmd).toBeDefined()
      expect(scanCmd?.description()).toContain('Scan')
    })

    it('should have init command', () => {
      const program = createProgram()
      const initCmd = program.commands.find((cmd) => cmd.name() === 'init')

      expect(initCmd).toBeDefined()
      expect(initCmd?.description()).toContain('Generate')
    })

    it('should have validate command', () => {
      const program = createProgram()
      const validateCmd = program.commands.find((cmd) => cmd.name() === 'validate')

      expect(validateCmd).toBeDefined()
      expect(validateCmd?.description()).toContain('Validate')
    })

    it('scan command should have output option', () => {
      const program = createProgram()
      const scanCmd = program.commands.find((cmd) => cmd.name() === 'scan')
      const options = scanCmd?.options.map((opt) => opt.long)

      expect(options).toContain('--output')
      expect(options).toContain('--format')
      expect(options).toContain('--policy')
    })

    it('init command should have output option', () => {
      const program = createProgram()
      const initCmd = program.commands.find((cmd) => cmd.name() === 'init')
      const options = initCmd?.options.map((opt) => opt.long)

      expect(options).toContain('--output')
      expect(options).toContain('--force')
    })
  })

  describe('command execution', () => {
    it('should display help without error', async () => {
      const program = createProgram()
      program.exitOverride()

      try {
        await program.parseAsync(['node', 'sg', '--help'])
      } catch (err) {
        // commander throws on --help, which is expected
        expect((err as Error).message).toContain('(outputHelp)')
      }
    })

    it('should display version without error', async () => {
      const program = createProgram()
      program.exitOverride()

      try {
        await program.parseAsync(['node', 'sg', '--version'])
      } catch (err) {
        // commander throws on --version, which is expected
        expect((err as Error).message).toContain('1.0.0')
      }
    })
  })

  describe('validate command', () => {
    it('should exit with ALLOW (0) for valid policy file', async () => {
      const program = createProgram()
      const validPolicyPath = join(fixturesPath, 'valid-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'validate', validPolicyPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ALLOW)
    })

    it('should exit with ERROR (3) for invalid policy file', async () => {
      const program = createProgram()
      const invalidPolicyPath = join(fixturesPath, 'invalid-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'validate', invalidPolicyPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ERROR)
    })

    it('should exit with ERROR (3) for non-existent policy file', async () => {
      const program = createProgram()

      try {
        await program.parseAsync(['node', 'sg', 'validate', '/non-existent/policy.yaml'])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ERROR)
    })

    it('should log success message for valid policy', async () => {
      const program = createProgram()
      const validPolicyPath = join(fixturesPath, 'valid-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'validate', validPolicyPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockConsoleInfo).toHaveBeenCalledWith(
        expect.stringContaining('valid')
      )
    })

    it('should log error messages for invalid policy', async () => {
      const program = createProgram()
      const invalidPolicyPath = join(fixturesPath, 'invalid-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'validate', invalidPolicyPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockConsoleError).toHaveBeenCalledWith(
        expect.stringContaining('invalid')
      )
    })

    it('should suppress output in quiet mode for valid policy', async () => {
      const program = createProgram()
      const validPolicyPath = join(fixturesPath, 'valid-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', '-q', 'validate', validPolicyPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ALLOW)
      // No info messages should be logged in quiet mode
      expect(mockConsoleInfo).not.toHaveBeenCalled()
    })
  })

  describe('init command', () => {
    let tempDir: string

    beforeEach(() => {
      tempDir = mkdtempSync(join(tmpdir(), 'sg-init-test-'))
    })

    afterEach(() => {
      rmSync(tempDir, { recursive: true, force: true })
    })

    it('should exit with ALLOW (0) when creating new policy file', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'new-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ALLOW)
      expect(existsSync(outputPath)).toBe(true)
    })

    it('should create valid policy file with correct content', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'new-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // process.exit is mocked to throw
      }

      const content = readFileSync(outputPath, 'utf-8')
      expect(content).toContain('version: "1.0"')
      expect(content).toContain('skillgate-default')
      expect(content).toContain('thresholds:')
      expect(content).toContain('critical_block:')
    })

    it('should exit with ERROR (3) when file exists without force', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'existing-policy.yaml')

      // Create the file first
      const firstProgram = createProgram()
      try {
        await firstProgram.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // Expected
      }

      // Try to create again without --force
      mockExit.mockClear()
      try {
        await program.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ERROR)
    })

    it('should exit with ALLOW (0) when file exists with force flag', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'existing-policy.yaml')

      // Create the file first
      const firstProgram = createProgram()
      try {
        await firstProgram.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // Expected
      }

      // Create again with --force
      mockExit.mockClear()
      try {
        await program.parseAsync(['node', 'sg', 'init', '-o', outputPath, '--force'])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ALLOW)
    })

    it('should log success message when creating policy', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'new-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', 'init', '-o', outputPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockConsoleInfo).toHaveBeenCalledWith(
        expect.stringContaining('Created policy file')
      )
    })

    it('should suppress output in quiet mode', async () => {
      const program = createProgram()
      const outputPath = join(tempDir, 'quiet-policy.yaml')

      try {
        await program.parseAsync(['node', 'sg', '-q', 'init', '-o', outputPath])
      } catch {
        // process.exit is mocked to throw
      }

      expect(mockExit).toHaveBeenCalledWith(ExitCode.ALLOW)
      expect(existsSync(outputPath)).toBe(true)
      // No info messages should be logged in quiet mode
      expect(mockConsoleInfo).not.toHaveBeenCalled()
    })
  })
})
