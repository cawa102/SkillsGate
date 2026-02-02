import { describe, it, expect, vi } from 'vitest'
import { BaseScanner, ScanContext } from './base.js'
import type { Finding, ScannerType } from '../../types/index.js'

// Concrete implementation for testing abstract class
class TestScanner extends BaseScanner {
  readonly type: ScannerType = 'secret'
  readonly name = 'Test Scanner'

  constructor(private mockScan?: (context: ScanContext) => Promise<Finding[]>) {
    super()
  }

  async scan(context: ScanContext): Promise<Finding[]> {
    if (this.mockScan) {
      return this.mockScan(context)
    }
    return []
  }
}

describe('BaseScanner', () => {
  describe('execute', () => {
    it('should return ScannerResult with findings on success', async () => {
      const mockFindings: Finding[] = [
        {
          scanner: 'secret',
          severity: 'critical',
          rule: 'secret_aws_access_key',
          message: 'AWS Access Key detected',
          location: { file: 'config.ts', line: 10 },
          evidence: 'AKIA***'
        }
      ]

      const scanner = new TestScanner(async () => mockFindings)
      const context: ScanContext = {
        rootPath: '/test/path',
        files: ['config.ts']
      }

      const result = await scanner.execute(context)

      expect(result.scanner).toBe('secret')
      expect(result.findings).toEqual(mockFindings)
      expect(result.duration).toBeGreaterThanOrEqual(0)
      expect(result.error).toBeUndefined()
    })

    it('should return empty findings array when scan returns empty', async () => {
      const scanner = new TestScanner(async () => [])
      const context: ScanContext = {
        rootPath: '/test/path',
        files: []
      }

      const result = await scanner.execute(context)

      expect(result.scanner).toBe('secret')
      expect(result.findings).toEqual([])
      expect(result.error).toBeUndefined()
    })

    it('should capture error message when scan throws Error', async () => {
      const scanner = new TestScanner(async () => {
        throw new Error('Scan failed')
      })
      const context: ScanContext = {
        rootPath: '/test/path',
        files: []
      }

      const result = await scanner.execute(context)

      expect(result.scanner).toBe('secret')
      expect(result.findings).toEqual([])
      expect(result.error).toBe('Scan failed')
      expect(result.duration).toBeGreaterThanOrEqual(0)
    })

    it('should convert non-Error throws to string', async () => {
      const scanner = new TestScanner(async () => {
        throw 'String error'
      })
      const context: ScanContext = {
        rootPath: '/test/path',
        files: []
      }

      const result = await scanner.execute(context)

      expect(result.error).toBe('String error')
    })

    it('should measure execution duration', async () => {
      const delay = 50
      const scanner = new TestScanner(async () => {
        await new Promise(resolve => setTimeout(resolve, delay))
        return []
      })
      const context: ScanContext = {
        rootPath: '/test/path',
        files: []
      }

      const result = await scanner.execute(context)

      expect(result.duration).toBeGreaterThanOrEqual(delay - 10)
    })
  })

  describe('ScanContext', () => {
    it('should accept context with rootPath and files', () => {
      const context: ScanContext = {
        rootPath: '/project',
        files: ['src/index.ts', 'src/utils.ts']
      }

      expect(context.rootPath).toBe('/project')
      expect(context.files).toHaveLength(2)
    })

    it('should accept optional policy', () => {
      const context: ScanContext = {
        rootPath: '/project',
        files: [],
        policy: {
          version: '1.0',
          name: 'test-policy',
          thresholds: { block: 40, warn: 70 },
          critical_block: [],
          rules: {},
          exceptions: []
        }
      }

      expect(context.policy).toBeDefined()
      expect(context.policy?.name).toBe('test-policy')
    })
  })
})
