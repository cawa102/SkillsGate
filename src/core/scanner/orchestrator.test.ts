import { describe, it, expect } from 'vitest'
import { ScannerOrchestrator, BaseScanner, ScanContext } from './index.js'
import type { Finding, ScannerType } from '../../types/index.js'

class MockScanner extends BaseScanner {
  readonly type: ScannerType
  readonly name: string

  constructor(
    type: ScannerType,
    name: string,
    private findingsToReturn: Finding[] = []
  ) {
    super()
    this.type = type
    this.name = name
  }

  async scan(_context: ScanContext): Promise<Finding[]> {
    return this.findingsToReturn
  }
}

describe('ScannerOrchestrator', () => {
  it('should start with no scanners', () => {
    const orchestrator = new ScannerOrchestrator()
    expect(orchestrator.scannerCount).toBe(0)
  })

  it('should register scanners', () => {
    const orchestrator = new ScannerOrchestrator()
    const scanner = new MockScanner('secret', 'Secret Scanner')

    orchestrator.register(scanner)

    expect(orchestrator.scannerCount).toBe(1)
  })

  it('should execute all scanners in parallel', async () => {
    const orchestrator = new ScannerOrchestrator()
    const finding1: Finding = {
      scanner: 'secret',
      severity: 'critical',
      rule: 'test_rule_1',
      message: 'Test finding 1',
      location: { file: 'file1.ts' }
    }
    const finding2: Finding = {
      scanner: 'static',
      severity: 'high',
      rule: 'test_rule_2',
      message: 'Test finding 2',
      location: { file: 'file2.ts' }
    }

    orchestrator.register(new MockScanner('secret', 'Secret Scanner', [finding1]))
    orchestrator.register(new MockScanner('static', 'Static Analyzer', [finding2]))

    const context: ScanContext = {
      rootPath: '/test',
      files: ['file1.ts', 'file2.ts']
    }

    const results = await orchestrator.scan(context)

    expect(results).toHaveLength(2)
    expect(results[0].scanner).toBe('secret')
    expect(results[0].findings).toEqual([finding1])
    expect(results[1].scanner).toBe('static')
    expect(results[1].findings).toEqual([finding2])
  })

  it('should return empty array when no scanners registered', async () => {
    const orchestrator = new ScannerOrchestrator()
    const context: ScanContext = {
      rootPath: '/test',
      files: []
    }

    const results = await orchestrator.scan(context)

    expect(results).toEqual([])
  })

  it('should handle scanner errors gracefully', async () => {
    const orchestrator = new ScannerOrchestrator()

    class ErrorScanner extends BaseScanner {
      readonly type: ScannerType = 'skill'
      readonly name = 'Error Scanner'

      async scan(_context: ScanContext): Promise<Finding[]> {
        throw new Error('Scanner failed')
      }
    }

    orchestrator.register(new ErrorScanner())

    const context: ScanContext = {
      rootPath: '/test',
      files: []
    }

    const results = await orchestrator.scan(context)

    expect(results).toHaveLength(1)
    expect(results[0].scanner).toBe('skill')
    expect(results[0].findings).toEqual([])
    expect(results[0].error).toBe('Scanner failed')
  })
})
