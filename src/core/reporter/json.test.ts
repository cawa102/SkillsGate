import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { writeFile } from 'node:fs/promises'
import { JsonReporter, createJsonReporter } from './json.js'
import type { ScanReport, Finding } from '../../types/index.js'

vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn()
}))

const mockWriteFile = vi.mocked(writeFile)

function createMockReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    version: '1.0.0',
    timestamp: '2026-02-02T12:00:00Z',
    source: {
      type: 'local',
      path: '/test/path',
      hash: 'abc123'
    },
    decision: 'allow',
    score: 85,
    findings: [],
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    criticalBlockRules: [],
    duration: 1000,
    policyName: 'default',
    errors: [],
    ...overrides
  }
}

function createMockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: 'secret',
    severity: 'high',
    rule: 'secret_aws_access_key',
    message: 'AWS access key detected',
    location: { file: 'config.js', line: 10 },
    ...overrides
  }
}

describe('JsonReporter', () => {
  let reporter: JsonReporter
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stdoutWriteSpy: any

  beforeEach(() => {
    reporter = new JsonReporter()
    stdoutWriteSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    mockWriteFile.mockClear()
  })

  afterEach(() => {
    stdoutWriteSpy.mockRestore()
  })

  describe('generate', () => {
    it('should generate valid JSON', () => {
      const report = createMockReport()
      const json = reporter.generate(report)

      expect(() => JSON.parse(json)).not.toThrow()
    })

    it('should generate pretty JSON by default', () => {
      const report = createMockReport()
      const json = reporter.generate(report)

      expect(json).toContain('\n')
      expect(json).toContain('  ')
    })

    it('should generate compact JSON when pretty is false', () => {
      const report = createMockReport()
      const json = reporter.generate(report, { pretty: false })

      expect(json).not.toContain('\n')
    })

    it('should mask secrets in evidence by default', () => {
      const finding = createMockFinding({
        evidence: 'AKIAIOSFODNN7EXAMPLE'
      })
      const report = createMockReport({ findings: [finding] })
      const json = reporter.generate(report)
      const parsed = JSON.parse(json)

      expect(parsed.findings[0].evidence).toContain('[MASKED]')
      expect(parsed.findings[0].evidence).not.toContain('AKIAIOSFODNN7EXAMPLE')
    })

    it('should preserve secrets when maskSecrets is false', () => {
      const finding = createMockFinding({
        evidence: 'AKIAIOSFODNN7EXAMPLE'
      })
      const report = createMockReport({ findings: [finding] })
      const json = reporter.generate(report, { maskSecrets: false })
      const parsed = JSON.parse(json)

      expect(parsed.findings[0].evidence).toBe('AKIAIOSFODNN7EXAMPLE')
    })

    it('should mask GitHub tokens', () => {
      const finding = createMockFinding({
        evidence: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'
      })
      const report = createMockReport({ findings: [finding] })
      const json = reporter.generate(report)
      const parsed = JSON.parse(json)

      expect(parsed.findings[0].evidence).toContain('[MASKED]')
      expect(parsed.findings[0].evidence).not.toContain('ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789')
    })

    it('should preserve findings without evidence', () => {
      const finding = createMockFinding({ evidence: undefined })
      const report = createMockReport({ findings: [finding] })
      const json = reporter.generate(report)
      const parsed = JSON.parse(json)

      expect(parsed.findings[0].evidence).toBeUndefined()
    })

    it('should include all report fields', () => {
      const report = createMockReport({
        decision: 'block',
        score: 25,
        criticalBlockRules: ['secret_private_key']
      })
      const json = reporter.generate(report)
      const parsed = JSON.parse(json)

      expect(parsed.version).toBe('1.0.0')
      expect(parsed.decision).toBe('block')
      expect(parsed.score).toBe(25)
      expect(parsed.criticalBlockRules).toContain('secret_private_key')
    })
  })

  describe('write', () => {
    it('should write to file when output is specified', async () => {
      const report = createMockReport()
      await reporter.write(report, { output: '/tmp/report.json' })

      expect(mockWriteFile).toHaveBeenCalledWith(
        '/tmp/report.json',
        expect.any(String),
        'utf-8'
      )
    })

    it('should write to stdout when no output specified', async () => {
      const report = createMockReport()
      await reporter.write(report)

      expect(stdoutWriteSpy).toHaveBeenCalled()
      const output = stdoutWriteSpy.mock.calls[0][0] as string
      expect(() => JSON.parse(output.trim())).not.toThrow()
    })

    it('should not write to stdout when quiet is true', async () => {
      const report = createMockReport()
      await reporter.write(report, { quiet: true })

      expect(stdoutWriteSpy).not.toHaveBeenCalled()
    })

    it('should write to file even when quiet is true', async () => {
      const report = createMockReport()
      await reporter.write(report, { output: '/tmp/report.json', quiet: true })

      expect(mockWriteFile).toHaveBeenCalled()
    })
  })

  describe('createJsonReporter', () => {
    it('should create a JsonReporter instance', () => {
      const reporter = createJsonReporter()

      expect(reporter).toBeInstanceOf(JsonReporter)
    })
  })
})
