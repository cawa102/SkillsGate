import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { writeFile } from 'node:fs/promises'
import { MarkdownReporter, createMarkdownReporter } from './markdown.js'
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

describe('MarkdownReporter', () => {
  let reporter: MarkdownReporter
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let stdoutWriteSpy: any

  beforeEach(() => {
    reporter = new MarkdownReporter()
    stdoutWriteSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    mockWriteFile.mockClear()
  })

  afterEach(() => {
    stdoutWriteSpy.mockRestore()
  })

  describe('generate', () => {
    it('should generate valid markdown with title', () => {
      const report = createMockReport()
      const md = reporter.generate(report)

      expect(md).toContain('# SkillGate Security Report')
    })

    it('should include decision badge for allow', () => {
      const report = createMockReport({ decision: 'allow' })
      const md = reporter.generate(report)

      expect(md).toContain('✅')
      expect(md).toContain('ALLOW')
    })

    it('should include decision badge for block', () => {
      const report = createMockReport({ decision: 'block' })
      const md = reporter.generate(report)

      expect(md).toContain('🚫')
      expect(md).toContain('BLOCK')
    })

    it('should include decision badge for quarantine', () => {
      const report = createMockReport({ decision: 'quarantine' })
      const md = reporter.generate(report)

      expect(md).toContain('⚠️')
      expect(md).toContain('QUARANTINE')
    })

    it('should include source information', () => {
      const report = createMockReport({
        source: {
          type: 'git',
          path: '/repo/path',
          url: 'https://github.com/test/repo',
          commit: 'abc123def',
          hash: 'sha256:abc123'
        }
      })
      const md = reporter.generate(report)

      expect(md).toContain('git')
      expect(md).toContain('/repo/path')
      expect(md).toContain('https://github.com/test/repo')
      expect(md).toContain('abc123def')
    })

    it('should include score and summary', () => {
      const report = createMockReport({
        score: 65,
        summary: {
          critical: 1,
          high: 2,
          medium: 3,
          low: 1,
          info: 0
        }
      })
      const md = reporter.generate(report)

      expect(md).toContain('65')
      expect(md).toContain('Critical')
      expect(md).toContain('High')
      expect(md).toContain('Medium')
    })

    it('should list findings grouped by severity', () => {
      const findings: Finding[] = [
        createMockFinding({ severity: 'critical', message: 'Critical issue' }),
        createMockFinding({ severity: 'high', message: 'High issue' }),
        createMockFinding({ severity: 'medium', message: 'Medium issue' })
      ]
      const report = createMockReport({ findings })
      const md = reporter.generate(report)

      expect(md).toContain('Critical issue')
      expect(md).toContain('High issue')
      expect(md).toContain('Medium issue')
    })

    it('should mask secrets in evidence by default', () => {
      const finding = createMockFinding({
        evidence: 'AKIAIOSFODNN7EXAMPLE'
      })
      const report = createMockReport({ findings: [finding] })
      const md = reporter.generate(report)

      expect(md).toContain('[MASKED]')
      expect(md).not.toContain('AKIAIOSFODNN7EXAMPLE')
    })

    it('should preserve secrets when maskSecrets is false', () => {
      const finding = createMockFinding({
        evidence: 'AKIAIOSFODNN7EXAMPLE'
      })
      const report = createMockReport({ findings: [finding] })
      const md = reporter.generate(report, { maskSecrets: false })

      expect(md).toContain('AKIAIOSFODNN7EXAMPLE')
    })

    it('should include file location for findings', () => {
      const finding = createMockFinding({
        location: { file: 'src/config.ts', line: 42 }
      })
      const report = createMockReport({ findings: [finding] })
      const md = reporter.generate(report)

      expect(md).toContain('src/config.ts')
      expect(md).toContain('42')
    })

    it('should include critical block rules when present', () => {
      const report = createMockReport({
        criticalBlockRules: ['secret_private_key', 'skill_rm_rf']
      })
      const md = reporter.generate(report)

      expect(md).toContain('secret_private_key')
      expect(md).toContain('skill_rm_rf')
    })

    it('should include errors when present', () => {
      const report = createMockReport({
        errors: ['Scanner timeout', 'Network error']
      })
      const md = reporter.generate(report)

      expect(md).toContain('Scanner timeout')
      expect(md).toContain('Network error')
    })

    it('should include scan duration', () => {
      const report = createMockReport({ duration: 2500 })
      const md = reporter.generate(report)

      expect(md).toContain('2.50')
    })

    it('should show no findings message when empty', () => {
      const report = createMockReport({ findings: [] })
      const md = reporter.generate(report)

      expect(md).toContain('No security issues found')
    })

    it('should include policy name', () => {
      const report = createMockReport({ policyName: 'strict-policy' })
      const md = reporter.generate(report)

      expect(md).toContain('strict-policy')
    })

    it('should handle unknown decision type gracefully', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const report = createMockReport({ decision: 'unknown' as any })
      const md = reporter.generate(report)

      expect(md).toContain('❓')
      expect(md).toContain('UNKNOWN')
    })

    it('should format location without line number', () => {
      const finding = createMockFinding({
        location: { file: 'src/config.ts' }
      })
      const report = createMockReport({ findings: [finding] })
      const md = reporter.generate(report)

      expect(md).toContain('`src/config.ts`')
      expect(md).not.toContain(':undefined')
    })
  })

  describe('write', () => {
    it('should write to file when output is specified', async () => {
      const report = createMockReport()
      await reporter.write(report, { output: '/tmp/report.md' })

      expect(mockWriteFile).toHaveBeenCalledWith(
        '/tmp/report.md',
        expect.any(String),
        'utf-8'
      )
    })

    it('should write to stdout when no output specified', async () => {
      const report = createMockReport()
      await reporter.write(report)

      expect(stdoutWriteSpy).toHaveBeenCalled()
      const output = stdoutWriteSpy.mock.calls[0][0] as string
      expect(output).toContain('# SkillGate Security Report')
    })

    it('should not write to stdout when quiet is true', async () => {
      const report = createMockReport()
      await reporter.write(report, { quiet: true })

      expect(stdoutWriteSpy).not.toHaveBeenCalled()
    })

    it('should write to file even when quiet is true', async () => {
      const report = createMockReport()
      await reporter.write(report, { output: '/tmp/report.md', quiet: true })

      expect(mockWriteFile).toHaveBeenCalled()
    })
  })

  describe('createMarkdownReporter', () => {
    it('should create a MarkdownReporter instance', () => {
      const reporter = createMarkdownReporter()

      expect(reporter).toBeInstanceOf(MarkdownReporter)
    })
  })
})
