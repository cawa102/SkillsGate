import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type { Finding } from '../../types/index.js'
import type { Policy } from '../policy/schema.js'
import { Enforcer, ExitCodes, createEnforcer } from './index.js'

const createTestPolicy = (overrides: Partial<Policy> = {}): Policy => ({
  version: '1.0.0',
  name: 'test-policy',
  thresholds: { block: 40, warn: 70 },
  critical_block: [],
  rules: {},
  exceptions: [],
  ...overrides
})

const createFinding = (overrides: Partial<Finding> = {}): Finding => ({
  scanner: 'secret',
  severity: 'high',
  rule: 'test_rule',
  message: 'Test finding',
  location: { file: 'src/test.ts', line: 10 },
  ...overrides
})

describe('ExitCodes', () => {
  it('has correct exit codes', () => {
    expect(ExitCodes.allow).toBe(0)
    expect(ExitCodes.block).toBe(1)
    expect(ExitCodes.quarantine).toBe(2)
    expect(ExitCodes.error).toBe(3)
  })
})

describe('Enforcer', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-02-02T12:00:00Z'))
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('enforce', () => {
    it('returns allow for no findings', () => {
      const enforcer = new Enforcer(createTestPolicy())
      const result = enforcer.enforce([])

      expect(result.decision).toBe('allow')
      expect(result.exitCode).toBe(0)
      expect(result.evaluation.score).toBe(100)
      expect(result.summary).toContain('ALLOWED')
      expect(result.summary).toContain('No security issues detected')
      expect(result.policyName).toBe('test-policy')
      expect(result.timestamp).toBe('2026-02-02T12:00:00.000Z')
    })

    it('returns block for critical block rules', () => {
      const policy = createTestPolicy({
        critical_block: ['secret_leak'],
        rules: {
          secret_leak: {
            severity: 'critical',
            weight: -50,
            message: 'Secret detected',
            enabled: true
          }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([
        createFinding({ rule: 'secret_leak', severity: 'critical' })
      ])

      expect(result.decision).toBe('block')
      expect(result.exitCode).toBe(1)
      expect(result.reasons).toContain('Critical block rules triggered: secret_leak')
    })

    it('returns block when score <= block threshold', () => {
      const policy = createTestPolicy({
        thresholds: { block: 40, warn: 70 },
        rules: {
          rule1: { severity: 'critical', weight: -30, message: 'Rule 1', enabled: true },
          rule2: { severity: 'critical', weight: -35, message: 'Rule 2', enabled: true }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([
        createFinding({ rule: 'rule1', severity: 'critical' }),
        createFinding({ rule: 'rule2', severity: 'critical' })
      ])

      expect(result.decision).toBe('block')
      expect(result.exitCode).toBe(1)
      expect(result.evaluation.score).toBe(35)
      expect(result.reasons.some(r => r.includes('at or below block threshold'))).toBe(true)
    })

    it('returns quarantine when score <= warn threshold', () => {
      const policy = createTestPolicy({
        thresholds: { block: 40, warn: 70 },
        rules: {
          test_rule: { severity: 'high', weight: -35, message: 'Test', enabled: true }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([createFinding()])

      expect(result.decision).toBe('quarantine')
      expect(result.exitCode).toBe(2)
      expect(result.evaluation.score).toBe(65)
      expect(result.reasons.some(r => r.includes('at or below warn threshold'))).toBe(true)
    })

    it('returns allow when score > warn threshold', () => {
      const policy = createTestPolicy({
        thresholds: { block: 40, warn: 70 },
        rules: {
          test_rule: { severity: 'low', weight: -5, message: 'Minor issue', enabled: true }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([createFinding()])

      expect(result.decision).toBe('allow')
      expect(result.exitCode).toBe(0)
      expect(result.evaluation.score).toBe(95)
    })

    it('includes triggered rules in reasons', () => {
      const policy = createTestPolicy({
        rules: {
          test_rule: { severity: 'high', weight: -10, message: 'Test issue', enabled: true }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([
        createFinding(),
        createFinding({ location: { file: 'other.ts' } })
      ])

      expect(result.reasons.some(r =>
        r.includes('HIGH') && r.includes('Test issue') && r.includes('2 occurrences')
      )).toBe(true)
    })

    it('includes suppressed findings in reasons', () => {
      const policy = createTestPolicy({
        exceptions: [
          { pattern: 'test/**', ignore: ['test_rule'] }
        ]
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([
        createFinding({ location: { file: 'test/foo.ts' } })
      ])

      expect(result.reasons.some(r => r.includes('suppressed by exceptions'))).toBe(true)
      expect(result.evaluation.suppressedFindings).toHaveLength(1)
    })

    it('builds correct summary for findings', () => {
      const policy = createTestPolicy({
        rules: {
          rule1: { severity: 'high', weight: -10, message: 'Rule 1', enabled: true },
          rule2: { severity: 'medium', weight: -5, message: 'Rule 2', enabled: true }
        }
      })
      const enforcer = new Enforcer(policy)
      const result = enforcer.enforce([
        createFinding({ rule: 'rule1' }),
        createFinding({ rule: 'rule1', location: { file: 'b.ts' } }),
        createFinding({ rule: 'rule2' })
      ])

      expect(result.summary).toContain('3 finding(s)')
      expect(result.summary).toContain('2 rule(s)')
      expect(result.summary).toContain('Score: 85/100')
    })
  })

  describe('accessors', () => {
    it('returns policy name', () => {
      const enforcer = new Enforcer(createTestPolicy({ name: 'my-policy' }))
      expect(enforcer.policyName).toBe('my-policy')
    })

    it('returns thresholds', () => {
      const enforcer = new Enforcer(
        createTestPolicy({ thresholds: { block: 30, warn: 60 } })
      )
      expect(enforcer.thresholds).toEqual({ block: 30, warn: 60 })
    })
  })
})

describe('createEnforcer', () => {
  it('creates an Enforcer instance', () => {
    const enforcer = createEnforcer(createTestPolicy())
    expect(enforcer).toBeInstanceOf(Enforcer)
  })
})
