import { describe, it, expect } from 'vitest'
import type { Finding } from '../../types/index.js'
import type { Policy } from './schema.js'
import { PolicyEngine, createPolicyEngine } from './engine.js'

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

describe('PolicyEngine', () => {
  describe('evaluate', () => {
    it('returns perfect score with no findings', () => {
      const engine = new PolicyEngine(createTestPolicy())
      const result = engine.evaluate([])

      expect(result.score).toBe(100)
      expect(result.triggeredRules).toEqual([])
      expect(result.hasCriticalBlock).toBe(false)
      expect(result.suppressedFindings).toEqual([])
    })

    it('applies rule weight to score', () => {
      const policy = createTestPolicy({
        rules: {
          test_rule: {
            severity: 'high',
            weight: -30,
            message: 'Test rule triggered',
            enabled: true
          }
        }
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([createFinding()])

      expect(result.score).toBe(70)
      expect(result.triggeredRules).toHaveLength(1)
      expect(result.triggeredRules[0].rule).toBe('test_rule')
      expect(result.triggeredRules[0].count).toBe(1)
    })

    it('applies weight only once for duplicate rules', () => {
      const policy = createTestPolicy({
        rules: {
          test_rule: {
            severity: 'high',
            weight: -20,
            message: 'Test rule',
            enabled: true
          }
        }
      })
      const engine = new PolicyEngine(policy)
      const findings = [
        createFinding({ location: { file: 'file1.ts' } }),
        createFinding({ location: { file: 'file2.ts' } }),
        createFinding({ location: { file: 'file3.ts' } })
      ]
      const result = engine.evaluate(findings)

      expect(result.score).toBe(80) // Only -20, not -60
      expect(result.triggeredRules[0].count).toBe(3)
      expect(result.triggeredRules[0].findings).toHaveLength(3)
    })

    it('uses default weight when rule not in policy', () => {
      const engine = new PolicyEngine(createTestPolicy())
      const result = engine.evaluate([createFinding({ severity: 'high' })])

      expect(result.score).toBe(80) // Default high = -20
    })

    it('uses correct default weights for each severity', () => {
      const engine = new PolicyEngine(createTestPolicy())

      const criticalResult = engine.evaluate([
        createFinding({ rule: 'r1', severity: 'critical' })
      ])
      expect(criticalResult.score).toBe(50) // -50

      const mediumResult = engine.evaluate([
        createFinding({ rule: 'r2', severity: 'medium' })
      ])
      expect(mediumResult.score).toBe(90) // -10

      const lowResult = engine.evaluate([
        createFinding({ rule: 'r3', severity: 'low' })
      ])
      expect(lowResult.score).toBe(95) // -5

      const infoResult = engine.evaluate([
        createFinding({ rule: 'r4', severity: 'info' })
      ])
      expect(infoResult.score).toBe(100) // 0
    })

    it('clamps score to 0-100', () => {
      const policy = createTestPolicy({
        rules: {
          critical_rule: {
            severity: 'critical',
            weight: -200,
            message: 'Critical issue',
            enabled: true
          }
        }
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ rule: 'critical_rule' })
      ])

      expect(result.score).toBe(0)
    })

    it('skips disabled rules', () => {
      const policy = createTestPolicy({
        rules: {
          disabled_rule: {
            severity: 'high',
            weight: -30,
            message: 'Disabled rule',
            enabled: false
          }
        }
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ rule: 'disabled_rule' })
      ])

      expect(result.score).toBe(100)
      expect(result.triggeredRules).toHaveLength(0)
    })
  })

  describe('critical_block', () => {
    it('detects critical block rules', () => {
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
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ rule: 'secret_leak' })
      ])

      expect(result.hasCriticalBlock).toBe(true)
      expect(result.criticalBlockRules).toContain('secret_leak')
    })

    it('does not mark non-critical-block rules', () => {
      const policy = createTestPolicy({
        critical_block: ['other_rule'],
        rules: {
          test_rule: {
            severity: 'high',
            weight: -20,
            message: 'Test',
            enabled: true
          }
        }
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([createFinding()])

      expect(result.hasCriticalBlock).toBe(false)
      expect(result.criticalBlockRules).toEqual([])
    })
  })

  describe('exceptions', () => {
    it('suppresses findings matching exception pattern', () => {
      const policy = createTestPolicy({
        exceptions: [
          { pattern: 'test/**/*.ts', ignore: ['test_rule'] }
        ]
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ location: { file: 'test/unit/foo.ts' } })
      ])

      expect(result.score).toBe(100)
      expect(result.triggeredRules).toHaveLength(0)
      expect(result.suppressedFindings).toHaveLength(1)
    })

    it('does not suppress if rule not in ignore list', () => {
      const policy = createTestPolicy({
        exceptions: [
          { pattern: 'test/**/*.ts', ignore: ['other_rule'] }
        ]
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ location: { file: 'test/unit/foo.ts' } })
      ])

      expect(result.triggeredRules).toHaveLength(1)
      expect(result.suppressedFindings).toHaveLength(0)
    })

    it('does not suppress if file does not match pattern', () => {
      const policy = createTestPolicy({
        exceptions: [
          { pattern: 'test/**/*.ts', ignore: ['test_rule'] }
        ]
      })
      const engine = new PolicyEngine(policy)
      const result = engine.evaluate([
        createFinding({ location: { file: 'src/main.ts' } })
      ])

      expect(result.triggeredRules).toHaveLength(1)
      expect(result.suppressedFindings).toHaveLength(0)
    })
  })

  describe('getDecision', () => {
    it('returns block for critical block', () => {
      const engine = new PolicyEngine(createTestPolicy())
      const result = engine.getDecision({
        score: 100,
        triggeredRules: [],
        hasCriticalBlock: true,
        criticalBlockRules: ['secret_leak'],
        suppressedFindings: []
      })

      expect(result).toBe('block')
    })

    it('returns block when score <= block threshold', () => {
      const engine = new PolicyEngine(createTestPolicy({ thresholds: { block: 40, warn: 70 } }))
      const result = engine.getDecision({
        score: 40,
        triggeredRules: [],
        hasCriticalBlock: false,
        criticalBlockRules: [],
        suppressedFindings: []
      })

      expect(result).toBe('block')
    })

    it('returns quarantine when score <= warn threshold', () => {
      const engine = new PolicyEngine(createTestPolicy({ thresholds: { block: 40, warn: 70 } }))
      const result = engine.getDecision({
        score: 60,
        triggeredRules: [],
        hasCriticalBlock: false,
        criticalBlockRules: [],
        suppressedFindings: []
      })

      expect(result).toBe('quarantine')
    })

    it('returns allow when score > warn threshold', () => {
      const engine = new PolicyEngine(createTestPolicy({ thresholds: { block: 40, warn: 70 } }))
      const result = engine.getDecision({
        score: 80,
        triggeredRules: [],
        hasCriticalBlock: false,
        criticalBlockRules: [],
        suppressedFindings: []
      })

      expect(result).toBe('allow')
    })
  })

  describe('accessors', () => {
    it('returns policy name', () => {
      const engine = new PolicyEngine(createTestPolicy({ name: 'my-policy' }))
      expect(engine.name).toBe('my-policy')
    })

    it('returns policy thresholds', () => {
      const engine = new PolicyEngine(
        createTestPolicy({ thresholds: { block: 30, warn: 60 } })
      )
      expect(engine.thresholds).toEqual({ block: 30, warn: 60 })
    })
  })
})

describe('createPolicyEngine', () => {
  it('creates a PolicyEngine instance', () => {
    const engine = createPolicyEngine(createTestPolicy())
    expect(engine).toBeInstanceOf(PolicyEngine)
  })
})
