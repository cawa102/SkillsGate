import { describe, it, expect } from 'vitest'
import {
  SeveritySchema,
  ThresholdsSchema,
  RuleDefinitionSchema,
  ExceptionSchema,
  PolicySchema,
  validatePolicy,
  validatePolicySafe,
  formatValidationErrors
} from './schema.js'

describe('SeveritySchema', () => {
  it('accepts valid severity levels', () => {
    expect(SeveritySchema.parse('critical')).toBe('critical')
    expect(SeveritySchema.parse('high')).toBe('high')
    expect(SeveritySchema.parse('medium')).toBe('medium')
    expect(SeveritySchema.parse('low')).toBe('low')
    expect(SeveritySchema.parse('info')).toBe('info')
  })

  it('rejects invalid severity', () => {
    expect(() => SeveritySchema.parse('invalid')).toThrow()
  })
})

describe('ThresholdsSchema', () => {
  it('accepts valid thresholds', () => {
    const result = ThresholdsSchema.parse({ block: 30, warn: 60 })
    expect(result.block).toBe(30)
    expect(result.warn).toBe(60)
  })

  it('applies default values', () => {
    const result = ThresholdsSchema.parse({})
    expect(result.block).toBe(40)
    expect(result.warn).toBe(70)
  })

  it('rejects block > warn', () => {
    expect(() => ThresholdsSchema.parse({ block: 80, warn: 50 })).toThrow(
      'Block threshold must be <= warn threshold'
    )
  })

  it('rejects values outside 0-100 range', () => {
    expect(() => ThresholdsSchema.parse({ block: -10 })).toThrow()
    expect(() => ThresholdsSchema.parse({ warn: 150 })).toThrow()
  })
})

describe('RuleDefinitionSchema', () => {
  it('accepts valid rule definition', () => {
    const rule = {
      severity: 'high',
      weight: -20,
      message: 'Detected dangerous pattern'
    }
    const result = RuleDefinitionSchema.parse(rule)
    expect(result.severity).toBe('high')
    expect(result.weight).toBe(-20)
    expect(result.message).toBe('Detected dangerous pattern')
    expect(result.enabled).toBe(true)
  })

  it('accepts explicit enabled flag', () => {
    const rule = {
      severity: 'medium',
      weight: -10,
      message: 'Test rule',
      enabled: false
    }
    const result = RuleDefinitionSchema.parse(rule)
    expect(result.enabled).toBe(false)
  })

  it('rejects empty message', () => {
    const rule = {
      severity: 'low',
      weight: -5,
      message: ''
    }
    expect(() => RuleDefinitionSchema.parse(rule)).toThrow('Message is required')
  })
})

describe('ExceptionSchema', () => {
  it('accepts valid exception', () => {
    const exception = {
      pattern: 'test/**/*.ts',
      ignore: ['secret_detection'],
      reason: 'Test files contain mock secrets'
    }
    const result = ExceptionSchema.parse(exception)
    expect(result.pattern).toBe('test/**/*.ts')
    expect(result.ignore).toEqual(['secret_detection'])
    expect(result.reason).toBe('Test files contain mock secrets')
  })

  it('accepts exception without reason', () => {
    const exception = {
      pattern: '*.test.ts',
      ignore: ['rule1']
    }
    const result = ExceptionSchema.parse(exception)
    expect(result.reason).toBeUndefined()
  })

  it('rejects empty pattern', () => {
    const exception = {
      pattern: '',
      ignore: ['rule1']
    }
    expect(() => ExceptionSchema.parse(exception)).toThrow('Pattern is required')
  })

  it('rejects empty ignore array', () => {
    const exception = {
      pattern: '*.ts',
      ignore: []
    }
    expect(() => ExceptionSchema.parse(exception)).toThrow(
      'At least one rule to ignore is required'
    )
  })
})

describe('PolicySchema', () => {
  const validPolicy = {
    version: '1.0.0',
    name: 'test-policy',
    thresholds: { block: 40, warn: 70 },
    rules: {
      secret_aws: {
        severity: 'critical',
        weight: -50,
        message: 'AWS credentials detected'
      }
    }
  }

  it('accepts valid policy', () => {
    const result = PolicySchema.parse(validPolicy)
    expect(result.version).toBe('1.0.0')
    expect(result.name).toBe('test-policy')
    expect(result.critical_block).toEqual([])
    expect(result.exceptions).toEqual([])
  })

  it('accepts policy with all optional fields', () => {
    const fullPolicy = {
      ...validPolicy,
      description: 'A comprehensive security policy',
      extends: 'base-policy',
      critical_block: ['secret_aws'],
      exceptions: [
        { pattern: 'test/**', ignore: ['secret_aws'], reason: 'Test files' }
      ]
    }
    const result = PolicySchema.parse(fullPolicy)
    expect(result.description).toBe('A comprehensive security policy')
    expect(result.extends).toBe('base-policy')
    expect(result.critical_block).toEqual(['secret_aws'])
    expect(result.exceptions).toHaveLength(1)
  })

  it('rejects invalid version format', () => {
    const invalid = { ...validPolicy, version: 'v1' }
    expect(() => PolicySchema.parse(invalid)).toThrow('Version must be semver format')
  })

  it('accepts semver with two parts', () => {
    const policy = { ...validPolicy, version: '1.0' }
    const result = PolicySchema.parse(policy)
    expect(result.version).toBe('1.0')
  })

  it('rejects empty policy name', () => {
    const invalid = { ...validPolicy, name: '' }
    expect(() => PolicySchema.parse(invalid)).toThrow('Policy name is required')
  })

  it('rejects policy name too long', () => {
    const invalid = { ...validPolicy, name: 'a'.repeat(51) }
    expect(() => PolicySchema.parse(invalid)).toThrow('Policy name too long')
  })
})

describe('validatePolicy', () => {
  it('returns parsed policy for valid input', () => {
    const input = {
      version: '1.0.0',
      name: 'test',
      thresholds: {},
      rules: {}
    }
    const result = validatePolicy(input)
    expect(result.name).toBe('test')
    expect(result.thresholds.block).toBe(40)
  })

  it('throws for invalid input', () => {
    expect(() => validatePolicy({})).toThrow()
  })
})

describe('validatePolicySafe', () => {
  it('returns success with data for valid input', () => {
    const input = {
      version: '1.0.0',
      name: 'test',
      thresholds: {},
      rules: {}
    }
    const result = validatePolicySafe(input)
    expect(result.success).toBe(true)
    expect(result.data?.name).toBe('test')
    expect(result.errors).toBeUndefined()
  })

  it('returns failure with errors for invalid input', () => {
    const result = validatePolicySafe({})
    expect(result.success).toBe(false)
    expect(result.data).toBeUndefined()
    expect(result.errors).toBeDefined()
  })
})

describe('formatValidationErrors', () => {
  it('formats errors with path and message', () => {
    const result = validatePolicySafe({
      version: 'invalid',
      name: '',
      thresholds: { block: 200 }
    })

    expect(result.success).toBe(false)
    if (result.errors) {
      const formatted = formatValidationErrors(result.errors)
      expect(formatted.some(e => e.includes('version'))).toBe(true)
      expect(formatted.some(e => e.includes('name'))).toBe(true)
    }
  })

  it('handles nested path errors', () => {
    const result = validatePolicySafe({
      version: '1.0.0',
      name: 'test',
      thresholds: { block: 80, warn: 50 },
      rules: {}
    })

    expect(result.success).toBe(false)
    if (result.errors) {
      const formatted = formatValidationErrors(result.errors)
      expect(formatted.some(e => e.includes('Block threshold must be <= warn threshold'))).toBe(true)
    }
  })
})
