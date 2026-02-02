import { describe, it, expect, beforeEach } from 'vitest'
import { join } from 'path'
import { PolicyLoader, PolicyLoadError, createPolicyLoader } from './loader.js'

const fixturesPath = join(import.meta.dirname, '__fixtures__')

describe('PolicyLoader', () => {
  let loader: PolicyLoader

  beforeEach(() => {
    loader = new PolicyLoader({ basePath: fixturesPath })
  })

  describe('load', () => {
    it('loads a valid policy file', async () => {
      const policy = await loader.load('valid-policy.yaml')

      expect(policy.version).toBe('1.0.0')
      expect(policy.name).toBe('test-policy')
      expect(policy.description).toBe('A test policy for unit tests')
      expect(policy.thresholds.block).toBe(40)
      expect(policy.thresholds.warn).toBe(70)
      expect(policy.critical_block).toContain('secret_aws_key')
      expect(policy.rules.secret_aws_key).toBeDefined()
      expect(policy.rules.secret_aws_key.severity).toBe('critical')
      expect(policy.exceptions).toHaveLength(1)
    })

    it('throws PolicyLoadError for non-existent file', async () => {
      await expect(loader.load('non-existent.yaml')).rejects.toThrow(PolicyLoadError)
    })

    it('throws PolicyLoadError for invalid policy', async () => {
      try {
        await loader.load('invalid-policy.yaml')
        expect.fail('Should have thrown')
      } catch (error) {
        expect(error).toBeInstanceOf(PolicyLoadError)
        const policyError = error as PolicyLoadError
        expect(policyError.validationErrors.length).toBeGreaterThan(0)
      }
    })

    it('caches loaded policies', async () => {
      const policy1 = await loader.load('valid-policy.yaml')
      const policy2 = await loader.load('valid-policy.yaml')

      expect(policy1).toBe(policy2) // Same reference
    })

    it('clears cache when requested', async () => {
      const policy1 = await loader.load('valid-policy.yaml')
      loader.clearCache()
      const policy2 = await loader.load('valid-policy.yaml')

      expect(policy1).not.toBe(policy2) // Different references
      expect(policy1).toEqual(policy2) // But same content
    })
  })

  describe('policy extends', () => {
    it('merges child policy with base policy', async () => {
      const policy = await loader.load('child-policy.yaml')

      // Child overrides
      expect(policy.version).toBe('1.1.0')
      expect(policy.name).toBe('child-policy')
      expect(policy.thresholds.warn).toBe(75)

      // Child thresholds with defaults (block not specified, uses default 40)
      expect(policy.thresholds.block).toBe(40)

      // Critical blocks merged
      expect(policy.critical_block).toContain('base_critical_rule')
      expect(policy.critical_block).toContain('child_critical_rule')

      // Rules merged
      expect(policy.rules.base_rule).toBeDefined()
      expect(policy.rules.child_rule).toBeDefined()

      // Child overrides shared rule
      expect(policy.rules.shared_rule.severity).toBe('high')
      expect(policy.rules.shared_rule.weight).toBe(-20)

      // Exceptions merged
      expect(policy.exceptions).toHaveLength(2)
    })

    it('does not extend when allowExtends is false', async () => {
      const loaderNoExtends = new PolicyLoader({
        basePath: fixturesPath,
        allowExtends: false
      })

      const policy = await loaderNoExtends.load('child-policy.yaml')

      // Should have extends field but not resolve it
      expect(policy.extends).toBe('./base-policy.yaml')

      // Should NOT have base rules
      expect(policy.rules.base_rule).toBeUndefined()
    })
  })

  describe('loadFromString', () => {
    it('parses valid YAML string', () => {
      const yamlContent = `
version: "1.0.0"
name: "inline-policy"
thresholds:
  block: 50
  warn: 80
rules:
  test_rule:
    severity: medium
    weight: -10
    message: "Test rule"
`
      const policy = loader.loadFromString(yamlContent)

      expect(policy.name).toBe('inline-policy')
      expect(policy.thresholds.block).toBe(50)
      expect(policy.rules.test_rule).toBeDefined()
    })

    it('throws for invalid YAML content', () => {
      const invalidYaml = `
version: "1.0"
name: ""
thresholds: {}
rules: {}
`
      expect(() => loader.loadFromString(invalidYaml)).toThrow()
    })
  })

  describe('validate', () => {
    it('returns valid: true for valid policy', async () => {
      const result = await loader.validate('valid-policy.yaml')

      expect(result.valid).toBe(true)
      expect(result.errors).toEqual([])
    })

    it('returns valid: false with errors for invalid policy', async () => {
      const result = await loader.validate('invalid-policy.yaml')

      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    it('returns valid: false for non-existent file', async () => {
      const result = await loader.validate('non-existent.yaml')

      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })
  })
})

describe('PolicyLoadError', () => {
  it('contains path and validation errors', () => {
    const error = new PolicyLoadError(
      'Test error message',
      '/path/to/policy.yaml',
      ['error1', 'error2']
    )

    expect(error.name).toBe('PolicyLoadError')
    expect(error.message).toBe('Test error message')
    expect(error.policyPath).toBe('/path/to/policy.yaml')
    expect(error.validationErrors).toEqual(['error1', 'error2'])
  })
})

describe('createPolicyLoader', () => {
  it('creates a PolicyLoader instance', () => {
    const loader = createPolicyLoader()
    expect(loader).toBeInstanceOf(PolicyLoader)
  })

  it('passes options to PolicyLoader', () => {
    const loader = createPolicyLoader({ basePath: '/custom/path' })
    expect(loader).toBeInstanceOf(PolicyLoader)
  })
})
