import { describe, it, expect } from 'vitest'
import { readFile } from 'fs/promises'
import { join } from 'path'
import yaml from 'js-yaml'
import { validatePolicySafe, formatValidationErrors } from './schema.js'

describe('Default Policy', () => {
  it('passes validation', async () => {
    const policyPath = join(import.meta.dirname, '../../../policies/default.yaml')
    const content = await readFile(policyPath, 'utf-8')
    const rawPolicy = yaml.load(content)

    const result = validatePolicySafe(rawPolicy)

    if (!result.success) {
      const errors = formatValidationErrors(result.errors!)
      throw new Error(`Default policy validation failed:\n${errors.join('\n')}`)
    }

    expect(result.success).toBe(true)
    expect(result.data).toBeDefined()
  })

  it('has required structure', async () => {
    const policyPath = join(import.meta.dirname, '../../../policies/default.yaml')
    const content = await readFile(policyPath, 'utf-8')
    const rawPolicy = yaml.load(content)
    const result = validatePolicySafe(rawPolicy)

    expect(result.success).toBe(true)
    const policy = result.data!

    // Check basic structure
    expect(policy.version).toBe('1.0')
    expect(policy.name).toBe('skillgate-default')
    expect(policy.description).toBeDefined()

    // Check thresholds
    expect(policy.thresholds.block).toBe(40)
    expect(policy.thresholds.warn).toBe(70)

    // Check critical_block has entries
    expect(policy.critical_block.length).toBeGreaterThan(0)

    // Check rules has entries
    expect(Object.keys(policy.rules).length).toBeGreaterThan(0)

    // Check exceptions
    expect(policy.exceptions.length).toBeGreaterThan(0)
  })

  it('has all critical_block rules defined in rules', async () => {
    const policyPath = join(import.meta.dirname, '../../../policies/default.yaml')
    const content = await readFile(policyPath, 'utf-8')
    const rawPolicy = yaml.load(content)
    const result = validatePolicySafe(rawPolicy)
    const policy = result.data!

    for (const ruleId of policy.critical_block) {
      expect(
        policy.rules[ruleId],
        `Rule "${ruleId}" is in critical_block but not defined in rules`
      ).toBeDefined()
    }
  })

  it('has critical severity for critical_block rules', async () => {
    const policyPath = join(import.meta.dirname, '../../../policies/default.yaml')
    const content = await readFile(policyPath, 'utf-8')
    const rawPolicy = yaml.load(content)
    const result = validatePolicySafe(rawPolicy)
    const policy = result.data!

    for (const ruleId of policy.critical_block) {
      const rule = policy.rules[ruleId]
      expect(
        rule.severity,
        `Rule "${ruleId}" in critical_block should have critical severity`
      ).toBe('critical')
    }
  })

  it('covers all scanner categories', async () => {
    const policyPath = join(import.meta.dirname, '../../../policies/default.yaml')
    const content = await readFile(policyPath, 'utf-8')
    const rawPolicy = yaml.load(content)
    const result = validatePolicySafe(rawPolicy)
    const policy = result.data!

    const ruleIds = Object.keys(policy.rules)

    // Check each scanner category has rules
    const categories = ['secret_', 'skill_', 'static_', 'entrypoint_', 'dependency_', 'ci_']

    for (const category of categories) {
      const categoryRules = ruleIds.filter(id => id.startsWith(category))
      expect(
        categoryRules.length,
        `No rules found for category "${category}"`
      ).toBeGreaterThan(0)
    }
  })
})
