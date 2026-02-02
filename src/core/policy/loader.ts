import { readFile } from 'fs/promises'
import { join, dirname, resolve } from 'path'
import yaml from 'js-yaml'
import { Policy, validatePolicy, validatePolicySafe, formatValidationErrors } from './schema.js'

export interface LoaderOptions {
  basePath?: string
  allowExtends?: boolean
}

export class PolicyLoader {
  private cache = new Map<string, Policy>()
  private basePath: string
  private allowExtends: boolean

  constructor(options: LoaderOptions = {}) {
    this.basePath = options.basePath || process.cwd()
    this.allowExtends = options.allowExtends ?? true
  }

  /**
   * Load policy from file path
   */
  async load(policyPath: string): Promise<Policy> {
    const absolutePath = resolve(this.basePath, policyPath)

    // Check cache
    if (this.cache.has(absolutePath)) {
      return this.cache.get(absolutePath)!
    }

    // Read file
    const content = await this.readPolicyFile(absolutePath)

    // Parse YAML
    const rawPolicy = yaml.load(content)

    // Validate
    const validation = validatePolicySafe(rawPolicy)
    if (!validation.success) {
      const errors = formatValidationErrors(validation.errors!)
      throw new PolicyLoadError(
        `Invalid policy file: ${policyPath}\n${errors.join('\n')}`,
        absolutePath,
        errors
      )
    }

    let policy = validation.data!

    // Handle extends
    if (policy.extends && this.allowExtends) {
      const basePolicy = await this.load(
        join(dirname(absolutePath), policy.extends)
      )
      policy = this.mergePolicy(basePolicy, policy)
    }

    // Cache and return
    this.cache.set(absolutePath, policy)
    return policy
  }

  /**
   * Load default policy from package
   */
  async loadDefault(): Promise<Policy> {
    const defaultPath = join(import.meta.dirname, '../../../policies/default.yaml')
    return this.load(defaultPath)
  }

  /**
   * Load policy from string content
   */
  loadFromString(content: string): Policy {
    const rawPolicy = yaml.load(content)
    return validatePolicy(rawPolicy)
  }

  /**
   * Validate policy file without loading
   */
  async validate(policyPath: string): Promise<{
    valid: boolean
    errors: string[]
  }> {
    try {
      const absolutePath = resolve(this.basePath, policyPath)
      const content = await this.readPolicyFile(absolutePath)
      const rawPolicy = yaml.load(content)
      const validation = validatePolicySafe(rawPolicy)

      if (validation.success) {
        return { valid: true, errors: [] }
      }

      return {
        valid: false,
        errors: formatValidationErrors(validation.errors!)
      }
    } catch (error) {
      if (error instanceof PolicyLoadError) {
        return { valid: false, errors: error.validationErrors }
      }
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : String(error)]
      }
    }
  }

  /**
   * Clear the policy cache
   */
  clearCache(): void {
    this.cache.clear()
  }

  private async readPolicyFile(absolutePath: string): Promise<string> {
    try {
      return await readFile(absolutePath, 'utf-8')
    } catch (error) {
      throw new PolicyLoadError(
        `Failed to read policy file: ${absolutePath}`,
        absolutePath,
        [(error as NodeJS.ErrnoException).code || 'UNKNOWN']
      )
    }
  }

  private mergePolicy(base: Policy, override: Policy): Policy {
    return {
      ...base,
      ...override,
      thresholds: {
        ...base.thresholds,
        ...override.thresholds
      },
      critical_block: [
        ...new Set([...base.critical_block, ...override.critical_block])
      ],
      rules: {
        ...base.rules,
        ...override.rules
      },
      exceptions: [
        ...base.exceptions,
        ...override.exceptions
      ]
    }
  }
}

/**
 * Custom error for policy loading failures
 */
export class PolicyLoadError extends Error {
  constructor(
    message: string,
    public readonly policyPath: string,
    public readonly validationErrors: string[]
  ) {
    super(message)
    this.name = 'PolicyLoadError'
  }
}

/**
 * Create a default loader instance
 */
export function createPolicyLoader(options?: LoaderOptions): PolicyLoader {
  return new PolicyLoader(options)
}
