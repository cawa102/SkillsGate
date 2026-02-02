/**
 * init command - Generate a default policy configuration file
 *
 * Ticket: 024
 */

import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

export const DEFAULT_OUTPUT_FILENAME = 'skillgate.policy.yaml'

export interface InitOptions {
  output?: string
  force?: boolean
}

export interface InitResult {
  success: boolean
  outputPath?: string
  error?: string
}

/**
 * Get the path to the default policy file bundled with the package
 */
function getDefaultPolicyPath(): string {
  const __filename = fileURLToPath(import.meta.url)
  const __dirname = path.dirname(__filename)

  // Navigate from src/cli/commands to policies/default.yaml
  // In development: src/cli/commands -> policies
  // In dist: dist/cli/commands -> policies
  const projectRoot = path.resolve(__dirname, '..', '..', '..')
  return path.join(projectRoot, 'policies', 'default.yaml')
}

/**
 * Execute the init command
 *
 * @param options - Command options
 * @returns Result of the operation
 */
export async function initCommand(options: InitOptions): Promise<InitResult> {
  const outputPath = path.resolve(
    process.cwd(),
    options.output ?? DEFAULT_OUTPUT_FILENAME
  )

  try {
    // Check if file already exists
    if (fs.existsSync(outputPath) && !options.force) {
      return {
        success: false,
        outputPath,
        error: `File already exists: ${outputPath}. Use --force to overwrite.`
      }
    }

    // Read default policy
    const defaultPolicyPath = getDefaultPolicyPath()
    const policyContent = fs.readFileSync(defaultPolicyPath, 'utf-8')

    // Create parent directories if needed
    const parentDir = path.dirname(outputPath)
    if (parentDir !== '.' && parentDir !== outputPath) {
      fs.mkdirSync(parentDir, { recursive: true })
    }

    // Write policy file
    fs.writeFileSync(outputPath, policyContent, 'utf-8')

    return {
      success: true,
      outputPath
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    return {
      success: false,
      outputPath,
      error: message
    }
  }
}
