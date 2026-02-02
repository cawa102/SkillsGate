#!/usr/bin/env node
/**
 * SkillGate CLI entry point
 *
 * Security scanner for Claude Code skills (.md files)
 */

import { Command } from 'commander'
import { createLogger } from '../utils/logger.js'
import { createPolicyLoader } from '../core/policy/loader.js'
import { initCommand, DEFAULT_OUTPUT_FILENAME } from './commands/init.js'
import { registerScanCommand } from './commands/scan.js'

/**
 * Exit codes for the CLI
 * - 0: allow (safe to install)
 * - 1: block (installation blocked)
 * - 2: quarantine (sandboxed execution recommended)
 * - 3: error (scan failed)
 */
export const ExitCode = {
  ALLOW: 0,
  BLOCK: 1,
  QUARANTINE: 2,
  ERROR: 3
} as const

export type ExitCodeType = (typeof ExitCode)[keyof typeof ExitCode]

/**
 * Global CLI options
 */
export interface GlobalOptions {
  verbose?: boolean
  quiet?: boolean
  config?: string
}

const logger = createLogger('cli')

/**
 * Create and configure the CLI program
 */
export function createProgram(): Command {
  const program = new Command()

  program
    .name('sg')
    .description('Security scanner for Claude Code skills')
    .version('1.0.0')
    .option('-v, --verbose', 'Enable verbose output')
    .option('-q, --quiet', 'Suppress output except errors')
    .option('-c, --config <path>', 'Path to policy configuration file')

  // Register scan command
  registerScanCommand(program)

  program
    .command('init')
    .description('Generate a default policy configuration file')
    .option('-o, --output <file>', 'Output file path', DEFAULT_OUTPUT_FILENAME)
    .option('--force', 'Overwrite existing file')
    .action(async (options: { output?: string; force?: boolean }) => {
      const globalOpts = program.opts() as GlobalOptions

      const result = await initCommand({
        output: options.output,
        force: options.force
      })

      if (result.success) {
        if (!globalOpts.quiet) {
          logger.info(`Created policy file: ${result.outputPath}`)
        }
        process.exit(ExitCode.ALLOW)
      } else {
        if (!globalOpts.quiet) {
          logger.error(`Failed to create policy file: ${result.error}`)
        }
        process.exit(ExitCode.ERROR)
      }
    })

  program
    .command('validate <policy>')
    .description('Validate a policy configuration file')
    .action(async (policy: string) => {
      const globalOpts = program.opts() as GlobalOptions
      try {
        const loader = createPolicyLoader()
        const result = await loader.validate(policy)

        if (result.valid) {
          if (!globalOpts.quiet) {
            logger.info(`✓ Policy file is valid: ${policy}`)
          }
          process.exit(ExitCode.ALLOW)
        } else {
          if (!globalOpts.quiet) {
            logger.error(`✗ Policy file is invalid: ${policy}`)
            for (const error of result.errors) {
              logger.error(`  - ${error}`)
            }
          }
          process.exit(ExitCode.ERROR)
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        if (!globalOpts.quiet) {
          logger.error(`Failed to validate policy: ${message}`)
        }
        process.exit(ExitCode.ERROR)
      }
    })

  return program
}

/**
 * Run the CLI
 */
export async function run(args: string[] = process.argv): Promise<void> {
  const program = createProgram()

  try {
    await program.parseAsync(args)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    logger.error(`CLI error: ${message}`)
    process.exit(ExitCode.ERROR)
  }
}

// Run CLI when executed directly (not when imported as a module)
// Use decodeURIComponent to handle paths with spaces or special characters
const isMainModule =
  import.meta.url === `file://${process.argv[1]}` ||
  decodeURIComponent(import.meta.url) === `file://${process.argv[1]}`
if (isMainModule) {
  run()
}
