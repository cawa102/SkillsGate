/**
 * Scan command implementation
 *
 * Orchestrates the full scan flow:
 * Source → Ingestor → Scanners (parallel) → Policy Engine → Enforcer → Reporter
 */

import type { Command } from 'commander'
import type { GlobalOptions } from '../index.js'
import { ExitCode } from '../index.js'
import { createLogger } from '../../utils/logger.js'
import {
  LocalIngestor,
  GitIngestor,
  ArchiveIngestor,
  type IngestResult,
  type IngestorSource,
  type SourceType
} from '../../core/ingestor/index.js'
import {
  ScannerOrchestrator,
  SecretScanner,
  StaticAnalyzer,
  SkillScanner,
  EntrypointDetector,
  DependencyScanner,
  CIRiskAnalyzer,
  type ScanContext
} from '../../core/scanner/index.js'
import { PolicyLoader } from '../../core/policy/loader.js'
import { Enforcer } from '../../core/enforcer/index.js'
import { JsonReporter } from '../../core/reporter/json.js'
import { MarkdownReporter } from '../../core/reporter/markdown.js'
import type { Finding, ScanReport, SourceInfo } from '../../types/index.js'

const logger = createLogger('scan')

/**
 * Scan command options
 */
export interface ScanOptions {
  output?: string
  format?: 'json' | 'markdown'
  policy?: string
}

/**
 * Detect source type from input string
 */
export function detectSourceType(source: string): SourceType {
  // Git URL patterns
  if (
    source.startsWith('git@') ||
    source.startsWith('https://github.com') ||
    source.startsWith('https://gitlab.com') ||
    source.startsWith('https://bitbucket.org') ||
    source.endsWith('.git')
  ) {
    return 'git'
  }

  // Archive patterns
  if (
    source.endsWith('.zip') ||
    source.endsWith('.tar.gz') ||
    source.endsWith('.tgz') ||
    source.endsWith('.tar')
  ) {
    return 'archive'
  }

  // Default to local
  return 'local'
}

/**
 * Ingest source based on detected type
 */
async function ingestSource(source: string): Promise<IngestResult> {
  const sourceType = detectSourceType(source)
  const ingestorSource: IngestorSource = {
    type: sourceType,
    location: source
  }

  switch (sourceType) {
    case 'git': {
      const ingestor = new GitIngestor()
      return ingestor.ingest(ingestorSource)
    }
    case 'archive': {
      const ingestor = new ArchiveIngestor()
      return ingestor.ingest(ingestorSource)
    }
    case 'local':
    default: {
      const ingestor = new LocalIngestor()
      return ingestor.ingest(ingestorSource)
    }
  }
}

/**
 * Create and configure scanner orchestrator with all scanners
 */
function createOrchestrator(): ScannerOrchestrator {
  const orchestrator = new ScannerOrchestrator()

  orchestrator.register(new SecretScanner())
  orchestrator.register(new StaticAnalyzer())
  orchestrator.register(new SkillScanner())
  orchestrator.register(new EntrypointDetector())
  orchestrator.register(new DependencyScanner())
  orchestrator.register(new CIRiskAnalyzer())

  return orchestrator
}

/**
 * Build source info for report
 */
function buildSourceInfo(
  source: string,
  sourceType: SourceType,
  context: { sourceHash: string; metadata: { commitSha?: string } }
): SourceInfo {
  const info: SourceInfo = {
    type: sourceType,
    path: source,
    hash: context.sourceHash
  }

  if (sourceType === 'git') {
    info.url = source
    if (context.metadata.commitSha) {
      info.commit = context.metadata.commitSha
    }
  }

  return info
}

/**
 * Execute scan command
 */
export async function executeScan(
  source: string,
  options: ScanOptions,
  globalOptions: GlobalOptions
): Promise<number> {
  const startTime = Date.now()
  const errors: string[] = []

  try {
    // 1. Ingest source
    if (globalOptions.verbose) {
      logger.info(`Ingesting source: ${source}`)
    }

    const ingestResult = await ingestSource(source)

    if (!ingestResult.success || !ingestResult.context) {
      const errorMsg = ingestResult.error || 'Failed to ingest source'
      if (!globalOptions.quiet) {
        logger.error(`Ingestion failed: ${errorMsg}`)
      }
      return ExitCode.ERROR
    }

    const { context: ingestContext } = ingestResult
    const sourceType = ingestContext.metadata.type

    if (globalOptions.verbose) {
      logger.info(`Ingested ${ingestContext.fileCount} files (${ingestContext.totalSize} bytes)`)
    }

    // 2. Create scan context for scanners
    const scanContext: ScanContext = {
      rootPath: ingestContext.rootDir,
      files: ingestContext.files.map(f => f.absolutePath)
    }

    // 3. Run scanners in parallel
    if (globalOptions.verbose) {
      logger.info('Running security scanners...')
    }

    const orchestrator = createOrchestrator()
    const results = await orchestrator.scan(scanContext)

    // Collect scanner errors
    for (const result of results) {
      if (result.error) {
        errors.push(`${result.scanner}: ${result.error}`)
      }
    }

    // 4. Collect all findings
    const findings: Finding[] = results.flatMap(r => r.findings)

    if (globalOptions.verbose) {
      logger.info(`Found ${findings.length} potential issues`)
    }

    // 5. Load policy
    const policyLoader = new PolicyLoader()
    const policy = options.policy
      ? await policyLoader.load(options.policy)
      : await policyLoader.loadDefault()

    // 6. Enforce policy
    const enforcer = new Enforcer(policy)
    const enforcement = enforcer.enforce(findings)

    // 7. Build report
    const report: ScanReport = {
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      source: buildSourceInfo(source, sourceType, ingestContext),
      decision: enforcement.decision,
      score: enforcement.evaluation.score,
      findings,
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length
      },
      criticalBlockRules: enforcement.evaluation.criticalBlockRules,
      duration: Date.now() - startTime,
      policyName: enforcement.policyName,
      errors
    }

    // 8. Generate and output report
    const reporter = options.format === 'markdown'
      ? new MarkdownReporter()
      : new JsonReporter()
    await reporter.write(report, {
      output: options.output,
      quiet: globalOptions.quiet
    })

    // 9. Print summary if not quiet and no output file
    if (!globalOptions.quiet && !options.output) {
      logger.info('')
      logger.info(enforcement.summary)
      for (const reason of enforcement.reasons) {
        logger.info(`  - ${reason}`)
      }
    }

    return enforcement.exitCode
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'
    if (!globalOptions.quiet) {
      logger.error(`Scan failed: ${message}`)
    }
    return ExitCode.ERROR
  }
}

/**
 * Register scan command on the program
 */
export function registerScanCommand(program: Command): void {
  program
    .command('scan <source>')
    .description('Scan a skill source for security risks')
    .option('-o, --output <file>', 'Output file path')
    .option('-f, --format <format>', 'Output format (json|markdown)', 'json')
    .option('-p, --policy <file>', 'Policy file to use')
    .action(async (source: string, options: ScanOptions) => {
      const globalOpts = program.opts() as GlobalOptions
      const exitCode = await executeScan(source, options, globalOpts)
      process.exit(exitCode)
    })
}
