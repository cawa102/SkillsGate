export { BaseScanner, type ScanContext } from './base.js'
export {
  getFiles,
  readFileContent,
  matchesPattern,
  getExtension,
  type GetFilesOptions
} from './utils.js'
export { SecretScanner } from './secret.js'
export { StaticAnalyzer } from './static.js'
export { SkillScanner } from './skill.js'
export { EntrypointDetector, createEntrypointDetector } from './entrypoint.js'
export { DependencyScanner, createDependencyScanner, parsers as dependencyParsers } from './dependency.js'
export { CIRiskAnalyzer, createCIRiskAnalyzer } from './ci-risk.js'

import type { ScannerResult } from '../../types/index.js'
import type { BaseScanner, ScanContext } from './base.js'

/**
 * Orchestrates multiple scanners to run in parallel
 */
export class ScannerOrchestrator {
  private scanners: BaseScanner[] = []

  /**
   * Register a scanner to be executed during scans
   * @param scanner - Scanner instance to register
   */
  register(scanner: BaseScanner): void {
    this.scanners = [...this.scanners, scanner]
  }

  /**
   * Execute all registered scanners in parallel
   * @param context - Scan context with files and configuration
   * @returns Array of results from all scanners
   */
  async scan(context: ScanContext): Promise<ScannerResult[]> {
    return Promise.all(
      this.scanners.map(scanner => scanner.execute(context))
    )
  }

  /**
   * Get the number of registered scanners
   */
  get scannerCount(): number {
    return this.scanners.length
  }
}
