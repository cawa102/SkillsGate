import yaml from 'js-yaml'
import { BaseScanner, type ScanContext } from './base.js'
import type { Finding } from '../../types/index.js'
import { readFileContent } from './utils.js'

interface GitHubWorkflow {
  permissions?: Record<string, string> | string
  on?: Record<string, unknown> | string | string[]
  jobs?: Record<string, GitHubJob>
}

interface GitHubJob {
  steps?: GitHubStep[]
  [key: string]: unknown
}

interface GitHubStep {
  run?: string
  uses?: string
  [key: string]: unknown
}

interface GitLabConfig {
  variables?: Record<string, string>
  [key: string]: unknown
}

interface GitLabJob {
  script?: string[]
  [key: string]: unknown
}

/**
 * CI Risk Analyzer Scanner
 *
 * Analyzes CI/CD configuration files for security risks:
 * - GitHub Actions workflows
 * - GitLab CI configuration
 *
 * Detects:
 * - Overly permissive permissions
 * - Secret exposure in logs
 * - Remote script execution (curl | bash)
 * - Unpinned actions
 * - pull_request_target risks
 * - Plaintext secrets in variables
 */
export class CIRiskAnalyzer extends BaseScanner {
  readonly type = 'ci-risk' as const
  readonly name = 'CI Risk Analyzer'

  async scan(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = []

    // GitHub Actions workflows
    const workflowFiles = context.files.filter((f) =>
      /\.github\/workflows\/.*\.ya?ml$/.test(f)
    )

    for (const file of workflowFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      const relativePath = this.getRelativePath(file, context.rootPath)

      try {
        const workflow = yaml.load(content) as GitHubWorkflow
        if (workflow && typeof workflow === 'object') {
          findings.push(...this.analyzeGitHubWorkflow(workflow, relativePath))
        }
      } catch {
        findings.push({
          scanner: this.type,
          severity: 'info',
          rule: 'ci_parse_error',
          message: 'Failed to parse workflow file',
          location: { file: relativePath }
        })
      }
    }

    // GitLab CI
    const gitlabFiles = context.files.filter((f) => f.endsWith('.gitlab-ci.yml'))
    for (const file of gitlabFiles) {
      const content = await readFileContent(file)
      if (!content) continue

      const relativePath = this.getRelativePath(file, context.rootPath)
      findings.push(...this.analyzeGitLabCI(content, relativePath))
    }

    return findings
  }

  private analyzeGitHubWorkflow(
    workflow: GitHubWorkflow,
    file: string
  ): Finding[] {
    const findings: Finding[] = []

    // Check permissions
    if (workflow.permissions === 'write-all') {
      findings.push({
        scanner: this.type,
        severity: 'high',
        rule: 'ci_write_all_permissions',
        message: 'Workflow has write-all permissions',
        location: { file }
      })
    }

    // Check for pull_request_target
    const on = workflow.on
    if (typeof on === 'object' && on !== null && 'pull_request_target' in on) {
      findings.push({
        scanner: this.type,
        severity: 'high',
        rule: 'ci_pull_request_target',
        message: 'Workflow uses pull_request_target - potential injection risk',
        location: { file }
      })
    }

    // Check jobs
    const jobs = workflow.jobs
    if (jobs) {
      for (const [jobName, job] of Object.entries(jobs)) {
        if (!job || typeof job !== 'object') continue

        const steps = job.steps
        if (steps && Array.isArray(steps)) {
          for (const step of steps) {
            findings.push(...this.analyzeGitHubStep(step, jobName, file))
          }
        }
      }
    }

    return findings
  }

  private analyzeGitHubStep(
    step: GitHubStep,
    jobName: string,
    file: string
  ): Finding[] {
    const findings: Finding[] = []

    const run = step.run
    if (run && typeof run === 'string') {
      // Check for secret exposure in logs
      if (/echo.*\$\{\{\s*secrets\./.test(run)) {
        findings.push({
          scanner: this.type,
          severity: 'critical',
          rule: 'ci_secret_exposure',
          message: `Potential secret exposure in job ${jobName}`,
          location: { file },
          evidence: run.slice(0, 100)
        })
      }

      // Check for dangerous commands
      if (/curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh)/.test(run)) {
        findings.push({
          scanner: this.type,
          severity: 'high',
          rule: 'ci_remote_script_execution',
          message: `Remote script execution in job ${jobName}`,
          location: { file }
        })
      }
    }

    // Check external actions
    const uses = step.uses
    if (uses && typeof uses === 'string') {
      // Unpinned action (no @, or @main/@master)
      if (
        !uses.includes('@') ||
        uses.endsWith('@main') ||
        uses.endsWith('@master')
      ) {
        findings.push({
          scanner: this.type,
          severity: 'medium',
          rule: 'ci_unpinned_action',
          message: `Unpinned action in job ${jobName}: ${uses}`,
          location: { file }
        })
      }

      // Third-party action without SHA pin
      if (!uses.startsWith('actions/') && !/@[a-f0-9]{40}$/.test(uses)) {
        findings.push({
          scanner: this.type,
          severity: 'medium',
          rule: 'ci_third_party_action',
          message: `Third-party action without SHA pin: ${uses}`,
          location: { file }
        })
      }
    }

    return findings
  }

  private analyzeGitLabCI(content: string, file: string): Finding[] {
    const findings: Finding[] = []

    try {
      const config = yaml.load(content) as GitLabConfig
      if (!config || typeof config !== 'object') {
        return findings
      }

      // Check for sensitive variables in plain text
      if (config.variables && typeof config.variables === 'object') {
        for (const [varName, varValue] of Object.entries(config.variables)) {
          if (
            /password|secret|token|key|api_key|apikey/i.test(varName) &&
            typeof varValue === 'string' &&
            varValue.length > 0
          ) {
            findings.push({
              scanner: this.type,
              severity: 'high',
              rule: 'ci_plaintext_secret',
              message: `Potential plaintext secret: ${varName}`,
              location: { file }
            })
          }
        }
      }

      // Check job scripts
      for (const [key, value] of Object.entries(config)) {
        // Skip reserved keys
        if (
          [
            'variables',
            'stages',
            'image',
            'services',
            'before_script',
            'after_script',
            'cache',
            'default',
            'include',
            'workflow'
          ].includes(key)
        ) {
          continue
        }

        if (this.isGitLabJob(value)) {
          const scripts = value.script
          if (Array.isArray(scripts)) {
            for (const script of scripts) {
              if (
                typeof script === 'string' &&
                /curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh)/.test(script)
              ) {
                findings.push({
                  scanner: this.type,
                  severity: 'high',
                  rule: 'ci_remote_script_execution',
                  message: `Remote script execution in job ${key}`,
                  location: { file }
                })
              }
            }
          }
        }
      }
    } catch {
      findings.push({
        scanner: this.type,
        severity: 'info',
        rule: 'ci_parse_error',
        message: 'Failed to parse GitLab CI file',
        location: { file }
      })
    }

    return findings
  }

  private isGitLabJob(value: unknown): value is GitLabJob {
    return (
      typeof value === 'object' &&
      value !== null &&
      'script' in value
    )
  }

  private getRelativePath(file: string, rootPath: string): string {
    if (file.startsWith(rootPath)) {
      return file.slice(rootPath.length + 1)
    }
    return file
  }
}

/**
 * Create a new CIRiskAnalyzer instance
 */
export function createCIRiskAnalyzer(): CIRiskAnalyzer {
  return new CIRiskAnalyzer()
}
