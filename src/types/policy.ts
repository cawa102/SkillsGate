import { z } from 'zod'
import type { Severity } from './finding.js'

/**
 * Schema for threshold configuration
 */
export const ThresholdsSchema = z.object({
  block: z.number().min(0).max(100).default(40),
  warn: z.number().min(0).max(100).default(70)
})

export type Thresholds = z.infer<typeof ThresholdsSchema>

/**
 * Schema for a single rule definition
 */
export const RuleDefinitionSchema = z.object({
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  weight: z.number(),
  message: z.string(),
  enabled: z.boolean().default(true)
})

export type RuleDefinition = z.infer<typeof RuleDefinitionSchema>

/**
 * Schema for exception patterns
 */
export const ExceptionSchema = z.object({
  pattern: z.string(),
  ignore: z.array(z.string())
})

export type Exception = z.infer<typeof ExceptionSchema>

/**
 * Schema for the complete policy file
 */
export const PolicySchema = z.object({
  version: z.string(),
  name: z.string(),
  description: z.string().optional(),
  thresholds: ThresholdsSchema,
  critical_block: z.array(z.string()).default([]),
  rules: z.record(z.string(), RuleDefinitionSchema),
  exceptions: z.array(ExceptionSchema).default([])
})

export type Policy = z.infer<typeof PolicySchema>

/**
 * Result of evaluating a policy against findings
 */
export interface PolicyEvaluationResult {
  score: number
  triggeredRules: Array<{
    rule: string
    severity: Severity
    weight: number
    message: string
    count: number
  }>
  hasCriticalBlock: boolean
  criticalBlockRules: string[]
}
