/**
 * Masking utilities for sensitive information
 */

/**
 * Mask a secret value, showing only prefix and suffix
 */
export function maskSecret(
  value: string,
  options: { prefixLength?: number; suffixLength?: number; maskChar?: string } = {}
): string {
  const { prefixLength = 4, suffixLength = 4, maskChar = '*' } = options

  if (value.length <= prefixLength + suffixLength) {
    return maskChar.repeat(value.length)
  }

  const prefix = value.slice(0, prefixLength)
  const suffix = value.slice(-suffixLength)
  const maskLength = Math.min(value.length - prefixLength - suffixLength, 8)

  return `${prefix}${maskChar.repeat(maskLength)}[MASKED]`
}

/**
 * Mask all secret patterns in a string
 */
export function maskSecrets(text: string, patterns: RegExp[]): string {
  let result = text

  for (const pattern of patterns) {
    result = result.replace(pattern, (match) => maskSecret(match))
  }

  return result
}

/**
 * Common secret patterns to mask
 */
export const SECRET_PATTERNS = [
  // AWS keys
  /AKIA[0-9A-Z]{16}/g,
  // GitHub tokens
  /ghp_[a-zA-Z0-9]{36}/g,
  /gho_[a-zA-Z0-9]{36}/g,
  /ghu_[a-zA-Z0-9]{36}/g,
  /ghs_[a-zA-Z0-9]{36}/g,
  /ghr_[a-zA-Z0-9]{36}/g,
  // Generic API keys
  /[a-zA-Z0-9_-]{32,}/g,
  // Private keys
  /-----BEGIN [A-Z]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z]+ PRIVATE KEY-----/g
]

/**
 * Mask evidence for safe display in reports
 */
export function maskEvidence(evidence: string, secretPatterns: RegExp[] = SECRET_PATTERNS): string {
  // First, try to mask known patterns
  let masked = evidence

  for (const pattern of secretPatterns) {
    masked = masked.replace(pattern, (match) => maskSecret(match))
  }

  // If the evidence looks like it could be a secret (long alphanumeric string),
  // mask the middle portion
  if (/^[a-zA-Z0-9_-]{20,}$/.test(evidence)) {
    return maskSecret(evidence)
  }

  return masked
}

/**
 * Mask file path to hide user-specific directories
 */
export function maskPath(path: string): string {
  // Replace home directory paths
  return path.replace(/\/Users\/[^/]+/g, '/Users/[REDACTED]')
    .replace(/\/home\/[^/]+/g, '/home/[REDACTED]')
    .replace(/C:\\Users\\[^\\]+/g, 'C:\\Users\\[REDACTED]')
}

/**
 * Mask sensitive data in a finding's evidence field
 */
export function maskFindingEvidence<T extends { evidence?: string }>(finding: T): T {
  if (!finding.evidence) {
    return finding
  }

  return {
    ...finding,
    evidence: maskEvidence(finding.evidence)
  }
}
