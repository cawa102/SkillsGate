import { readFile, readdir, stat } from 'fs/promises'
import { join, extname, basename } from 'path'

export interface GetFilesOptions {
  /** File extensions to include (e.g., ['.ts', '.js']) */
  extensions?: string[]
  /** Directory names to exclude (e.g., ['node_modules', '.git']) */
  exclude?: string[]
}

/**
 * Recursively get all files from a directory
 * @param dirPath - Directory path to scan
 * @param options - Filter options for extensions and exclusions
 * @returns Array of absolute file paths
 */
export async function getFiles(
  dirPath: string,
  options?: GetFilesOptions
): Promise<string[]> {
  const { extensions, exclude = [] } = options ?? {}
  const results: string[] = []

  try {
    const entries = await readdir(dirPath, { withFileTypes: true })

    for (const entry of entries) {
      const fullPath = join(dirPath, entry.name)

      if (entry.isDirectory()) {
        if (!exclude.includes(entry.name)) {
          const nested = await getFiles(fullPath, options)
          results.push(...nested)
        }
      } else if (entry.isFile()) {
        if (extensions) {
          const ext = extname(entry.name)
          if (extensions.includes(ext)) {
            results.push(fullPath)
          }
        } else {
          results.push(fullPath)
        }
      }
    }
  } catch {
    // Return empty array for non-existent or inaccessible directories
    return []
  }

  return results
}

/**
 * Read file content safely
 * @param filePath - Path to the file
 * @returns File content as string, or null if file doesn't exist
 */
export async function readFileContent(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf-8')
  } catch {
    return null
  }
}

/**
 * Check if a file path matches a glob-like pattern
 * Supports:
 * - Exact match: 'package.json'
 * - Wildcard: '*.ts' matches any .ts file
 * - Double wildcard: '**\/*.ts' matches .ts files at any depth
 * - Directory prefix: 'node_modules/**' matches anything under node_modules
 *
 * @param filePath - File path to check
 * @param pattern - Glob-like pattern
 * @returns True if the path matches the pattern
 */
export function matchesPattern(filePath: string, pattern: string): boolean {
  // Exact match
  if (pattern === filePath || pattern === basename(filePath)) {
    return true
  }

  // Handle **/ prefix pattern (match at any depth including root)
  if (pattern.startsWith('**/')) {
    const suffix = pattern.slice(3)
    const suffixPattern = suffix
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[^/]*')
    const regex = new RegExp(`(^|/)${suffixPattern}$`)
    return regex.test(filePath)
  }

  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '<<DOUBLE_STAR>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<DOUBLE_STAR>>/g, '.*')

  const regex = new RegExp(`(^|/)${regexPattern}$`)
  return regex.test(filePath)
}

/**
 * Get file extension including the dot
 * @param filePath - File path
 * @returns Extension with dot (e.g., '.ts') or empty string if no extension
 */
export function getExtension(filePath: string): string {
  const name = basename(filePath)

  // Handle hidden files without extension (e.g., .gitignore)
  if (name.startsWith('.') && !name.includes('.', 1)) {
    return ''
  }

  return extname(filePath)
}
