import { createHash } from 'crypto'
import { readFile, stat, readdir } from 'fs/promises'
import { join } from 'path'

/**
 * Calculate SHA-256 hash of a string
 */
export function hashString(content: string): string {
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Calculate SHA-256 hash of a file
 */
export async function hashFile(filePath: string): Promise<string> {
  const content = await readFile(filePath)
  return createHash('sha256').update(content).digest('hex')
}

/**
 * Calculate SHA-256 hash of a directory (based on all file contents)
 */
export async function hashDirectory(dirPath: string): Promise<string> {
  const hash = createHash('sha256')
  const files = await getFilesRecursively(dirPath)

  // Sort files for deterministic hashing
  files.sort()

  for (const file of files) {
    const content = await readFile(file)
    hash.update(file.slice(dirPath.length))
    hash.update(content)
  }

  return hash.digest('hex')
}

/**
 * Get all files in a directory recursively
 */
async function getFilesRecursively(dirPath: string): Promise<string[]> {
  const files: string[] = []
  const entries = await readdir(dirPath, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name)

    // Skip hidden directories and common ignore patterns
    if (entry.name.startsWith('.') || entry.name === 'node_modules') {
      continue
    }

    if (entry.isDirectory()) {
      const subFiles = await getFilesRecursively(fullPath)
      files.push(...subFiles)
    } else {
      files.push(fullPath)
    }
  }

  return files
}

/**
 * Check if a path is a directory
 */
export async function isDirectory(path: string): Promise<boolean> {
  try {
    const stats = await stat(path)
    return stats.isDirectory()
  } catch {
    return false
  }
}

/**
 * Check if a path is a file
 */
export async function isFile(path: string): Promise<boolean> {
  try {
    const stats = await stat(path)
    return stats.isFile()
  } catch {
    return false
  }
}
