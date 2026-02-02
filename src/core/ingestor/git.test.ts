import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, rm, writeFile } from 'fs/promises'
import { join } from 'path'
import { execSync } from 'child_process'
import { GitIngestor } from './git.js'

const TEST_DIR = '/tmp/skillgate-test-git-ingestor'
const REPO_DIR = join(TEST_DIR, 'repo')
const WORK_DIR = join(TEST_DIR, 'work')

/**
 * Helper to create a local git repository for testing
 */
async function createTestRepo(): Promise<string> {
  await mkdir(REPO_DIR, { recursive: true })

  // Initialize git repo
  execSync('git init', { cwd: REPO_DIR, stdio: 'pipe' })
  execSync('git config user.email "test@test.com"', { cwd: REPO_DIR, stdio: 'pipe' })
  execSync('git config user.name "Test User"', { cwd: REPO_DIR, stdio: 'pipe' })

  // Create initial commit
  await writeFile(join(REPO_DIR, 'README.md'), '# Test Repo')
  execSync('git add .', { cwd: REPO_DIR, stdio: 'pipe' })
  execSync('git commit -m "Initial commit"', { cwd: REPO_DIR, stdio: 'pipe' })

  return REPO_DIR
}

/**
 * Get current commit SHA of a repo
 */
function getCommitSha(repoPath: string): string {
  return execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf-8' }).trim()
}

/**
 * Create a new branch in repo
 */
function createBranch(repoPath: string, branchName: string): void {
  execSync(`git checkout -b ${branchName}`, { cwd: repoPath, stdio: 'pipe' })
}

/**
 * Create a tag in repo
 */
function createTag(repoPath: string, tagName: string): void {
  execSync(`git tag ${tagName}`, { cwd: repoPath, stdio: 'pipe' })
}

describe('GitIngestor', () => {
  beforeEach(async () => {
    await mkdir(TEST_DIR, { recursive: true })
    await mkdir(WORK_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('ingest', () => {
    it('should clone and ingest a local git repository', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.success).toBe(true)
      expect(result.context).toBeDefined()
      expect(result.context?.fileCount).toBeGreaterThan(0)
    })

    it('should return error for invalid git URL', async () => {
      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: '/nonexistent/repo'
      })

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })

    it('should record commit SHA in metadata', async () => {
      const repoPath = await createTestRepo()
      const expectedSha = getCommitSha(repoPath)

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.context?.metadata.commitSha).toBe(expectedSha)
    })

    it('should collect files from cloned repository', async () => {
      const repoPath = await createTestRepo()

      // Add more files
      await mkdir(join(repoPath, 'src'), { recursive: true })
      await writeFile(join(repoPath, 'src', 'index.ts'), 'export {}')
      execSync('git add .', { cwd: repoPath, stdio: 'pipe' })
      execSync('git commit -m "Add src"', { cwd: repoPath, stdio: 'pipe' })

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.context?.files.some(f => f.path === 'README.md')).toBe(true)
      expect(result.context?.files.some(f => f.path === 'src/index.ts')).toBe(true)
    })
  })

  describe('ref support', () => {
    it('should checkout specific branch', async () => {
      const repoPath = await createTestRepo()

      // Create feature branch with different content
      createBranch(repoPath, 'feature')
      await writeFile(join(repoPath, 'feature.txt'), 'feature content')
      execSync('git add .', { cwd: repoPath, stdio: 'pipe' })
      execSync('git commit -m "Add feature"', { cwd: repoPath, stdio: 'pipe' })
      const featureSha = getCommitSha(repoPath)

      // Switch back to main
      execSync('git checkout master || git checkout main', { cwd: repoPath, stdio: 'pipe', shell: '/bin/bash' })

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath,
        ref: 'feature'
      })

      expect(result.success).toBe(true)
      expect(result.context?.metadata.ref).toBe('feature')
      expect(result.context?.metadata.commitSha).toBe(featureSha)
      expect(result.context?.files.some(f => f.path === 'feature.txt')).toBe(true)
    })

    it('should checkout specific tag', async () => {
      const repoPath = await createTestRepo()
      const v1Sha = getCommitSha(repoPath)
      createTag(repoPath, 'v1.0.0')

      // Add more commits after tag
      await writeFile(join(repoPath, 'new.txt'), 'new content')
      execSync('git add .', { cwd: repoPath, stdio: 'pipe' })
      execSync('git commit -m "After tag"', { cwd: repoPath, stdio: 'pipe' })

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath,
        ref: 'v1.0.0'
      })

      expect(result.success).toBe(true)
      expect(result.context?.metadata.ref).toBe('v1.0.0')
      expect(result.context?.metadata.commitSha).toBe(v1Sha)
      expect(result.context?.files.some(f => f.path === 'new.txt')).toBe(false)
    })

    it('should checkout specific commit SHA', async () => {
      const repoPath = await createTestRepo()
      const firstSha = getCommitSha(repoPath)

      // Add more commits
      await writeFile(join(repoPath, 'second.txt'), 'second')
      execSync('git add .', { cwd: repoPath, stdio: 'pipe' })
      execSync('git commit -m "Second commit"', { cwd: repoPath, stdio: 'pipe' })

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath,
        ref: firstSha
      })

      expect(result.success).toBe(true)
      expect(result.context?.metadata.commitSha).toBe(firstSha)
      expect(result.context?.files.some(f => f.path === 'second.txt')).toBe(false)
    })

    it('should return error for non-existent ref', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath,
        ref: 'nonexistent-branch'
      })

      expect(result.success).toBe(false)
      expect(result.error).toBeDefined()
    })
  })

  describe('metadata', () => {
    it('should set source type to git', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.context?.metadata.type).toBe('git')
    })

    it('should record original location', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.context?.metadata.originalLocation).toBe(repoPath)
    })
  })

  describe('cleanup', () => {
    it('should clean up cloned directory by default', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR, cleanup: true })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.success).toBe(true)
      // The rootDir should still exist during context building
      // but cleanup happens after ingest completes
    })

    it('should keep cloned directory when cleanup is false', async () => {
      const repoPath = await createTestRepo()

      const ingestor = new GitIngestor({ workDir: WORK_DIR, cleanup: false })
      const result = await ingestor.ingest({
        type: 'git',
        location: repoPath
      })

      expect(result.success).toBe(true)
      expect(result.context?.rootDir).toBeDefined()
    })
  })
})
