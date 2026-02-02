import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  DependencyScanner,
  createDependencyScanner,
  parsers
} from './dependency.js'
import * as utils from './utils.js'
import type { ScanContext } from './base.js'

vi.mock('./utils.js', async () => {
  const actual = await vi.importActual('./utils.js')
  return {
    ...actual,
    readFileContent: vi.fn()
  }
})

const mockReadFileContent = vi.mocked(utils.readFileContent)

// Mock fetch for OSV API
const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

function createContext(files: string[], rootPath = '/test/project'): ScanContext {
  return { files, rootPath }
}

describe('DependencyScanner', () => {
  let scanner: DependencyScanner

  beforeEach(() => {
    scanner = new DependencyScanner({ enableOsvApi: false })
    mockReadFileContent.mockReset()
    mockFetch.mockReset()
  })

  describe('metadata', () => {
    it('should have correct type', () => {
      expect(scanner.type).toBe('dependency')
    })

    it('should have correct name', () => {
      expect(scanner.name).toBe('Dependency Scanner')
    })
  })

  describe('lock file detection', () => {
    it('should detect missing package-lock.json', async () => {
      const content = JSON.stringify({ name: 'test', dependencies: {} })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await scanner.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('dependency_no_lockfile')
      expect(findings[0].severity).toBe('medium')
    })

    it('should not report when lock file exists', async () => {
      const content = JSON.stringify({ name: 'test', dependencies: {} })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await scanner.scan(
        createContext([
          '/test/project/package.json',
          '/test/project/package-lock.json'
        ])
      )

      expect(findings).toHaveLength(0)
    })

    it('should detect missing go.sum', async () => {
      const content = `
module example.com/mymodule

go 1.21
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await scanner.scan(
        createContext(['/test/project/go.mod'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('dependency_no_lockfile')
    })

    it('should detect missing Cargo.lock', async () => {
      const content = `
[package]
name = "myproject"

[dependencies]
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await scanner.scan(
        createContext(['/test/project/Cargo.toml'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('dependency_no_lockfile')
    })
  })

  describe('parse error handling', () => {
    it('should report parse errors gracefully', async () => {
      mockReadFileContent.mockResolvedValue('invalid json {{{')

      const findings = await scanner.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('dependency_parse_error')
      expect(findings[0].severity).toBe('info')
    })

    it('should handle unreadable files', async () => {
      mockReadFileContent.mockResolvedValue(null)

      const findings = await scanner.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(0)
    })
  })

  describe('OSV API integration', () => {
    it('should query OSV API when enabled', async () => {
      const scannerWithApi = new DependencyScanner({ enableOsvApi: true })
      const content = JSON.stringify({
        name: 'test',
        dependencies: { lodash: '4.17.20' }
      })
      mockReadFileContent.mockResolvedValue(content)
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          vulns: [
            {
              id: 'GHSA-test-1234',
              summary: 'Test vulnerability',
              severity: [{ type: 'CVSS_V3', score: '7.5' }]
            }
          ]
        })
      })

      const findings = await scannerWithApi.scan(
        createContext([
          '/test/project/package.json',
          '/test/project/package-lock.json'
        ])
      )

      expect(mockFetch).toHaveBeenCalled()
      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toContain('dependency_vuln')
      expect(findings[0].severity).toBe('high')
    })

    it('should handle API errors gracefully', async () => {
      const scannerWithApi = new DependencyScanner({ enableOsvApi: true })
      const content = JSON.stringify({
        name: 'test',
        dependencies: { lodash: '4.17.20' }
      })
      mockReadFileContent.mockResolvedValue(content)
      mockFetch.mockRejectedValue(new Error('Network error'))

      const findings = await scannerWithApi.scan(
        createContext([
          '/test/project/package.json',
          '/test/project/package-lock.json'
        ])
      )

      // Should not throw, just skip vulnerabilities
      expect(findings).toHaveLength(0)
    })

    it('should skip version ranges', async () => {
      const scannerWithApi = new DependencyScanner({ enableOsvApi: true })
      const content = JSON.stringify({
        name: 'test',
        dependencies: { lodash: '^4.17.0' }
      })
      mockReadFileContent.mockResolvedValue(content)
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ vulns: [] })
      })

      await scannerWithApi.scan(
        createContext([
          '/test/project/package.json',
          '/test/project/package-lock.json'
        ])
      )

      // Should query with cleaned version
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"version":"4.17.0"')
        })
      )
    })
  })

  describe('createDependencyScanner', () => {
    it('should create a DependencyScanner instance', () => {
      const scanner = createDependencyScanner()
      expect(scanner).toBeInstanceOf(DependencyScanner)
    })

    it('should accept options', () => {
      const scanner = createDependencyScanner({ enableOsvApi: false })
      expect(scanner).toBeInstanceOf(DependencyScanner)
    })
  })
})

describe('parsers', () => {
  describe('parsePackageJson', () => {
    it('should parse dependencies', () => {
      const content = JSON.stringify({
        name: 'my-package',
        dependencies: {
          lodash: '^4.17.21',
          express: '4.18.0'
        }
      })

      const result = parsers.parsePackageJson(content)

      expect(result.name).toBe('my-package')
      expect(result.ecosystem).toBe('npm')
      expect(result.dependencies).toHaveLength(2)
      expect(result.dependencies[0]).toEqual({ name: 'lodash', version: '^4.17.21' })
    })

    it('should parse devDependencies', () => {
      const content = JSON.stringify({
        name: 'my-package',
        devDependencies: {
          typescript: '^5.0.0'
        }
      })

      const result = parsers.parsePackageJson(content)

      expect(result.dependencies).toHaveLength(1)
      expect(result.dependencies[0]).toEqual({
        name: 'typescript',
        version: '^5.0.0',
        dev: true
      })
    })

    it('should handle missing name', () => {
      const content = JSON.stringify({ dependencies: {} })
      const result = parsers.parsePackageJson(content)
      expect(result.name).toBe('unknown')
    })
  })

  describe('parseRequirementsTxt', () => {
    it('should parse versioned requirements', () => {
      const content = `
requests==2.28.0
flask>=2.0.0
django~=4.0
`
      const result = parsers.parseRequirementsTxt(content)

      expect(result.ecosystem).toBe('PyPI')
      expect(result.dependencies).toHaveLength(3)
      expect(result.dependencies[0]).toEqual({ name: 'requests', version: '2.28.0' })
    })

    it('should skip comments', () => {
      const content = `
# This is a comment
requests==2.28.0
# Another comment
`
      const result = parsers.parseRequirementsTxt(content)

      expect(result.dependencies).toHaveLength(1)
    })

    it('should handle packages without version', () => {
      const content = 'requests'
      const result = parsers.parseRequirementsTxt(content)

      expect(result.dependencies[0]).toEqual({ name: 'requests', version: '*' })
    })
  })

  describe('parseGoMod', () => {
    it('should parse require block', () => {
      const content = `
module example.com/mymodule

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)
`
      const result = parsers.parseGoMod(content)

      expect(result.ecosystem).toBe('Go')
      expect(result.dependencies).toHaveLength(2)
      expect(result.dependencies[0]).toEqual({
        name: 'github.com/gin-gonic/gin',
        version: '1.9.1'
      })
    })

    it('should parse single-line require', () => {
      const content = `
module example.com/mymodule

require github.com/pkg/errors v0.9.1
`
      const result = parsers.parseGoMod(content)

      expect(result.dependencies).toHaveLength(1)
      expect(result.dependencies[0].name).toBe('github.com/pkg/errors')
    })
  })

  describe('parseCargoToml', () => {
    it('should parse simple dependencies', () => {
      const content = `
[package]
name = "myproject"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.28"
`
      const result = parsers.parseCargoToml(content)

      expect(result.ecosystem).toBe('crates.io')
      expect(result.dependencies).toHaveLength(2)
      expect(result.dependencies[0]).toEqual({ name: 'serde', version: '1.0' })
    })

    it('should parse table-style dependencies', () => {
      const content = `
[dependencies]
serde = { version = "1.0", features = ["derive"] }
`
      const result = parsers.parseCargoToml(content)

      expect(result.dependencies).toHaveLength(1)
      expect(result.dependencies[0]).toEqual({ name: 'serde', version: '1.0' })
    })

    it('should stop at next section', () => {
      const content = `
[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"
`
      const result = parsers.parseCargoToml(content)

      expect(result.dependencies).toHaveLength(1)
    })
  })
})
