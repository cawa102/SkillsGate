import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, writeFile, rm } from 'fs/promises'
import { join } from 'path'
import { SecretScanner } from './secret.js'
import type { ScanContext } from './base.js'

const TEST_DIR = '/tmp/skillgate-secret-test'

describe('SecretScanner', () => {
  let scanner: SecretScanner

  beforeEach(async () => {
    scanner = new SecretScanner()
    await mkdir(TEST_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('metadata', () => {
    it('should have correct type', () => {
      expect(scanner.type).toBe('secret')
    })

    it('should have correct name', () => {
      expect(scanner.name).toBe('Secret Scanner')
    })
  })

  describe('AWS credentials', () => {
    it('should detect AWS Access Key ID', async () => {
      const filePath = join(TEST_DIR, 'config.ts')
      await writeFile(filePath, 'const key = "AKIAIOSFODNN7EXAMPLE"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_aws_access_key')
      expect(findings[0].severity).toBe('critical')
      expect(findings[0].evidence).not.toContain('AKIAIOSFODNN7EXAMPLE')
      expect(findings[0].evidence).toContain('[MASKED]')
    })

    it('should detect AWS Secret Key pattern', async () => {
      const filePath = join(TEST_DIR, 'config.ts')
      // 40-character base64-like string (typical AWS secret key format)
      await writeFile(filePath, 'const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const awsFinding = findings.find(f => f.rule === 'secret_aws_secret_key')
      expect(awsFinding).toBeDefined()
      expect(awsFinding?.severity).toBe('critical')
    })
  })

  describe('GitHub tokens', () => {
    it('should detect GitHub Personal Access Token', async () => {
      const filePath = join(TEST_DIR, 'auth.ts')
      await writeFile(filePath, 'const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_github_token')
      expect(findings[0].severity).toBe('critical')
    })

    it('should detect GitHub OAuth Token', async () => {
      const filePath = join(TEST_DIR, 'oauth.ts')
      await writeFile(filePath, 'const token = "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_github_oauth')
      expect(findings[0].severity).toBe('critical')
    })
  })

  describe('OpenAI API Key', () => {
    it('should detect OpenAI API Key', async () => {
      const filePath = join(TEST_DIR, 'llm.ts')
      await writeFile(filePath, 'const key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_openai_key')
      expect(findings[0].severity).toBe('critical')
    })
  })

  describe('Anthropic API Key', () => {
    it('should detect Anthropic API Key', async () => {
      const filePath = join(TEST_DIR, 'claude.ts')
      // Anthropic keys are sk-ant- followed by 95 characters
      const anthropicKey = 'sk-ant-' + 'x'.repeat(95)
      await writeFile(filePath, `const key = "${anthropicKey}"`)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_anthropic_key')
      expect(findings[0].severity).toBe('critical')
    })
  })

  describe('Private keys', () => {
    it('should detect RSA private key', async () => {
      const filePath = join(TEST_DIR, 'key.pem')
      await writeFile(filePath, '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_private_key')
      expect(findings[0].severity).toBe('critical')
    })

    it('should detect EC private key', async () => {
      const filePath = join(TEST_DIR, 'ec.pem')
      await writeFile(filePath, '-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_private_key')
    })

    it('should detect OpenSSH private key', async () => {
      const filePath = join(TEST_DIR, 'id_ed25519')
      await writeFile(filePath, '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_private_key')
    })
  })

  describe('Passwords in URLs', () => {
    it('should detect password in database URL', async () => {
      const filePath = join(TEST_DIR, 'db.ts')
      await writeFile(filePath, 'const url = "postgres://user:secretpassword@localhost:5432/db"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_password_in_url')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect password in HTTP URL', async () => {
      const filePath = join(TEST_DIR, 'api.ts')
      await writeFile(filePath, 'const url = "https://admin:password123@api.example.com"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_password_in_url')
    })
  })

  describe('Generic API keys', () => {
    it('should detect api_key assignment', async () => {
      const filePath = join(TEST_DIR, 'config.ts')
      await writeFile(filePath, 'const api_key = "abcdefghij1234567890klmnopqrst"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const genericFinding = findings.find(f => f.rule === 'secret_generic_api_key')
      expect(genericFinding).toBeDefined()
      expect(genericFinding?.severity).toBe('high')
    })

    it('should detect API_SECRET environment variable style', async () => {
      const filePath = join(TEST_DIR, '.env')
      await writeFile(filePath, 'API_SECRET=supersecretkey1234567890abcdef')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
    })
  })

  describe('JWT tokens', () => {
    it('should detect JWT token', async () => {
      const filePath = join(TEST_DIR, 'auth.ts')
      // Standard JWT format: header.payload.signature (base64url encoded)
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
      await writeFile(filePath, `const token = "${jwt}"`)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('secret_jwt_token')
      expect(findings[0].severity).toBe('high')
    })
  })

  describe('Line number detection', () => {
    it('should report correct line number', async () => {
      const filePath = join(TEST_DIR, 'multiline.ts')
      const content = `// Line 1
// Line 2
// Line 3
const key = "AKIAIOSFODNN7EXAMPLE"
// Line 5`
      await writeFile(filePath, content)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].location.line).toBe(4)
    })
  })

  describe('Multiple findings', () => {
    it('should detect multiple secrets in one file', async () => {
      const filePath = join(TEST_DIR, 'secrets.ts')
      const content = `
const awsKey = "AKIAIOSFODNN7EXAMPLE"
const githubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
`
      await writeFile(filePath, content)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(3)
    })

    it('should scan multiple files', async () => {
      const file1 = join(TEST_DIR, 'file1.ts')
      const file2 = join(TEST_DIR, 'file2.ts')
      await writeFile(file1, 'const key = "AKIAIOSFODNN7EXAMPLE"')
      await writeFile(file2, 'const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [file1, file2]
      }

      const findings = await scanner.scan(context)

      expect(findings).toHaveLength(2)
      expect(findings.map(f => f.rule)).toContain('secret_aws_access_key')
      expect(findings.map(f => f.rule)).toContain('secret_github_token')
    })
  })

  describe('Edge cases', () => {
    it('should handle empty files', async () => {
      const filePath = join(TEST_DIR, 'empty.ts')
      await writeFile(filePath, '')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toEqual([])
    })

    it('should handle non-existent files gracefully', async () => {
      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: ['/non/existent/file.ts']
      }

      const findings = await scanner.scan(context)

      expect(findings).toEqual([])
    })

    it('should handle files with no secrets', async () => {
      const filePath = join(TEST_DIR, 'clean.ts')
      await writeFile(filePath, 'const message = "Hello, World!"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings).toEqual([])
    })

    it('should use relative path in location', async () => {
      const filePath = join(TEST_DIR, 'src', 'config.ts')
      await mkdir(join(TEST_DIR, 'src'), { recursive: true })
      await writeFile(filePath, 'const key = "AKIAIOSFODNN7EXAMPLE"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await scanner.scan(context)

      expect(findings[0].location.file).toBe('src/config.ts')
    })
  })
})
