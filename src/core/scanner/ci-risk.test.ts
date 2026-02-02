import { describe, it, expect, vi, beforeEach } from 'vitest'
import { CIRiskAnalyzer, createCIRiskAnalyzer } from './ci-risk.js'
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

function createContext(files: string[], rootPath = '/test/project'): ScanContext {
  return { files, rootPath }
}

describe('CIRiskAnalyzer', () => {
  let analyzer: CIRiskAnalyzer

  beforeEach(() => {
    analyzer = new CIRiskAnalyzer()
    mockReadFileContent.mockReset()
  })

  describe('metadata', () => {
    it('should have correct type', () => {
      expect(analyzer.type).toBe('ci-risk')
    })

    it('should have correct name', () => {
      expect(analyzer.name).toBe('CI Risk Analyzer')
    })
  })

  describe('GitHub Actions analysis', () => {
    describe('permissions', () => {
      it('should detect write-all permissions', async () => {
        const content = `
name: CI
permissions: write-all
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_write_all_permissions')).toBe(
          true
        )
        expect(
          findings.find((f) => f.rule === 'ci_write_all_permissions')?.severity
        ).toBe('high')
      })
    })

    describe('secret exposure', () => {
      it('should detect secret exposure in echo', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.MY_SECRET }}
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_secret_exposure')).toBe(true)
        expect(
          findings.find((f) => f.rule === 'ci_secret_exposure')?.severity
        ).toBe('critical')
      })
    })

    describe('remote script execution', () => {
      it('should detect curl | bash', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/install.sh | bash
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(
          findings.some((f) => f.rule === 'ci_remote_script_execution')
        ).toBe(true)
      })

      it('should detect wget | sh', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: wget -qO- https://example.com/script | sh
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(
          findings.some((f) => f.rule === 'ci_remote_script_execution')
        ).toBe(true)
      })
    })

    describe('unpinned actions', () => {
      it('should detect action without version', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_unpinned_action')).toBe(true)
      })

      it('should detect action pinned to main', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@main
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_unpinned_action')).toBe(true)
      })

      it('should detect action pinned to master', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@master
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_unpinned_action')).toBe(true)
      })
    })

    describe('third-party actions', () => {
      it('should detect third-party action without SHA', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@v1
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_third_party_action')).toBe(
          true
        )
      })

      it('should not flag official actions', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_third_party_action')).toBe(
          false
        )
      })

      it('should not flag SHA-pinned third-party actions', async () => {
        const content = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_third_party_action')).toBe(
          false
        )
      })
    })

    describe('pull_request_target', () => {
      it('should detect pull_request_target trigger', async () => {
        const content = `
name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_pull_request_target')).toBe(
          true
        )
        expect(
          findings.find((f) => f.rule === 'ci_pull_request_target')?.severity
        ).toBe('high')
      })
    })

    describe('parse errors', () => {
      it('should handle invalid YAML', async () => {
        mockReadFileContent.mockResolvedValue('invalid: yaml: {{{')

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_parse_error')).toBe(true)
        expect(findings[0].severity).toBe('info')
      })

      it('should handle unreadable files', async () => {
        mockReadFileContent.mockResolvedValue(null)

        const findings = await analyzer.scan(
          createContext(['/test/project/.github/workflows/ci.yml'])
        )

        expect(findings).toHaveLength(0)
      })
    })
  })

  describe('GitLab CI analysis', () => {
    describe('plaintext secrets', () => {
      it('should detect plaintext password variable', async () => {
        const content = `
variables:
  DB_PASSWORD: mysecretpassword

build:
  script:
    - echo "Building"
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.gitlab-ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_plaintext_secret')).toBe(true)
      })

      it('should detect plaintext token variable', async () => {
        const content = `
variables:
  API_TOKEN: abc123token

build:
  script:
    - echo "Building"
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.gitlab-ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_plaintext_secret')).toBe(true)
      })

      it('should detect plaintext api_key variable', async () => {
        const content = `
variables:
  MY_API_KEY: secretkey123

build:
  script:
    - echo "Building"
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.gitlab-ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_plaintext_secret')).toBe(true)
      })
    })

    describe('remote script execution', () => {
      it('should detect curl | bash in script', async () => {
        const content = `
build:
  script:
    - curl -sSL https://example.com/install.sh | bash
`
        mockReadFileContent.mockResolvedValue(content)

        const findings = await analyzer.scan(
          createContext(['/test/project/.gitlab-ci.yml'])
        )

        expect(
          findings.some((f) => f.rule === 'ci_remote_script_execution')
        ).toBe(true)
      })
    })

    describe('parse errors', () => {
      it('should handle invalid YAML', async () => {
        mockReadFileContent.mockResolvedValue('invalid: yaml: {{{')

        const findings = await analyzer.scan(
          createContext(['/test/project/.gitlab-ci.yml'])
        )

        expect(findings.some((f) => f.rule === 'ci_parse_error')).toBe(true)
      })
    })
  })

  describe('file matching', () => {
    it('should match .github/workflows/*.yml', async () => {
      mockReadFileContent.mockResolvedValue('name: CI\non: push\njobs: {}')

      await analyzer.scan(
        createContext(['/test/project/.github/workflows/test.yml'])
      )

      expect(mockReadFileContent).toHaveBeenCalled()
    })

    it('should match .github/workflows/*.yaml', async () => {
      mockReadFileContent.mockResolvedValue('name: CI\non: push\njobs: {}')

      await analyzer.scan(
        createContext(['/test/project/.github/workflows/test.yaml'])
      )

      expect(mockReadFileContent).toHaveBeenCalled()
    })

    it('should not match non-workflow files', async () => {
      await analyzer.scan(
        createContext(['/test/project/.github/other.yml'])
      )

      expect(mockReadFileContent).not.toHaveBeenCalled()
    })
  })

  describe('createCIRiskAnalyzer', () => {
    it('should create a CIRiskAnalyzer instance', () => {
      const analyzer = createCIRiskAnalyzer()
      expect(analyzer).toBeInstanceOf(CIRiskAnalyzer)
    })
  })
})
