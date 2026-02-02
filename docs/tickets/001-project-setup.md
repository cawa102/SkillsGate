# チケット 001: プロジェクト初期化

## 概要
SkillGateプロジェクトの基本構成ファイルを作成する

## ステータス
- [x] 完了

## 成果物

### 1. package.json
```json
{
  "name": "skillgate",
  "version": "1.0.0",
  "description": "Security scanner for Claude Code skills (.md)",
  "type": "module",
  "main": "dist/cli/index.js",
  "bin": {
    "sg": "dist/cli/index.js"
  },
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "start": "node dist/cli/index.js",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "lint": "eslint src --ext .ts",
    "clean": "rm -rf dist",
    "prepublishOnly": "pnpm run build"
  },
  "dependencies": {
    "chalk": "^5.3.0",
    "commander": "^12.0.0",
    "js-yaml": "^4.1.0",
    "simple-git": "^3.22.0",
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "@types/node": "^20.0.0",
    "typescript": "^5.3.0",
    "vitest": "^1.2.0"
  },
  "engines": {
    "node": ">=20.0.0"
  }
}
```

### 2. tsconfig.json
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "test"]
}
```

### 3. vitest.config.ts
```typescript
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/cli/index.ts']
    }
  }
})
```

### 4. .gitignore
```
node_modules/
dist/
coverage/
.DS_Store
*.log
.env
.env.local
```

## ディレクトリ構造
```
skillgate/
├── src/
│   ├── cli/
│   │   └── commands/
│   ├── core/
│   │   ├── ingestor/
│   │   ├── scanner/
│   │   ├── policy/
│   │   ├── enforcer/
│   │   └── reporter/
│   ├── types/
│   └── utils/
├── policies/
├── test/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── docs/
```

## 完了条件
- [x] package.json作成
- [x] tsconfig.json作成
- [x] vitest.config.ts作成
- [x] .gitignore作成
- [x] `pnpm install`が成功する
- [x] `pnpm build`が成功する（空でも）
