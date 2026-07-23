// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'data/**', 'reports/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts', 'tests/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      import: importPlugin,
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'import/no-restricted-paths': [
        'error',
        {
          zones: [
            {
              target: './src/core',
              from: './src/cli',
              message:
                'core/ must never depend on cli/ — business logic cannot depend on the CLI entry point.',
            },
            {
              target: './src/scanners',
              from: './src/scanners',
              except: ['./scanner-registry.ts'],
              message:
                'Scanners must never import one another — communicate only through AuditContext.',
            },
          ],
        },
      ],
    },
  },
  {
    files: ['*.config.ts', '*.config.js'],
    languageOptions: {
      parserOptions: {
        project: null,
      },
    },
  },
  eslintConfigPrettier,
);
