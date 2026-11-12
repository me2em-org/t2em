/**
 * ESLint flat config for the t2em workspace (root-owned toolchain).
 *
 * Mirrors the me2em-protocol setup:
 * - ONE config at the workspace root; per-package `lint` scripts run
 *   `eslint .` from their own directory — ESLint resolves this file by
 *   walking up from the current working directory.
 * - Base sets: `@eslint/js` recommended + `typescript-eslint` recommended
 *   (non-type-checked; type-checked linting is a later ratchet, not a gate).
 */
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/coverage/**',
      '**/node_modules/**',
      // docs/ holds the TZ (Markdown) — nothing lintable.
      'docs/**',
      // Infra examples and Python SDK (not TS).
      'infra/**',
      'python-sdk/**',
      'examples/**',
    ],
  },

  eslint.configs.recommended,
  tseslint.configs.recommended,

  {
    files: ['**/*.ts'],
    rules: {
      // Underscore-prefixed parameters/variables are the documented way
      // to mark intentionally unused bindings.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
);
