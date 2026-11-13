# CI & Security Pipeline — Developer Guide

Pipeline file: [`.github/workflows/ci-security.yml`](./ci-security.yml)
Triggered by: push to `main`, pull requests to `main`, weekly schedule
(Mondays 02:00 UTC).

## Pipeline overview

| Job | What runs |
|-----|-----------|
| **secret-scan** | [gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1 (pinned OSS binary) scans the full git history for hardcoded secrets |
| **build-and-test** | `pnpm install --frozen-lockfile` → build (topological: `@t2em/protocol` first) → typecheck → tests → lint → dependency audit (high/critical = blocking) |
| **codeql** | GitHub CodeQL deep static analysis, `security-extended` query set. Runs only on **public** repos (code scanning is a paid Advanced Security feature on private ones) — skipped automatically while the repo is private |

All three run **in parallel**. All three must be green for `main`.

Node 22 · pnpm (from `packageManager` in root `package.json`) ·
runner pinned to `ubuntu-24.04`.

## Job 1: secret-scan (gitleaks) failed

Gitleaks found something in the git history that matches a secret
pattern. Fix: remove the secret, rotate it immediately if it was ever
pushed, then commit the removal. Legitimate test fixtures are
allowlisted in the root [`.gitleaks.toml`](../../.gitleaks.toml) — add
new fixture patterns there, never use `GITLEAKS_SKIP` or `# gitleaks:ignore`
inline comments.

## Job 2: build-and-test failed

| Step | Typical cause | Fix |
|------|---------------|-----|
| Install | `pnpm-lock.yaml` out of sync with `package.json` | run `pnpm install` locally, commit the lockfile |
| Build | workspace dep not built / wrong import path | `pnpm -r build` locally; imports go through package `exports` |
| Typecheck | type error surfaced only after deps built | `pnpm -r typecheck` |
| Test | behavioral regression | `pnpm -r test` |
| Lint | style/rule violation | `pnpm -r lint` (eslint.config.mjs at repo root) |
| Audit | high/critical vuln in prod deps | upgrade the dep; exceptions need a dated justification in the PR description |

## Job 3: codeql failed

CodeQL reports a potential vulnerability class (injection, SSRF,
unchecked crypto usage). For t2em, treat SSRF findings in
`@t2em/mcp-server` (§8.4 ТЗ) and any logging of secrets as blocking.
