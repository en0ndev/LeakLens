# LeakLens

LeakLens is a production-focused credential and secret detection tool for Git repositories.

It is designed to be stronger than regex-only scanners by combining:

- regex detection for known secret formats
- entropy detection for unknown/random secrets
- contextual code analysis for suspicious hardcoded values
- developer-friendly remediation guidance
- safe autofix suggestions (advisory only, no automatic file mutation)

## Why this exists

Most leaked credentials are introduced during normal development and code review misses.
LeakLens helps developers catch those leaks early:

- locally via CLI
- before commit via pre-commit hook
- in CI/CD via GitHub Actions

## Features

- `leaklens scan .`
- `leaklens scan --staged`
- `leaklens scan --commit <hash>`
- `leaklens scan --diff <base> <head>`
- `leaklens rules list`
- `leaklens report --format json`
- `leaklens report --format sarif`

Deterministic CI behavior:

- stable sort order for findings and JSON/SARIF output
- non-zero exit code when findings meet `--fail-on` (or configured threshold)
- redacted previews only (never full secret output)

Detection pipeline:

1. Regex detectors (AWS/GitHub/GitLab/Slack/Stripe/OpenAI/Google/JWT/private keys/.env/db URLs)
2. Entropy detector using Shannon entropy over candidate literals
3. Context detector for suspicious assignments and auth-adjacent literals

Output includes:

- finding type
- file path and line number
- redacted preview
- detector source(s)
- confidence score
- severity (`low|medium|high|critical`)
- risk explanation
- safer alternative
- remediation guidance
- autofix suggestion

## Installation

```bash
pip install -e .
```

Development setup:

```bash
pip install -e '.[dev]'
```

## Usage

Command quick reference:

| Command | Purpose |
| --- | --- |
| `leaklens scan .` | Full repository scan |
| `leaklens scan --staged` | Staged changes scan |
| `leaklens scan --commit <hash>` | Single commit scan |
| `leaklens scan --diff <base> <head>` | Commit-range diff scan |
| `leaklens rules list` | List active rules |
| `leaklens report --format json` | CI JSON report |
| `leaklens report --format sarif` | SARIF report for code scanning |

Scan repository:

```bash
leaklens scan .
```

Scan staged changes:

```bash
leaklens scan --staged
```

Scan specific commit:

```bash
leaklens scan --commit <hash>
```

Scan diff range:

```bash
leaklens scan --diff main HEAD
```

List rules:

```bash
leaklens rules list
```

CI JSON report:

```bash
leaklens report --format json
```

SARIF report:

```bash
leaklens report --format sarif --output leaklens.sarif
```

Version:

```bash
leaklens --version
```

Fail threshold override:

```bash
leaklens scan . --fail-on high
```

Run as module:

```bash
python -m leaklens scan .
```

Exit code semantics:

- `0`: no findings at/above fail threshold
- `1`: findings at/above fail threshold
- `2`: CLI usage/configuration errors

## Configuration

Default config file: `leaklens.yml`

Example:

```yaml
entropy_threshold: 4.2
severity_threshold: medium
enabled_detectors: [regex, entropy, context]
ignored_paths:
  - "node_modules/**"
allowlist:
  values: ["example-secret"]
  patterns: ["^dummy_"]
rules:
  - name: custom_internal_token
    regex: "inttok_[A-Za-z0-9]{24}"
    secret_type: "Internal API Token"
    severity: high
    confidence: 0.9
baseline_file: .leaklens-baseline.json
```

## Ignore and baseline support

- `.leaklensignore` for path patterns
- inline ignore markers: `leaklens:ignore`
- allowlist values and patterns in config
- baseline suppression via fingerprints
- legacy compatibility: `.aicredleakignore` and `aicredleak:ignore` are also accepted

Generate baseline from current findings:

```bash
leaklens scan . --write-baseline .leaklens-baseline.json
```

## Safe redaction

LeakLens never prints full secret values. Example previews:

- `ghp_****ABCD`
- `sk-****XYZ`

## Pre-commit setup

Use the included `.pre-commit-config.yaml` hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: leaklens
        entry: leaklens scan --staged
```

## GitHub Actions setup

Use `.github/workflows/leaklens.yml`.

The workflow:

- installs dependencies
- runs tests
- generates SARIF via `leaklens report --format sarif`
- uploads SARIF to GitHub Code Scanning

## Project structure

```text
src/leaklens/
  cli.py
  config.py
  engine.py
  rules.py
  models.py
  detectors/
  reporters/
tests/
examples/
.github/workflows/
```

## Limitations

- No live credential validity checks by default (offline-safe behavior)
- Context detection is heuristic and may produce false positives in edge cases
- Binary and generated minified assets are intentionally skipped
- LeakLens does not rewrite source files automatically; autofix output is advisory guidance

## Roadmap

- Optional AI review stage for borderline findings
- PR comment bot integration for developer feedback loops
- Secret validity verification integrations (cloud/vendor APIs)
- Exposure timeline analysis across commit history and branches

## Quality checks

```bash
pytest
ruff check src tests
ruff format src tests
```
