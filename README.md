# Vuln Research Agent

An autonomous AI vulnerability research tool. Multiple AI models scan a target application in parallel; the first scanner swarm to confirm a finding ends that vulnerability-class run.

## What It Does

- Accepts a live web app URL, source repository, or local binary as the target
- Runs specialized scanner swarms per vulnerability class, including XSS, SQLi, buffer overflow, use-after-free, auth bypass, and source review
- Validates findings by requiring a working proof of concept
- Outputs a structured report with confirmed vulnerabilities and full API cost accounting

## Quick Start

```bash
uv sync
docker build -f sandbox/Dockerfile.sandbox -t vuln-research-sandbox .
cp .env.example .env
```

Create `targets.yml`:

```yaml
targets:
  - name: "MyApp"
    type: web
    url: "http://localhost:8080"
    repo_url: "https://github.com/org/myapp"
    vuln_classes: [xss, sqli, auth]
    scope_allowlist: ["localhost:8080"]
    description: "Flask e-commerce app"
```

Run a scan:

```bash
uv run vuln-scan --targets targets.yml --target MyApp --output report.md --json-output report.json
```

## Scanner Swarms

Scanner swarms are selected from `backend/models.py`:

- `xss`: reflected, stored, and DOM XSS
- `sqli`: union, error-based, boolean, and time-based SQL injection
- `bof`: stack and heap buffer overflow analysis
- `uaf`: object lifetime and dangling pointer analysis
- `auth`: auth bypass, IDOR, broken access control, and JWT weaknesses
- `source`: static analysis plus dynamic confirmation

Each swarm runs the configured model lineup for that vulnerability class and stops when a confirmed finding is returned or the iteration limit is reached.

## Sandbox Tooling

Each scanner runs in an isolated Docker container with tooling for:

- Static analysis: Semgrep, Bandit, Safety
- Web testing: Playwright, sqlmap, requests-toolbelt, curl, nmap
- Binary analysis: GDB, radare2, binutils, pwntools, angr, ROPgadget
- Fuzzing and memory analysis: afl++, Valgrind, AddressSanitizer
- Source checkout and reporting: git, Jinja2, Markdown

## Output

The reporter writes:

- Markdown report with target metadata, findings, proof-of-concept blocks, evidence, cost summary, and cost breakdown
- JSON report with the same finding data and machine-readable cost accounting

Only findings with `confirmed=true`, a non-empty proof of concept, a specific affected component, and a severity are counted as confirmed.

## Configuration

`.env` provides model and infrastructure settings:

```env
ANTHROPIC_API_KEY=sk-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=
TARGETS_FILE=targets.yml
MAX_CONCURRENT_SWARMS=10
MAX_ITERATIONS_PER_SWARM=50
SANDBOX_IMAGE=vuln-research-sandbox
```

`targets.yml` defines the authorized research scope. Scanners may only interact with hosts or paths in `scope_allowlist`.

## Requirements

- Python 3.14+
- Docker
- `uv`
- API keys or provider credentials for the configured models
