# CTF-Agent → Vulnerability Research Tool Migration Guide

## Summary of Changes

This document outlines the transformation of `ctf-agent` from a CTFd competition solver into a general-purpose AI vulnerability research tool.

## What Changed

### Removed Components
- ❌ `pull_challenges.py` — CTFd challenge fetcher
- ❌ CTFd-specific configuration in `config.py` (ctfd_url, ctfd_token, ctfd_user, ctfd_pass)
- ❌ Flag detection and submission logic
- ❌ Challenge-based prompting system

### Added Components  
- ✅ `backend/finding.py` — Vulnerability finding model + deduplication
- ✅ `backend/target_loader.py` — YAML-based target definition
- ✅ `backend/reporter.py` — Report generation + cost tracking
- ✅ `VULNERABILITY_RESEARCH.md` — Comprehensive documentation
- ✅ `targets.example.yml` — Example target configuration
- ✅ Enhanced `Dockerfile.sandbox` with vulnerability research tools

### Modified Components

#### `backend/config.py`
**Before:**
```python
ctfd_url: str = "http://localhost:8000"
ctfd_token: str = ""
max_concurrent_challenges: int = 10
```

**After:**
```python
targets_file: str = "targets.yml"
max_concurrent_swarms: int = 10
max_iterations_per_swarm: int = 50
```

#### `backend/models.py`
**Added:**
```python
SWARM_CONFIGS = {
    "xss": {...},
    "sqli": {...},
    "bof": {...},
    "uaf": {...},
    "auth": {...},
    "source": {...},
}
```

Each vulnerability class has its own system prompt and model assignments.

#### `backend/cli.py`
**Before:**
```bash
ctf-solve --ctfd-url ... --challenge name --no-submit
```

**After:**
```bash
ctf-solve --targets targets.yml --target TargetName --output report.md
# or research all targets:
ctf-solve --targets targets.yml
```

**New Options:**
- `--targets` — Path to targets YAML file
- `--target` — Single target name (optional, defaults to all)
- `--output` — Markdown report path
- `--json-output` — JSON report path
- `--max-swarms` — Concurrent swarms
- `--max-iterations` — Iterations per swarm

#### `sandbox/Dockerfile.sandbox`
**Added Tools:**
- **Static Analysis:** semgrep, bandit, safety
- **Web Testing:** Playwright, sqlmap, requests-toolbelt
- **Fuzzing:** AFL++
- **Memory Analysis:** Valgrind, libasan
- **Reporting:** jinja2, markdown

## Migration Checklist

### For Existing CTF Projects
- [ ] Archive old CTFd integration code if needed
- [ ] Delete `pull_challenges.py`
- [ ] Update `.env` — remove CTFd settings
- [ ] Test new CLI with example targets

### For New Vulnerability Research Projects
- [ ] Copy `targets.example.yml` → `targets.yml`
- [ ] Define your targets (web apps, binaries, source repos)
- [ ] Configure API keys in `.env`
- [ ] Build new sandbox: `docker build -f sandbox/Dockerfile.sandbox -t ctf-sandbox .`
- [ ] Run research: `python -m backend.cli --targets targets.yml`

## File Inventory

### New Files
```
backend/finding.py              # Finding dataclass + deduplication
backend/target_loader.py        # VulnTarget + load_targets()
backend/reporter.py             # CostTracker + report generation
targets.example.yml             # Example target configuration
VULNERABILITY_RESEARCH.md       # Comprehensive guide
MIGRATION.md                    # This file
```

### Modified Files
```
backend/config.py               # Removed CTFd, added vuln research settings
backend/models.py               # Added SWARM_CONFIGS
backend/cli.py                  # Refactored for target-based research
.env.example                    # Updated for vulnerability research
sandbox/Dockerfile.sandbox      # Added security research tools
```

### Files to Delete (Optional)
```
pull_challenges.py              # No longer needed
```

### Files Still Using Old Logic (⚠️ Needs Updating)
```
backend/solver.py               # Update for Finding objects instead of flags
backend/solver_base.py          # Update status constants
backend/ctfd.py                 # No longer needed (can deprecate)
backend/prompts.py              # CTF challenge prompts (replace with vuln context)
backend/agents/swarm.py         # Update for target-based swarms
backend/agents/coordinator_core.py  # Update for vulnerability assignment
backend/agents/claude_coordinator.py # Implement run_claude_researcher()
backend/agents/codex_coordinator.py  # Implement run_codex_researcher()
```

## API Changes

### Finding Model (New)
```python
from backend.finding import Finding

finding = Finding(
    id=uuid.uuid4().hex,
    vuln_class="XSS",
    affected_component="/search?q",
    severity="high",
    description="Reflected XSS in search parameter",
    proof_of_concept='q=<img src=x onerror="alert(1)">',
    evidence="Screenshot showing alert(1) in browser",
    confirmed=True,
    solver_model="claude-opus-4-6",
)
```

### Target Model (New)
```python
from backend.target_loader import VulnTarget, load_targets

target = VulnTarget(
    name="MyApp",
    type="web",
    url="http://localhost:8080",
    repo_url="https://github.com/org/myapp",
    vuln_classes=["xss", "sqli", "auth"],
    scope_allowlist=["localhost:8080"],
)

targets = load_targets("targets.yml")
```

### CostTracker (New)
```python
from backend.reporter import CostTracker, ModelCall

tracker = CostTracker()
tracker.record(ModelCall(
    model="claude-opus-4-6",
    swarm_id="xss-swarm-1",
    vuln_class="xss",
    input_tokens=1000,
    output_tokens=500,
))

print(f"Total cost: ${tracker.total_cost():.2f}")
print(f"By model: {tracker.cost_by_model()}")
```

## Configuration Migration

### .env Changes

**Old (CTF Mode):**
```bash
CTFD_URL=https://ctf.example.com
CTFD_TOKEN=ctfd_your_token
CTFD_USER=admin
CTFD_PASS=admin
MAX_CONCURRENT_CHALLENGES=10
MAX_ATTEMPTS_PER_CHALLENGE=3
```

**New (Vulnerability Research Mode):**
```bash
TARGETS_FILE=targets.yml
MAX_CONCURRENT_SWARMS=10
MAX_ITERATIONS_PER_SWARM=50
# API keys remain the same
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
```

### targets.yml Format

```yaml
targets:
  - name: "MyTarget"
    type: web              # "web", "binary", or "source"
    url: "http://localhost:8080"
    repo_url: "https://github.com/org/myapp"
    vuln_classes: [xss, sqli, auth]
    scope_allowlist: ["localhost:8080"]
    description: "Target description"
```

## Reporting Changes

### Old Output
```
Challenge: Reverse a String
Status: CORRECT
Flag: flag{...}
Cost: $0.50
```

### New Output

**Markdown Report (report.md):**
```markdown
# Vulnerability Research Report
**Target:** MyApp
**Confirmed Findings:** 3

## Findings
- [CRITICAL] XSS in /search
- [HIGH] SQLi in /api/users
- [MEDIUM] Auth bypass in /admin
```

**JSON Report (report.json):**
```json
{
  "metadata": {...},
  "summary": {
    "total_findings": 3,
    "confirmed_findings": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1
    }
  },
  "findings": [{...}],
  "cost_analysis": {
    "total_cost_usd": 3.45,
    "cost_per_finding_usd": 1.15,
    "total_api_calls": 42
  }
}
```

## Testing

### 1. Verify Target Loading
```python
from backend.target_loader import load_targets
targets = load_targets("targets.example.yml")
assert len(targets) > 0
print(targets[0].name)
```

### 2. Verify Finding Model
```python
from backend.finding import Finding, deduplicate

f1 = Finding(vuln_class="XSS", affected_component="/search")
f2 = Finding(vuln_class="XSS", affected_component="/search", confirmed=True)
merged = deduplicate([f1, f2])
assert merged[0].confirmed == True
```

### 3. Verify Cost Tracking
```python
from backend.reporter import CostTracker, ModelCall
from datetime import datetime

tracker = CostTracker()
tracker.record(ModelCall(
    model="claude-opus-4-6",
    swarm_id="test",
    vuln_class="xss",
    input_tokens=1000,
    output_tokens=500,
))
assert tracker.total_cost() > 0
```

### 4. Verify CLI
```bash
# Test with example targets
python -m backend.cli --targets targets.example.yml --target ExampleWebApp --help

# Run single target
python -m backend.cli --targets targets.example.yml --target ExampleWebApp
```

## Breaking Changes

| Feature | Before | After | Migration |
|---------|--------|-------|-----------|
| Challenge selection | CLI `--challenge` | YAML `targets.yml` + `--target` | Define targets in YAML |
| Flag detection | Regex `flag{...}` | PoC validation | Update solvers for findings |
| Success metric | Flag submission | Confirmed finding + PoC | Update coordinator logic |
| Configuration | CTFd URL + token | Target YAML file | Rewrite `.env` and create targets |
| Coordinator role | Challenge fetcher | Swarm manager | No functional change needed |

## Backward Compatibility

**None.** This is a complete rewrite of the application logic. Existing CTF challenge solvers will not work with the new system.

**Recommendation:** Archive old CTFd-specific code if needed, but replace all solver/coordinator logic.

## Next Steps

1. **Integration Work:**
   - Update solver.py to create Finding objects
   - Update coordinators to assign swarms per vuln_class
   - Implement run_claude_researcher() and run_codex_researcher()

2. **Testing:**
   - Unit tests for Finding, VulnTarget, CostTracker
   - Integration tests with example targets
   - End-to-end test with real vulnerable app

3. **Deployment:**
   - Build new sandbox: `docker build -f sandbox/Dockerfile.sandbox -t ctf-sandbox .`
   - Test with OWASP Juice Shop or similar intentionally vulnerable app
   - Document findings from first research run

4. **Extension:**
   - Add new vulnerability classes (XXE, SSRF, path traversal)
   - Custom tool integrations (Burp, Zap, etc.)
   - Report template customization

---

**Status:** Foundation complete. Ready for solver/coordinator integration.
