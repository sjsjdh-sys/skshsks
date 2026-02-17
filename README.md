# test

> **test**: A three-agent security auditing pipeline built on LangGraph, ChromaDB, and Claude.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         LangGraph DAG                           │
│                                                                 │
│   ┌──────────────┐      ┌─────────────────┐                    │
│   │  SUPERVISOR  │─────▶│   RESEARCHER    │                    │
│   │              │◀─────│  (Taint Analyst)│                    │
│   │ "Security    │      └─────────────────┘                    │
│   │  Lead"       │                                              │
│   │              │      ┌─────────────────┐                    │
│   │  Manages:    │─────▶│   VALIDATOR     │                    │
│   │  - File queue│◀─────│  (Prosecutor /  │                    │
│   │  - State     │      │   FP Detector)  │                    │
│   │  - Routing   │      └─────────────────┘                    │
│   └──────────────┘                                              │
│          │                                                      │
│          ▼                                                      │
│        [END]                                                    │
└─────────────────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
  ChromaDB (AST-indexed)    audit_state.json
  code chunks               (persistent state)
```

### Agent Personas

| Agent | Persona | Responsibility |
|-------|---------|---------------|
| **Supervisor** | Pragmatic Security Lead | Prioritizes files (APIs/DBs first), runs Semgrep, delegates tasks |
| **Researcher** | Deep-Dive Taint Analyst | Traces data from user input → dangerous sink, produces `DraftFinding` |
| **Validator** | Skeptical Auditor / Prosecutor | Aggressively finds false positives; confirms only clear vulnerabilities |

---

## Directory Structure

```
security_agent/
├── main.py                  # LangGraph workflow + CLI entry point
├── core/
│   ├── schema.py            # Pydantic models (AuditState, DraftFinding, etc.)
│   ├── vector_db.py         # AST chunker + ChromaDB engine
│   └── state_manager.py     # JSON persistence for audit_state.json
├── agents/
│   ├── supervisor.py        # Supervisor node (orchestrator + router)
│   ├── researcher.py        # Researcher node (taint analysis)
│   └── validator.py         # Validator node (false positive elimination)
├── tools/
│   ├── file_utils.py        # list_files, read_function, read_file
│   └── scanner_utils.py     # semgrep_wrapper, ast_pattern_scan, query_code
├── example_target/
│   └── app.py               # Deliberately vulnerable Flask app (for testing)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick Start

### 1. Install Dependencies

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install Python dependencies
pip install -r requirements.txt

# Optional but recommended: install Semgrep for enhanced scanning
pip install semgrep
# or: brew install semgrep
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set your ANTHROPIC_API_KEY
```

### 3. Run the Auditor

```bash
# Audit the included vulnerable test app
python main.py --repo ./example_target

# Audit your own project
python main.py --repo /path/to/your/flask/app

# Resume an interrupted audit
python main.py --repo /path/to/your/flask/app --resume

# Verbose mode (debug logging)
python main.py --repo ./example_target --verbose

# Limit to 10 LangGraph iterations (for quick testing)
python main.py --repo ./example_target --max-iter 10
```

---

## Data Flow

```
list_files(repo)
    │
    ▼
[prioritize by security relevance]
    │
    ▼ For each file:
semgrep_wrapper(file)    ─────┐
ast_pattern_scan(file)   ─────┤──▶ SemgrepMatch list
query_code(engine, file) ─────┘
    │
    ▼
Supervisor LLM decides: DELEGATE_RESEARCH | SKIP | COMPLETE
    │
    ▼ (if DELEGATE_RESEARCH)
ResearchTask ──▶ Researcher LLM
                     │
                     ▼
                DraftFinding (with taint path)
                     │
                     ▼
Supervisor routes ──▶ ValidationTask ──▶ Validator LLM
                                              │
                                              ▼
                                    CONFIRM ──▶ ConfirmedFinding
                                    REJECT  ──▶ RejectedFinding (FP)
```

---

## Key Design Decisions

### Stateless Agent Handoffs
Each agent receives only the context needed for its current task:
- **Researcher** gets: `ResearchTask` (file path, focus area, semgrep hits)
- **Validator** gets: `ValidationTask` (draft finding + source code + sanitizer search)

### AST-Based Chunking
Instead of naive line-based chunking, the vector engine extracts:
- `FunctionDef` nodes with their complete bodies
- `AsyncFunctionDef` nodes
- `ClassDef` nodes  
- Method nodes with `parent_class` metadata

This enables precise semantic search for "functions that validate input" or "database query functions."

### Validator as Prosecutor
The Validator's LLM prompt instructs it to *actively try to disprove* findings:
1. Is there sanitization before the sink?
2. Is the code actually reachable from user input?
3. Are the values hardcoded (not user-controlled)?
4. Does the framework protect automatically?
5. Is this test/dead code?

Only findings that survive this interrogation are confirmed.

---

## Output

### Console Output
```
[  4.2s] Phase: RESEARCHER   | Files: 3/12 | ✓ 2 findings | ✗ 1 FP | Pending: 9

======================================================================
  SECURITY AUDIT COMPLETE
======================================================================
  Session ID   : a3f8c2d1
  Target       : /path/to/flask_app
  Files Scanned: 12/12
  Failed Files : 0

  CONFIRMED FINDINGS: 3
  REJECTED (FP)     : 2

  ┌─ CONFIRMED VULNERABILITIES ───────────────────────────────────
  │  1. 🔴 [CRITICAL] SQL Injection in get_user()
  │     File: /path/to/flask_app/views/users.py
  │     Func: get_user()
  │     CWE : CWE-89
  │     Rem : Use parameterized queries: cursor.execute("... WHERE id=?", (id,))
  │
  │  2. 🟠 [HIGH] Command Injection in run_diagnostic()
  │     File: /path/to/flask_app/utils/diagnostics.py
  │     Func: run_diagnostic()
  │     CWE : CWE-78
  │     Rem : Use subprocess with list args and shell=False
  └──────────────────────────────────────────────────────────────
```

### JSON Report
A full machine-readable report is saved to `security_report_<session_id>.json` including:
- All confirmed findings with taint paths and remediation
- All rejected findings with reasons
- Severity breakdown
- Scanned file list
- Error log

---

## Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `ANTHROPIC_API_KEY` | *required* | Your Anthropic API key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5-20250929` | Model for all agents |
| `CHROMA_PERSIST_DIR` | `.chroma_db` | ChromaDB storage directory |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence-transformer model |
| `SEMGREP_CONFIG` | `auto` | Semgrep ruleset |
| `SEMGREP_TIMEOUT` | `60` | Semgrep timeout in seconds |

---

## CLI Reference

```
usage: test [-h] --repo REPO [--resume] [--max-iter N]
                [--state-file PATH] [--chroma-dir PATH] [--verbose] [--no-report]

options:
  --repo PATH        Path to the Python repository to audit (required)
  --resume           Resume from a previous audit_state.json
  --max-iter N       Maximum LangGraph iterations (default: 50)
  --state-file PATH  Audit state file path (default: audit_state.json)
  --chroma-dir PATH  ChromaDB directory (default: .chroma_db)
  --verbose, -v      Enable debug logging
  --no-report        Skip exporting the final JSON report
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit complete, no CRITICAL/HIGH findings confirmed |
| `1` | One or more CRITICAL/HIGH findings confirmed |

This makes test suitable for use in CI/CD pipelines.

---

## Extending test

### Adding Custom Semgrep Rules
Place `.yaml` rule files in a `rules/` directory and pass `--config=./rules` in `scanner_utils.py`.

### Adding New Vulnerability Patterns
Edit `DANGEROUS_CALLS` in `tools/scanner_utils.py` to add new AST-detected sink patterns.

### Adding a New Agent
1. Create `agents/my_agent.py` with a `my_agent_node(state, engine) -> AuditState` function
2. Add the node to `build_graph()` in `main.py`
3. Add routing logic in `route_from_*` functions
