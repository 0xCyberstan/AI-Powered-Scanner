# Two-Stage Neuro-Symbolic Vulnerability Scanners

Two scanners that combine deterministic program analysis (AST parsing, call-graph construction, lifecycle tracking) with LLM-based semantic reasoning, using a **Scout/Judge** architecture. Targets logic-based vulnerabilities that traditional SAST tools miss and unconstrained LLM analysis cannot reliably verify.

## Scanners

### `django_scan.py` — Django ORM auditor

Targets logic-based SQL injection arising from state contamination in ORM internals — specifically attribute injection via `**kwargs` flowing into query compilation, where public APIs accept arguments that reach internal SQL construction logic without sanitisation.

- **Stage 1 (Scout):** Gemini 2.5 Flash performs broad per-function triage across the codebase under a constrained search space (unsafe identifier handling, ORM abstraction subversion, attribute injection via dictionary unpacking).
- **Stage 2 (Judge):** Gemini 2.5 Pro reasons over each finding with reverse-BFS call-graph context from sink to public entry point (functions accepting `request`), plus AST-derived taint-flow summaries.
- Schema-constrained inference via Gemini's `responseSchema` directive guarantees machine-parsable JSON output.
- Source-fingerprinted JSON call-graph cache (SHA-256 over path/size/mtime) avoids pickle-based deserialisation risk.

### `cpython_scan.py` — CPython C-source auditor

Targets reference-counting bugs, use-after-free, GIL violations, GC protocol violations, and `tp_dealloc` re-entrancy in C code. Uses libclang for AST extraction.

- **Symbolic layer:** pointer lifecycle tracking (alloc/free/deref events with canonical expression matching), stop-the-world vs. GIL-release region detection (hybrid AST + comment-stripped line scan to handle macro expansion), weak-reference and exception-masking detection, free-threaded (`Py_GIL_DISABLED`) divergence detection.
- **Neural layer:** Gemini 2.5 Pro reasons over assembled structural evidence with a hardcoded reference-ownership ground-truth table covering ~60 CPython C-API functions (`NEW_REF` / `BORROWED` / `STEALS_ARGn` semantics).
- **BFS structural gate** discards findings with no path to a public entry, suppressing internal-only false positives before the expensive LLM call.
- UAF candidates are partitioned by synchronisation context so refcount operations protected by `_PyEval_StopTheWorld` are not flagged.

## Architecture notes

Both scanners share the same Scout/Judge separation:

- **Scout** runs the cheaper model over every function-level AST node for broad detection.
- **Judge** runs the higher-reasoning model only on Scout findings, with structural context (call paths, taint flow, lifecycle events) assembled deterministically and injected into the prompt.

The reasoning core is reused across both languages; only the graph ingestion layer differs (Python `ast` module vs. libclang).

Other shared engineering:

- Reverse BFS from sink to public entry with cycle detection, depth bounding (default 8), and global visited set.
- Thread-pool execution with exponential backoff on 429/500/503.
- Resumable runs — both scanners persist progress incrementally and can resume from a partial output file.
- `--show-prompts` flag inspects generated prompts without making API calls (useful for prompt iteration and cost estimation).

## Usage

```bash
# Django scanner (two-stage)
python django_scan.py scan /path/to/project -o initial.json
python django_scan.py triage initial.json /path/to/project -o triaged.json

# CPython scanner
python cpython_scan.py /path/to/source -o audit.json
python cpython_scan.py /path/to/source -o audit.json --resume   # skip already-audited functions
```

Set `GEMINI_API_KEY` in a `.env` file (see `.env.example`).

## Dependencies

- `requests`, `python-dotenv`
- `libclang` Python bindings (CPython scanner only; requires system LLVM ≥ 18)

```bash
pip install requests python-dotenv libclang
```

## Repository structure

```
.
├── django_scan.py      # Django ORM logic-flaw scanner
├── cpython_scan.py     # CPython C-source memory/refcount scanner
├── README.md
├── LICENSE
└── .env.example        # template for GEMINI_API_KEY
```

## License

Released under the [MIT License](LICENSE).
