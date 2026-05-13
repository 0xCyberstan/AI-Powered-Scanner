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
- **Neural layer:** Gemini 2.5 Flash performs broad per-function Scout triage; Gemini 2.5 Pro acts as the Judge over assembled structural evidence with a hardcoded reference-ownership ground-truth table covering ~60 CPython C-API functions (`NEW_REF` / `BORROWED` / `STEALS_ARGn` semantics).
- **BFS structural gate** discards findings with no path to a public entry, suppressing internal-only false positives before the expensive LLM call.
- UAF candidates are partitioned by synchronisation context so refcount operations protected by `_PyEval_StopTheWorld` are not flagged.

### `depth_ablation.py` — Stage 2 BFS depth ablation harness

Standalone script that loads a cached Django call graph and measures the maximum recoverable path depth for the production reverse BFS (see dissertation §4.2.3 and Appendix B).

- Tests `D ∈ {2, 4, 6, 8, 10, 12, 16, 20}` against 31 candidate sinks spanning Django's ORM query-compilation pipeline.
- Uses a variant `bfs_longest_path` that returns the *longest* path rather than the shortest, since the production system minimises hop count for direct exploitation routes whereas the ablation needs the structural ceiling.
- Public-entry termination is deliberately omitted so the result reflects the structural ceiling on recoverable depth rather than the production system's exploit-path constraint.
- Per-path (not global) cycle detection, since a global visited set would block alternative-path exploration and underestimate the true maximum.
- Prerequisite: run `python src/django_scan.py triage` first to produce `django_framework_scan.cache`.

## Architecture notes

Both production scanners share the same Scout/Judge separation:

- **Scout** (Gemini 2.5 Flash) runs first over every function-level AST node for broad detection.
- **Judge** (Gemini 2.5 Pro) runs only on Scout findings, with structural context (call paths, taint flow, lifecycle events) assembled deterministically and injected into the prompt.

The reasoning core is reused across both languages; only the graph ingestion layer differs (Python `ast` module vs. libclang).

Other shared engineering:

- Reverse BFS from sink to public entry with cycle detection, depth bounding (default 8), and global visited set.
- Thread-pool execution with exponential backoff on 429/500/503.
- Resumable runs — both scanners persist progress incrementally and can resume from a partial output file.
- `--show-prompts` flag inspects generated prompts without making API calls (useful for prompt iteration and cost estimation).

## Installation

    pip install -r requirements.txt

Requirements:

- `requests`, `python-dotenv`
- `libclang` Python bindings (CPython scanner only; requires system LLVM ≥ 18)

Copy `src/.env.example` to `src/.env` and set your `GEMINI_API_KEY`.

## Usage

    # Django scanner (two-stage)
    python src/django_scan.py scan /path/to/project -o initial.json
    python src/django_scan.py triage initial.json /path/to/project -o triaged.json

    # CPython scanner
    python src/cpython_scan.py /path/to/source -o audit.json
    python src/cpython_scan.py /path/to/source -o audit.json --resume

    # Depth ablation (run after `django_scan.py triage` has produced the cache file)
    python src/depth_ablation.py

## Repository structure

    .
    ├── src/
    │   ├── django_scan.py        # Django ORM logic-flaw scanner
    │   ├── cpython_scan.py       # CPython C-source memory/refcount scanner
    │   ├── depth_ablation.py     # Stage 2 BFS depth ablation harness (Appendix B)
    │   └── .env.example          # template for GEMINI_API_KEY
    ├── requirements.txt
    ├── LICENSE
    └── README.md

## License

Released under the [MIT License](LICENSE).
