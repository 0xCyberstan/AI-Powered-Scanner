import os
import sys
import json
import argparse
import time
import random
import re
import requests
import concurrent.futures
import threading
from dotenv import load_dotenv

try:
    from clang.cindex import Config, Index, CursorKind
    Config.set_library_file("/usr/lib/llvm-18/lib/libclang.so")
except ImportError:
    print("Error: 'libclang' Python bindings not found. Run: pip install libclang", file=sys.stderr)
    sys.exit(1)

API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
SCAN_MODEL = "gemini-2.5-flash"
MODEL_JUDGE = "gemini-2.5-pro"

BATCH_SIZE_SCOUT = 10
MAX_WORKERS = 16

# Cap BFS path enumeration; Judge only uses the first path.
MAX_BFS_PATHS = 20
DEFAULT_BFS_DEPTH = 8

# Flush findings to disk every N findings.
SAVE_INTERVAL_FINDINGS = 5


# Reference ownership semantics for CPython C-API functions.
#   NEW_REF      -- caller owns, must DECREF
#   BORROWED     -- caller does not own, must not DECREF
#   STEALS_ARGn  -- callee takes ownership of argument n (0-indexed)
REF_OWNERSHIP = {
    # New references (caller must DECREF)
    "PyLong_FromLong":                  "NEW_REF",
    "PyLong_FromSsize_t":               "NEW_REF",
    "PyLong_FromSize_t":                "NEW_REF",
    "PyFloat_FromDouble":               "NEW_REF",
    "PyBool_FromLong":                  "NEW_REF",
    "PyUnicode_FromString":             "NEW_REF",
    "PyUnicode_FromStringAndSize":      "NEW_REF",
    "PyUnicode_FromFormat":             "NEW_REF",
    "PyBytes_FromString":               "NEW_REF",
    "PyBytes_FromStringAndSize":        "NEW_REF",
    "PyByteArray_FromStringAndSize":    "NEW_REF",
    "PyList_New":                       "NEW_REF",
    "PyTuple_New":                      "NEW_REF",
    "PyDict_New":                       "NEW_REF",
    "PySet_New":                        "NEW_REF",
    "PyFrozenSet_New":                  "NEW_REF",
    "PyObject_GetAttr":                 "NEW_REF",
    "PyObject_GetAttrString":           "NEW_REF",
    "PyObject_GetItem":                 "NEW_REF",
    "PyObject_CallObject":              "NEW_REF",
    "PyObject_CallFunction":            "NEW_REF",
    "PyObject_CallMethod":              "NEW_REF",
    "PyObject_Call":                    "NEW_REF",
    "PyObject_Repr":                    "NEW_REF",
    "PyObject_Str":                     "NEW_REF",
    "PyObject_RichCompare":             "NEW_REF",
    "PyObject_Type":                    "NEW_REF",
    "PyObject_Dir":                     "NEW_REF",
    "PySequence_GetItem":               "NEW_REF",
    "PySequence_GetSlice":              "NEW_REF",
    "PyMapping_GetItemString":          "NEW_REF",
    "PyDict_GetItemWithError":          "NEW_REF",
    "PyDict_Items":                     "NEW_REF",
    "PyDict_Keys":                      "NEW_REF",
    "PyDict_Values":                    "NEW_REF",
    "PyDict_Copy":                      "NEW_REF",
    "PyList_GetItem":                   "NEW_REF",
    "PyErr_GetRaisedException":         "NEW_REF",   # also clears exc state
    "PyErr_GetExcInfo":                 "NEW_REF",
    "Py_NewRef":                        "NEW_REF",
    "Py_XNewRef":                       "NEW_REF",
    "_PyObject_CallMethodIdObjArgs":    "NEW_REF",
    "PyImport_Import":                  "NEW_REF",
    "PyImport_ImportModule":            "NEW_REF",
    "PyImport_ImportModuleLevelObject": "NEW_REF",
    "PyRun_String":                     "NEW_REF",
    "PyEval_EvalCode":                  "NEW_REF",
    "PyNumber_Add":                     "NEW_REF",
    "PyNumber_Multiply":                "NEW_REF",
    "PyIter_Next":                      "NEW_REF",
    "PyWeakref_NewRef":                 "NEW_REF",
    "PyWeakref_NewProxy":               "NEW_REF",
    "PyCode_New":                       "NEW_REF",
    "PyFrame_New":                      "NEW_REF",

    # Borrowed references (caller must not DECREF)
    "PyList_GET_ITEM":                  "BORROWED",  # macro, no bounds check
    "PyTuple_GET_ITEM":                 "BORROWED",  # macro, no bounds check
    "PyDict_GetItem":                   "BORROWED",  # NULL without exc on miss
    "PyDict_GetItemString":             "BORROWED",
    "PySequence_Fast_GET_ITEM":         "BORROWED",
    "PyErr_Occurred":                   "BORROWED",
    "PyImport_GetModuleDict":           "BORROWED",
    "PySys_GetObject":                  "BORROWED",
    "PyEval_GetBuiltins":               "BORROWED",
    "PyEval_GetLocals":                 "BORROWED",
    "PyEval_GetGlobals":                "BORROWED",
    "PyThreadState_GetDict":            "BORROWED",
    "PyWeakref_GET_OBJECT":             "BORROWED",  # can become Py_None at GC
    "Py_TYPE":                          "BORROWED",
    "Py_GET_TYPE":                      "BORROWED",

    # Reference-stealing
    "PyTuple_SET_ITEM":                 "STEALS_ARG2",  # (tuple, index, item)
    "PyList_SET_ITEM":                  "STEALS_ARG2",  # (list, index, item)
    "PyTuple_SetItem":                  "STEALS_ARG2",
    "PyList_SetItem":                   "STEALS_ARG2",
    "PyErr_SetObject":                  "STEALS_ARG1",
    "PyErr_SetRaisedException":         "STEALS_ARG0",
    "_PyErr_SetRaisedException":        "STEALS_ARG1",
    "PyModule_AddObject":               "STEALS_ARG2_ON_SUCCESS_ONLY",
    "_PyTuple_FromArraySteal":          "STEALS_ALL_ARGS",
}

# Borrowed-ref functions whose result can be invalidated by GC.
WEAK_REF_FUNCTIONS = {
    "PyWeakref_GET_OBJECT",
    "PyWeakref_GetObject",
}

# GC type slot name fragments.
GC_SLOT_PATTERNS = {"tp_traverse", "tp_clear", "tp_dealloc", "tp_finalize"}

# Immortal object guards (Python 3.12+); missing DECREF inside is intentional.
IMMORTAL_GUARDS = {"_Py_IsImmortal", "_Py_IsImmortalLoose"}

# Specialising adaptive interpreter; locking too complex for static analysis.
SPECIALISING_PREFIXES = ("_Py_Specialize_", "_PyAdaptiveEntry_", "specialize_")

# Memory lifecycle primitives.
ALLOC_FUNCTIONS = {
    "PyMem_Malloc", "PyMem_Calloc", "PyMem_Realloc",
    "PyObject_Malloc", "PyObject_Calloc", "PyObject_Realloc",
    "malloc", "calloc", "realloc",
}
FREE_FUNCTIONS = {
    "PyMem_Free", "PyObject_Free", "free", "munmap",
    "Py_DECREF", "Py_XDECREF", "Py_CLEAR",
}
DEREF_KINDS = {CursorKind.MEMBER_REF_EXPR, CursorKind.ARRAY_SUBSCRIPT_EXPR}

# Synchronisation primitives.
STOP_THE_WORLD_FUNCTIONS = {"_PyEval_StopTheWorld", "_PyEval_StopTheWorldAll"}
START_THE_WORLD_FUNCTIONS = {"_PyEval_StartTheWorld", "_PyEval_StartTheWorldAll"}
GIL_RELEASE_MARKERS = {"Py_BEGIN_ALLOW_THREADS", "PyEval_SaveThread", "_PyThreadState_Detach"}
GIL_RESTORE_MARKERS = {"Py_END_ALLOW_THREADS", "PyEval_RestoreThread", "_PyThreadState_Attach"}

def is_public_entry_name(name):
    """Public entry: external linkage and no leading underscore (CPython convention)."""
    return bool(name) and not name.startswith("_")


# Build reference ownership lookup string for prompt injection.
def _build_ref_ownership_table():
    lines = []
    for fn, ownership in sorted(REF_OWNERSHIP.items()):
        lines.append(f"  {fn:<48} -> {ownership}")
    return "\n".join(lines)

REF_OWNERSHIP_TABLE = _build_ref_ownership_table()


def _retry_api(model, payload, api_key):
    url = f"{API_BASE_URL}/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    for attempt in range(5):
        try:
            resp = requests.post(url, headers=headers,
                                 data=json.dumps(payload), timeout=120)
            if resp.status_code in [429, 500, 503]:
                time.sleep((2 ** attempt) + random.uniform(0, 1))
                continue
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            if attempt == 4:
                print(f"  [!] API failed after retries: {e}", file=sys.stderr)
    return None

def clean_json(text):
    if not text:
        return ""
    for pattern in [r"```json\s*(.*?)\s*```", r"```\s*(.*?)\s*```"]:
        m = re.search(pattern, text, re.DOTALL)
        if m:
            return m.group(1).strip()
    return text.strip()

def get_llm_text(api_response):
    """Extract text from a Gemini response, skipping thought traces."""
    if not api_response:
        return ""
    parts = (api_response.get("candidates", [{}])[0]
             .get("content", {})
             .get("parts", []))
    for part in reversed(parts):
        txt = part.get("text", "").strip()
        if txt:
            return txt
    return ""


def _collect_sync_calls(func_cursor, function_names):
    """Return sorted (line, callee) for CALL_EXPRs whose callee is in function_names."""
    matches = []
    for child in func_cursor.walk_preorder():
        if child.kind == CursorKind.CALL_EXPR and child.spelling in function_names:
            matches.append((child.location.line, child.spelling))
    matches.sort(key=lambda t: t[0])
    return matches

def _pair_into_regions(open_calls, close_calls):
    """Pair (line, name) opens/closes into (open_line, close_line) regions via stack."""
    events = ([(line, "open") for line, _ in open_calls] +
              [(line, "close") for line, _ in close_calls])
    events.sort(key=lambda t: t[0])
    regions, stack = [], []
    for line, kind in events:
        if kind == "open":
            stack.append(line)
        elif stack:
            regions.append((stack.pop(), line))
    return regions

# Macro markers (Py_BEGIN_ALLOW_THREADS etc) aren't visible to libclang since
# the preprocessor expands them before AST construction; fall back to a line
# scan against comment-stripped source.
_LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')

def _strip_noncode(text):
    """Remove comments and string literals from C source."""
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _LINE_COMMENT_RE.sub("", text)
    text = _STRING_RE.sub('""', text)
    return text

def detect_stop_the_world_regions_ast(func_cursor):
    """AST-based STW region detection."""
    opens = _collect_sync_calls(func_cursor, STOP_THE_WORLD_FUNCTIONS)
    closes = _collect_sync_calls(func_cursor, START_THE_WORLD_FUNCTIONS)
    return _pair_into_regions(opens, closes)

def detect_gil_release_regions_hybrid(func_cursor, code):
    """GIL-release detection: AST for function calls, line scan for macros."""
    fn_release = {"PyEval_SaveThread", "_PyThreadState_Detach"}
    fn_restore = {"PyEval_RestoreThread", "_PyThreadState_Attach"}
    opens = _collect_sync_calls(func_cursor, fn_release)
    closes = _collect_sync_calls(func_cursor, fn_restore)

    # Macro-only markers via comment-stripped line scan.
    macro_open = {"Py_BEGIN_ALLOW_THREADS"}
    macro_close = {"Py_END_ALLOW_THREADS"}
    stripped = _strip_noncode(code)
    for i, line in enumerate(stripped.splitlines(), start=1):
        if any(m in line for m in macro_open):
            opens.append((i, "Py_BEGIN_ALLOW_THREADS"))
        if any(m in line for m in macro_close):
            closes.append((i, "Py_END_ALLOW_THREADS"))

    return _pair_into_regions(opens, closes)

def is_line_in_region(line_no, regions):
    return any(s <= line_no <= e for s, e in regions)

def detect_weak_ref_usage_ast(func_cursor):
    """AST-based weak-ref usage detection. Returns line numbers."""
    return sorted({
        child.location.line
        for child in func_cursor.walk_preorder()
        if child.kind == CursorKind.CALL_EXPR and child.spelling in WEAK_REF_FUNCTIONS
    })

def detect_gc_slots(name):
    return any(pat in name for pat in GC_SLOT_PATTERNS)

def detect_immortal_guards(code):
    return any(g in _strip_noncode(code) for g in IMMORTAL_GUARDS)

def is_specialising_function(name):
    return any(name.startswith(p) for p in SPECIALISING_PREFIXES)

def detect_exception_masking_ast(func_cursor):
    """AST-based PyErr_Clear() detection."""
    return sorted({
        child.location.line
        for child in func_cursor.walk_preorder()
        if child.kind == CursorKind.CALL_EXPR and child.spelling == "PyErr_Clear"
    })

def detect_module_add_object_ast(func_cursor):
    """AST-based PyModule_AddObject() detection."""
    return sorted({
        child.location.line
        for child in func_cursor.walk_preorder()
        if child.kind == CursorKind.CALL_EXPR and child.spelling == "PyModule_AddObject"
    })

def detect_tpdealloc_reentrancy_risk(code):
    """
    Detect Py_DECREF followed by access to the same variable within 5 lines:
    a potential tp_dealloc re-entrancy UAF. Operates on comment-stripped source.
    """
    stripped = _strip_noncode(code)
    lines = stripped.splitlines()
    risks = []
    for i, line in enumerate(lines):
        m = re.search(r'Py_X?DECREF\((\w+)', line)
        if m:
            var = m.group(1)
            for j in range(i + 1, min(i + 6, len(lines))):
                if var in lines[j] and "Py_DECREF" not in lines[j]:
                    risks.append({
                        "var": var,
                        "decref_line": i + 1,
                        "access_line": j + 1,
                    })
                    break
    return risks

def detect_gil_disabled_branches(code):
    """True if function has free-threaded divergence branches."""
    stripped = _strip_noncode(code)
    return "Py_GIL_DISABLED" in stripped or "ifdef Py_GIL_DISABLED" in stripped


def _canonical_pointer_expr(cursor):
    """
    Canonical string form of a pointer expression for matching alloc/free/deref
    events on the same pointer location. Subscripts collapse to "[]" since the
    index expression cannot in general be proved equal across call sites; this
    is a sound over-approximation (more candidates, filtered by Judge).

    Examples:
        ptr            -> "ptr"
        obj->buf       -> "obj->buf"
        obj->arenas[i] -> "obj->arenas[]"
        (*pp)->field   -> "*pp->field"
    """
    if cursor is None:
        return ""

    kind = cursor.kind

    if kind == CursorKind.DECL_REF_EXPR:
        return cursor.spelling or ""

    if kind == CursorKind.MEMBER_REF_EXPR:
        children = list(cursor.get_children())
        base = _canonical_pointer_expr(children[0]) if children else ""
        # Approximate operator as "->" (common case for ptr-to-struct in CPython).
        member = cursor.spelling or ""
        if base and member:
            return f"{base}->{member}"
        return member or base

    if kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
        children = list(cursor.get_children())
        base = _canonical_pointer_expr(children[0]) if children else ""
        return f"{base}[]" if base else "[]"

    if kind == CursorKind.UNARY_OPERATOR:
        children = list(cursor.get_children())
        inner = _canonical_pointer_expr(children[0]) if children else ""
        # libclang doesn't expose the operator without tokenising; '*' is a
        # reasonable approximation and still gives a stable key.
        return f"*{inner}" if inner else ""

    if kind == CursorKind.PAREN_EXPR:
        children = list(cursor.get_children())
        return _canonical_pointer_expr(children[0]) if children else ""

    if kind == CursorKind.CSTYLE_CAST_EXPR or kind == CursorKind.UNEXPOSED_EXPR:
        # Look through casts and implicit conversions.
        children = list(cursor.get_children())
        for c in children:
            rendered = _canonical_pointer_expr(c)
            if rendered:
                return rendered
        return ""

    return cursor.spelling or ""


class ClangExtractor:

    @staticmethod
    def _get_include_flags(root_dir):
        paths = {root_dir}
        for root, _, files in os.walk(root_dir):
            if any(f.endswith((".h", ".hpp")) for f in files):
                paths.add(root)
        return [f"-I{p}" for p in paths]

    @staticmethod
    def _classify_call(call_name):
        if call_name in ALLOC_FUNCTIONS:
            return "ALLOCATED"
        if call_name in FREE_FUNCTIONS:
            return "FREED"
        return None

    @staticmethod
    def _extract_lifecycle_events(func_cursor):
        """
        Record ALLOCATED / FREED / DEREFERENCED events per pointer expression.

        Argument expressions to alloc/free calls are themselves MEMBER_REF_EXPR /
        ARRAY_SUBSCRIPT_EXPR cursors, which would otherwise be double-counted as
        a synthetic dereference at the call site. Suppress every descendant of
        recognised alloc/free calls from the deref pass.
        """
        events = []

        # First pass: alloc/free CALL_EXPRs and the cursor IDs of their argument subtrees.
        suppressed_ids = set()
        call_events = []
        for child in func_cursor.walk_preorder():
            if child.kind == CursorKind.CALL_EXPR:
                call_name = child.spelling
                state = ClangExtractor._classify_call(call_name)
                if state:
                    args = list(child.get_arguments())
                    var_expr = (_canonical_pointer_expr(args[0])
                                if args else call_name)
                    if var_expr:
                        call_events.append({
                            "var": var_expr,
                            "state": state,
                            "line": child.location.line,
                        })
                    for descendant in child.walk_preorder():
                        suppressed_ids.add(id(descendant))

        events.extend(call_events)

        # Second pass: dereferences not nested inside an alloc/free call.
        for child in func_cursor.walk_preorder():
            if id(child) in suppressed_ids:
                continue
            if child.kind in DEREF_KINDS:
                var_expr = _canonical_pointer_expr(child)
                if var_expr:
                    events.append({
                        "var": var_expr,
                        "state": "DEREFERENCED",
                        "line": child.location.line,
                    })

        return events

    @staticmethod
    def _detect_uaf_candidates(events):
        candidates, freed = [], {}
        for ev in events:
            if ev["state"] == "FREED":
                freed[ev["var"]] = ev["line"]
            elif ev["state"] == "DEREFERENCED" and ev["var"] in freed:
                candidates.append({
                    "var": ev["var"],
                    "freed_line": freed[ev["var"]],
                    "deref_line": ev["line"],
                })
        return candidates

    @staticmethod
    def extract(file_path, root_dir, include_flags):
        nodes = []
        try:
            index = Index.create()
            tu = index.parse(file_path, args=["-std=c11"] + include_flags)
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            relative_path = os.path.relpath(file_path, root_dir)

            for node in tu.cursor.get_children():
                if not (node.kind == CursorKind.FUNCTION_DECL and node.is_definition()):
                    continue
                if is_specialising_function(node.spelling):
                    continue  # internal locking too complex for static analysis

                start = node.extent.start.line - 1
                end   = node.extent.end.line - 1
                code  = "".join(lines[start:end + 1])

                calls = set()
                for child in node.walk_preorder():
                    if child.kind == CursorKind.CALL_EXPR:
                        calls.add(child.spelling)

                lifecycle_events = ClangExtractor._extract_lifecycle_events(node)
                uaf_candidates   = ClangExtractor._detect_uaf_candidates(lifecycle_events)
                stw_regions      = detect_stop_the_world_regions_ast(node)
                gil_release_regs = detect_gil_release_regions_hybrid(node, code)

                # Annotate each UAF candidate with protection status.
                for c in uaf_candidates:
                    c["in_stw_region"] = (
                        is_line_in_region(c["freed_line"], stw_regions) or
                        is_line_in_region(c["deref_line"], stw_regions)
                    )
                    c["in_gil_release"] = (
                        is_line_in_region(c["freed_line"], gil_release_regs) or
                        is_line_in_region(c["deref_line"], gil_release_regs)
                    )

                nodes.append({
                    "name":                 node.spelling,
                    "code":                 code,
                    "calls":                list(calls),
                    "file":                 relative_path,
                    "summary":              None,
                    "lifecycle":            lifecycle_events,
                    "uaf_candidates":       uaf_candidates,
                    "stw_regions":          stw_regions,
                    "gil_release_regs":     gil_release_regs,
                    "weak_ref_lines":       detect_weak_ref_usage_ast(node),
                    "is_gc_slot":           detect_gc_slots(node.spelling),
                    "has_immortal_guards":  detect_immortal_guards(code),
                    "exception_clears":     detect_exception_masking_ast(node),
                    "tpdealloc_risks":      detect_tpdealloc_reentrancy_risk(code),
                    "has_gil_disabled":     detect_gil_disabled_branches(code),
                    "module_add_object":    detect_module_add_object_ast(node),
                })
        except Exception as e:
            print(f"  [-] Parse failed for {file_path}: {e}")
        return nodes


class CallGraph:
    """
    Reverse call graph: { callee -> [caller, ...] }.
    bfs_reverse walks from a sink back to a public entry point.
    """

    def __init__(self, all_nodes):
        self.graph = {}
        for node in all_nodes:
            for callee in node["calls"]:
                self.graph.setdefault(callee, [])
                info = {"name": node["name"], "file": node["file"]}
                if info not in self.graph[callee]:
                    self.graph[callee].append(info)

    def bfs_reverse(self, sink_name, max_depth=DEFAULT_BFS_DEPTH,
                    max_paths=MAX_BFS_PATHS):
        """
        Return up to max_paths paths to a public entry, ordered shortest-first.
        Each path is a list of {name, file} dicts ending at the sink. Empty if
        no path reaches a public entry within max_depth.

        Uses a global visited set rather than per-path: trades alternative-path
        diversity for tractability against highly-shared sinks like Py_DECREF.
        """
        paths = []
        queue = [[{"name": sink_name, "file": "UNKNOWN"}]]
        globally_visited = {sink_name}

        while queue and len(paths) < max_paths:
            path = queue.pop(0)
            current = path[0]["name"]

            # Public entry reached; require non-trivial path (at least one caller).
            if is_public_entry_name(current) and len(path) > 1:
                paths.append(path)
                continue

            if len(path) > max_depth:
                continue

            for caller in self.graph.get(current, []):
                cname = caller["name"]
                if cname in globally_visited:
                    continue
                globally_visited.add(cname)
                queue.append([caller] + path)

        paths.sort(key=len)
        return paths


def generate_security_signatures(batch_nodes, api_key):
    if not batch_nodes:
        return []

    code_blocks = "\n\n".join(
        f"### FUNCTION: {n['name']}\n{n['code']}" for n in batch_nodes
    )

    prompt = f"""You are a CPython Core Developer assistant.
Analyse these C functions and produce a Security Signature for each.

## CRITICAL: CPython Synchronisation Hierarchy

### _PyEval_StopTheWorld / _PyEval_StartTheWorld
TRUE stop-the-world: ALL other threads SUSPENDED until StartTheWorld returns.
Py_INCREF / Py_DECREF / Py_XNewRef INSIDE this block are SAFE BY CONSTRUCTION.
Do NOT classify this as a GIL release -- it provides stronger serialisation.

### Py_BEGIN_ALLOW_THREADS / PyEval_SaveThread / _PyThreadState_Detach
These RELEASE the GIL. Concurrent threads CAN run. Python object access
inside these blocks IS unsafe and SHOULD be flagged as GIL violations.

### PyMutex_Lock / Py_BEGIN_CRITICAL_SECTION (#ifdef Py_GIL_DISABLED)
Per-object/per-interpreter locks used in free-threaded builds.
Not equivalent to the GIL -- provide localised mutual exclusion only.

## Reference Ownership Table (ground truth -- consult before any verdict):
{REF_OWNERSHIP_TABLE}

## Critical rules from the table:
- PyDict_GetItem           -> BORROWED. Py_DECREF on result = double-free.
- PyErr_GetRaisedException -> NEW_REF + clears exc state. Must restore on ALL paths.
- PyTuple_SET_ITEM         -> STEALS_ARG2. Py_DECREF after = double-free.
- PyModule_AddObject       -> STEALS_ARG2 ON SUCCESS ONLY. Must Py_DECREF on failure.
- PyWeakref_GET_OBJECT     -> BORROWED, can become Py_None at any GC point.

## Security Signature focus areas:
1. Ref Ownership: NEW_REF / BORROWED / STEALS_ARGn?
2. Ref Stealing: Steals a reference from any argument?
3. Synchronisation: StopTheWorld (serialised/safe) / GIL-release (unsafe) /
   critical section / none?
4. Memory: Allocates raw memory the caller must free?
5. GC slot: Is this tp_traverse, tp_clear, tp_dealloc, or tp_finalize?
6. Exception state: Consumes or modifies the current thread exception state?
7. Free-threaded: Contains #ifdef Py_GIL_DISABLED divergence?

Return a JSON list ONLY -- no prose:
[{{"name": "func_name", "signature": "concise security signature"}}]

CODE:
{code_blocks}"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
        },
    }
    res = _retry_api(MODEL_SCOUT, payload, api_key)
    if not res:
        return []
    try:
        return json.loads(clean_json(get_llm_text(res)))
    except Exception:
        return []


def _build_structural_context(node):
    """Assemble all parser annotations into a single evidence block."""
    lines = []

    # Synchronisation regions.
    stw = node.get("stw_regions", [])
    lines.append("### STOP-THE-WORLD REGIONS (refcount ops SAFE -- all threads suspended):")
    if stw:
        for s, e in stw:
            lines.append(f"  Lines {s}-{e}: world stopped, no concurrent access possible")
    else:
        lines.append("  None.")

    gil = node.get("gil_release_regs", [])
    lines.append("### GIL-RELEASE REGIONS (Python object access UNSAFE):")
    if gil:
        for s, e in gil:
            lines.append(f"  Lines {s}-{e}: GIL released, concurrent threads active")
    else:
        lines.append("  None.")

    # UAF candidates partitioned by protection status.
    real_uaf = [c for c in node["uaf_candidates"] if not c.get("in_stw_region")]
    stw_safe = [c for c in node["uaf_candidates"] if c.get("in_stw_region")]
    lines.append("### POINTER LIFECYCLE UAF CANDIDATES:")
    if real_uaf:
        lines.append("  UNPROTECTED (potentially exploitable):")
        for c in real_uaf:
            gil_note = " [INSIDE GIL-release region -- high risk]" if c.get("in_gil_release") else ""
            lines.append(f"    '{c['var']}': freed L{c['freed_line']}, "
                         f"deref L{c['deref_line']}{gil_note}")
    if stw_safe:
        lines.append("  STW-PROTECTED (safe by construction -- DO NOT flag):")
        for c in stw_safe:
            lines.append(f"    '{c['var']}': freed L{c['freed_line']}, "
                         f"deref L{c['deref_line']} [world stopped -- no race]")
    if not real_uaf and not stw_safe:
        lines.append("  None detected.")

    # tp_dealloc re-entrancy risks.
    risks = node.get("tpdealloc_risks", [])
    if risks:
        lines.append("### TP_DEALLOC RE-ENTRANCY RISKS:")
        for r in risks:
            lines.append(f"  '{r['var']}': Py_DECREF L{r['decref_line']}, "
                         f"accessed L{r['access_line']} -- tp_dealloc could run between these")

    # Weak references.
    wr = node.get("weak_ref_lines", [])
    if wr:
        lines.append(f"### WEAK REFERENCE USAGE at lines: {wr}")
        lines.append("  PyWeakref_GET_OBJECT -> BORROWED, can become Py_None at any GC point.")
        lines.append("  Verify: (1) checked != Py_None, (2) Py_INCREF before any call.")

    # Exception masking.
    exc = node.get("exception_clears", [])
    if exc:
        lines.append(f"### PyErr_Clear() at lines: {exc}")
        lines.append("  Verify: discarded exception is intentional and documented.")

    # PyModule_AddObject -- conditional steal.
    mao = node.get("module_add_object", [])
    if mao:
        lines.append(f"### PyModule_AddObject() at lines: {mao}")
        lines.append("  STEALS ref ONLY on success. Failure path must Py_DECREF the object.")
        lines.append("  Check: is there a Py_DECREF(value) on the error path?")

    # GC slot flag.
    if node.get("is_gc_slot"):
        lines.append("### GC SLOT FUNCTION (tp_traverse / tp_clear / tp_dealloc):")
        lines.append("  Apply GC Protocol checklist items 10-12.")

    # Immortal guards.
    if node.get("has_immortal_guards"):
        lines.append("### IMMORTAL GUARDS PRESENT (_Py_IsImmortal):")
        lines.append("  Missing DECREF inside _Py_IsImmortal guard = intentional. Not a leak.")

    # Free-threaded divergence.
    if node.get("has_gil_disabled"):
        lines.append("### FREE-THREADED (#ifdef Py_GIL_DISABLED) DIVERGENCE DETECTED:")
        lines.append("  Analyse BOTH GIL and GIL-disabled paths independently.")
        lines.append("  GIL-disabled path must use PyMutex_Lock / Py_BEGIN_CRITICAL_SECTION.")

    return "\n".join(lines)


def audit_function(node, node_map, call_graph, api_key):
    """
    Hybrid triage:
      1. BFS structural gate: discard if no public path exists.
      2. Assemble deterministic structural context.
      3. Gemini reasons over code + context + ownership table.
      4. Escalate only Judge-confirmed true positives.
    """
    call_paths = call_graph.bfs_reverse(node["name"])
    if not call_paths:
        return []

    primary_path = call_paths[0]
    path_str = " -> ".join(f["name"] for f in primary_path)
    structural_ctx = _build_structural_context(node)

    context_sigs = [
        f"  - {callee}: {node_map[callee]['summary']}"
        for callee in node["calls"]
        if callee in node_map and node_map[callee].get("summary")
    ]
    context_str = ("### CALLEE SECURITY SIGNATURES:\n" + "\n".join(context_sigs)
                   if context_sigs else "### CALLEE SECURITY SIGNATURES: None available.")

    prompt = f"""You are a Senior CPython Security Auditor performing deterministically-constrained neuro-symbolic inference.

The static call graph has CONFIRMED this function is reachable from a public entry point:
  {path_str}

{structural_ctx}

{context_str}

## REFERENCE OWNERSHIP GROUND TRUTH
This table is definitive. Consult it before any reference-counting verdict:
{REF_OWNERSHIP_TABLE}

## Critical rules that catch the most common CPython bugs:

1. PyDict_GetItem -> BORROWED.
   Py_DECREF(result) is a double-free. Do not do it.

2. PyErr_GetRaisedException -> NEW_REF + clears exception state simultaneously.
   The returned object MUST be either:
   (a) Passed to _PyErr_SetRaisedException (which steals it), OR
   (b) Py_DECREF'd explicitly.
   On ALL code paths including error paths. Failure = exception leak.

3. PyTuple_SET_ITEM / PyList_SET_ITEM -> STEAL ARG2.
   After this call the item is owned by the container. Calling Py_DECREF(item)
   afterwards is a double-free.

4. PyModule_AddObject -> STEALS ARG2 ON SUCCESS ONLY.
   On failure: caller must still Py_DECREF(value). Very common ref leak pattern.
   Check the error path explicitly.

5. PyWeakref_GET_OBJECT -> BORROWED, can become Py_None at ANY GC point.
   Must: (a) check result != Py_None, (b) Py_INCREF before any call that
   might trigger GC. Failing to do (b) = potential UAF.

## SYNCHRONISATION RULES

### _PyEval_StopTheWorld / _PyEval_StartTheWorld
NOT a GIL release. TRUE stop-the-world -- ALL threads suspended.
Py_XNewRef / Py_INCREF / Py_DECREF inside this block = SAFE BY CONSTRUCTION.
DO NOT flag as GIL violation. STW-protected UAF candidates above are safe.

Historical false positive to avoid: _PyMonitoring_RegisterCallback was
incorrectly flagged because Py_XNewRef follows StopTheWorld. This is WRONG.
The world is stopped -- Py_XNewRef inside StopTheWorld is explicitly safe.

### Py_BEGIN_ALLOW_THREADS / PyEval_SaveThread
GIL IS released. Python object access = unsafe. Flag these.

### #ifdef Py_GIL_DISABLED branches
Analyse both paths independently. Free-threaded path needs PyMutex_Lock or
Py_BEGIN_CRITICAL_SECTION -- not the GIL.

## TARGET: `{node['name']}` in `{node['file']}`

## CODE:
```c
{node['code']}
```

## AUDIT CHECKLIST:

### Reference Counting
1. Ref Leaks: Missing Py_DECREF/Py_XDECREF on ANY error path?
   Trace every `goto error`, early `return NULL`, and exception-raising path.
2. Double Free: Does a callee steal a ref (STEALS_ARGn in table) that this
   code then also Py_DECREFs? (e.g. PyTuple_SET_ITEM + Py_DECREF = double-free)
3. Borrowed ref misuse: Is a BORROWED ref (see table) incorrectly Py_DECREF'd?
4. PyModule_AddObject: Is there a Py_DECREF(value) on the failure path?

### Memory Safety
5. tp_dealloc re-entrancy: After ANY Py_DECREF, does code access the same
   object or shared global state? If refcount hits zero, tp_dealloc runs
   arbitrary code that can re-enter this function. See TP_DEALLOC RISKS above.
6. UAF: Do UNPROTECTED pointer lifecycle candidates represent real UAF?
   (Ignore STW-protected ones -- they are safe by construction.)

### GIL / Threading
7. GIL violations: Python C-API calls inside Py_BEGIN_ALLOW_THREADS?
   (NOT inside StopTheWorld -- that is safe.)
8. Free-threaded divergence: If #ifdef Py_GIL_DISABLED exists, does the
   GIL-disabled path use proper locking (PyMutex_Lock / CRITICAL_SECTION)?

### Exception State
9. Exception masking: Does PyErr_Clear() silently discard an exception?
   Is a C-API function called without checking for an existing exception first?
10. _PyErr_GetRaisedException ownership: Returned NEW_REF must be restored
    via _PyErr_SetRaisedException on ALL paths. Missing = exception leak.

### GC Protocol (apply ONLY for tp_traverse / tp_clear / tp_dealloc functions)
11. tp_traverse vs tp_clear symmetry: Every Py_VISIT in tp_traverse must
    have a corresponding Py_CLEAR in tp_clear and vice versa.
12. tp_clear null-after-clear: Does tp_clear null each member after Py_CLEAR?
    Failing causes UAF if the object is visited again.
13. tp_dealloc untrack order: Must call PyObject_GC_UnTrack BEFORE decrementing
    any contained references. Doing it after is a UAF.

### Weak References
14. PyWeakref_GET_OBJECT: Result checked for Py_None? Strong ref acquired
    (Py_INCREF) before any call that could trigger GC?

### Integer Safety
15. Integer overflows in size calculations before malloc/realloc?
    Especially: `n * sizeof(T)`, `a + b + 1` used as allocation sizes.

## Structured Reasoning Protocol:
Step 1 -- Synchronisation audit: classify all primitives (StopTheWorld=safe /
          GIL-release=unsafe / critical section / none).
Step 2 -- Reference counting audit: trace each DECREF against ownership table.
Step 3 -- Structural candidates: confirm or refute each with code line evidence.
Step 4 -- Reachability: is the confirmed call path sufficient for exploitation?
Step 5 -- Sanitisation gap: does any guard prevent exploitation?
Step 6 -- Final verdict.

Return JSON ONLY. Empty findings array if the function is safe.
{{
  "verdict": "Likely True Positive | Likely False Positive | Uncertain",
  "reasoning": "<chain-of-thought covering all 6 steps>",
  "findings": [
    {{
      "vuln_type": "UAF | Ref Leak | GIL Violation | Double Free | Integer Overflow | Denial of Service | Exception Leak | Weak Ref Misuse | GC Protocol Violation | tp_dealloc Reentrancy",
      "severity": "High | Medium | Low",
      "line_offset": <int>,
      "description": "<concise explanation referencing specific lines>",
      "exploitation_scenario": "<concrete attacker steps>",
      "synchronisation_note": "<which primitive protects or fails to protect this>",
      "ownership_note": "<which ref-ownership rule is violated, if applicable>"
    }}
  ]
}}"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
        },
    }

    res = _retry_api(MODEL_JUDGE, payload, api_key)
    if not res:
        return []

    try:
        data = json.loads(clean_json(get_llm_text(res)))
        verdict = data.get("verdict", "Uncertain")
        findings = data.get("findings", [])

        if verdict != "Likely True Positive":
            return []

        for f in findings:
            f["function"]       = node["name"]
            f["file"]           = node["file"]
            f["call_path"]      = path_str
            f["verdict"]        = verdict
            f["reasoning"]      = data.get("reasoning", "")
            f["uaf_candidates"] = node["uaf_candidates"]

        return findings
    except Exception as e:
        print(f"  [!] JSON parse error for {node['name']}: {e}", file=sys.stderr)
        return []


def _load_existing_findings(path):
    """Load prior findings for --resume. A function with no findings is treated
    as not yet audited and will be re-run; cost is bounded and lets prompt
    changes take effect on resume."""
    if not os.path.exists(path):
        return [], set()
    try:
        with open(path) as f:
            data = json.load(f)
        findings = data.get("findings", [])
        seen = {(f.get("function"), f.get("file")) for f in findings if f.get("function")}
        return findings, seen
    except Exception:
        return [], set()


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="CPython C Source Auditor -- Neuro-Symbolic UAF/RefLeak Scanner"
    )
    parser.add_argument("paths", nargs="+", help="C files or directories to scan")
    parser.add_argument("-o", "--output", default="cpython_audit.json")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_BFS_DEPTH)
    parser.add_argument("--resume", action="store_true",
                        help="Skip functions already present in --output")
    args = parser.parse_args()

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: Set GEMINI_API_KEY environment variable.", file=sys.stderr)
        sys.exit(1)

    print("[*] Phase 1: Parsing C source with libclang...")

    c_files = []
    base_root = (os.path.dirname(os.path.abspath(args.paths[0]))
                 if os.path.isfile(args.paths[0]) else args.paths[0])

    for path in args.paths:
        if os.path.isfile(path) and path.endswith((".c", ".cc", ".cpp")):
            c_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith((".c", ".cc", ".cpp")):
                        c_files.append(os.path.join(root, f))

    include_flags = ClangExtractor._get_include_flags(base_root)
    print(f"    Found {len(c_files)} C files, {len(include_flags)} include paths.")

    all_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(ClangExtractor.extract, f, base_root, include_flags): f
            for f in c_files
        }
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            all_nodes.extend(future.result())
            if (i + 1) % 10 == 0:
                print(f"    Parsed {i + 1}/{len(c_files)} files...")

    # Diagnostic stats.
    uaf_total     = sum(1 for n in all_nodes if n["uaf_candidates"])
    stw_protected = sum(1 for n in all_nodes
                        for c in n["uaf_candidates"] if c.get("in_stw_region"))
    gil_exposed   = sum(1 for n in all_nodes
                        for c in n["uaf_candidates"] if c.get("in_gil_release"))
    gc_slots      = sum(1 for n in all_nodes if n["is_gc_slot"])
    weak_ref_fns  = sum(1 for n in all_nodes if n["weak_ref_lines"])
    tpd_risks     = sum(1 for n in all_nodes if n["tpdealloc_risks"])
    gil_dis_fns   = sum(1 for n in all_nodes if n["has_gil_disabled"])
    mao_fns       = sum(1 for n in all_nodes if n["module_add_object"])

    print(f"    Extracted {len(all_nodes)} functions.")
    print(f"    UAF candidates:              {uaf_total} functions")
    print(f"      STW-protected (safe):      {stw_protected}")
    print(f"      GIL-release-exposed:       {gil_exposed}")
    print(f"    GC slot functions:           {gc_slots}")
    print(f"    Weak reference usages:       {weak_ref_fns}")
    print(f"    tp_dealloc re-entrancy:      {tpd_risks}")
    print(f"    GIL-disabled branches:       {gil_dis_fns}")
    print(f"    PyModule_AddObject usages:   {mao_fns}")

    node_map = {n["name"]: n for n in all_nodes}

    print("[*] Phase 2: Building reverse call graph...")
    call_graph = CallGraph(all_nodes)
    print(f"    Call graph: {len(call_graph.graph)} unique callee entries.")

    print(f"[*] Phase 3: Semantic Scout (Model: {MODEL_SCOUT})...")
    batches = [all_nodes[i:i + BATCH_SIZE_SCOUT]
               for i in range(0, len(all_nodes), BATCH_SIZE_SCOUT)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_batch = {
            executor.submit(generate_security_signatures, b, api_key): b
            for b in batches
        }
        for i, future in enumerate(concurrent.futures.as_completed(future_to_batch)):
            for item in future.result():
                if item.get("name") in node_map:
                    node_map[item["name"]]["summary"] = item.get("signature", "")
            if (i + 1) % 5 == 0:
                print(f"    Summarised {i + 1}/{len(batches)} batches...")

    print(f"[*] Phase 4: Judge -- BFS-gated deep audit (Model: {MODEL_JUDGE})...")

    if args.resume:
        existing_findings, audited_keys = _load_existing_findings(args.output)
        if audited_keys:
            print(f"    Resuming: {len(audited_keys)} functions already audited.")
        nodes_to_audit = [n for n in all_nodes
                          if (n["name"], n["file"]) not in audited_keys]
        final_findings = list(existing_findings)
    else:
        nodes_to_audit = all_nodes
        final_findings = []
        with open(args.output, "w") as f:
            json.dump({"findings": []}, f, indent=4)

    write_lock = threading.Lock()
    findings_since_flush = [0]   # mutable sentinel for closure

    def flush():
        with open(args.output, "w") as f:
            json.dump({"findings": final_findings}, f, indent=4)
        findings_since_flush[0] = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {
            executor.submit(audit_function, n, node_map, call_graph, api_key): n
            for n in nodes_to_audit
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_node):
            res = future.result()
            if res:
                with write_lock:
                    final_findings.extend(res)
                    findings_since_flush[0] += len(res)
                    if findings_since_flush[0] >= SAVE_INTERVAL_FINDINGS:
                        flush()
                for finding in res:
                    sev = finding.get("severity", "").lower()
                    if sev == "high":
                        print(f"    [!] HIGH:   {finding['function']} -- {finding['vuln_type']}")
                    elif sev == "medium":
                        print(f"    [~] MEDIUM: {finding['function']} -- {finding['vuln_type']}")
            completed += 1
            if completed % 20 == 0:
                print(f"    Audited {completed}/{len(nodes_to_audit)} functions...")

    with write_lock:
        flush()

    print(f"\n[+] Complete. {len(final_findings)} verified findings saved to {args.output}")


if __name__ == "__main__":
    main()
