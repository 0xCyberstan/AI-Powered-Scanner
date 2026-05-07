# django_scan.py
#
# Two-stage AI-powered security scanner for Django codebases.
# Stage 1 (Scout): Gemini 2.5 Flash for broad probabilistic detection.
# Stage 2 (Judge): Gemini 2.5 Pro for deep reasoning on graph paths.
#
# USAGE:
#   1. SCAN:    python django_scan.py scan /path/to/project -o initial_results.json
#   2. TRIAGE:  python django_scan.py triage initial_results.json /path/to/project -o triaged.json
#   3. SHOW PROMPTS: add --show-prompts to either command
#
# pip install requests python-dotenv

import os
import sys
import json
import argparse
import time
import random
import hashlib
import requests
import ast
import concurrent.futures
from dotenv import load_dotenv

SCAN_MODEL = "gemini-2.5-flash"
TRIAGE_MODEL = "gemini-2.5-pro"

SCAN_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{SCAN_MODEL}:generateContent"
TRIAGE_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{TRIAGE_MODEL}:generateContent"

SUPPORTED_EXTENSIONS = ('.py',)
TRIAGE_BATCH_SIZE = 1
CALL_GRAPH_TIMEOUT = 60.0

# Keep request bursts under Gemini Tier 1 RPM (Flash: 2000 RPM).
SCAN_MAX_WORKERS = 16
TRIAGE_MAX_WORKERS = 2

# Functions whose parameter list contains any of these names are treated as
# public web entry points.
PUBLIC_ENTRY_PARAM_NAMES = {'request', 'self_request'}


def _retry_with_backoff(api_call, *args, **kwargs):
    """Retry an API call with exponential backoff."""
    max_retries = 5
    backoff_factor = 2
    for attempt in range(max_retries):
        try:
            return api_call(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            status_code = getattr(e.response, 'status_code', None)
            if status_code in [429, 500, 503] and attempt < max_retries - 1:
                wait_time = (backoff_factor ** attempt) + random.uniform(0, 1)
                print(f"API call failed with status {status_code}. Retrying in {wait_time:.2f}s...", file=sys.stderr)
                time.sleep(wait_time)
            else:
                print(f"API call failed permanently: {e}", file=sys.stderr)
                raise
    return None


def _find_call_paths_worker(call_graph, public_entries, function_name, max_depth, queue):
    """
    Worker for running reverse BFS in a separate process. Receives plain
    JSON-able data rather than the full analyzer instance to avoid pickling
    AST objects on spawn-default platforms (macOS/Windows).
    """
    try:
        public_entries_set = set(public_entries)
        paths = _bfs_reverse(call_graph, public_entries_set, function_name, max_depth)
        queue.put(paths)
    except Exception as e:
        import traceback
        try:
            queue.put(RuntimeError(f"{e}\n{traceback.format_exc()}"))
        except Exception:
            sys.stderr.write(f"Worker fatal: {e}\n{traceback.format_exc()}\n")
            sys.stderr.flush()


def _bfs_reverse(call_graph, public_entries, target_function_name, max_depth, max_paths=20):
    """
    Reverse BFS from target sink toward public entry points.

    Returns up to max_paths paths terminating at a public entry, with cycle
    detection and depth bounding. The max_paths cap is essential on heavily
    shared sinks (e.g. SQLCompiler.as_sql) where path enumeration would
    otherwise be combinatorial. The Judge prompt only consumes the first 5
    paths after sorting, so generating more is wasted work.

    Uses a global visited set: once enqueued, a node is not enqueued again
    from a different path. Trades alternative-path diversity for tractability.
    """
    paths = []
    queue = [[{'name': target_function_name, 'file': 'UNKNOWN', 'class': None}]]
    globally_visited = {target_function_name}

    while queue and len(paths) < max_paths:
        current_path = queue.pop(0)
        last_func = current_path[0]
        last_func_name = last_func['name']

        # Public entry reached.
        if last_func_name in public_entries or _strip_qualifier(last_func_name) in public_entries:
            paths.append(current_path)
            continue

        # Depth bound: prune paths that haven't reached a public entry.
        if len(current_path) > max_depth:
            continue

        callers = call_graph.get(last_func_name, [])
        if not callers:
            continue

        for caller in callers:
            caller_name = caller['name']
            if caller_name in globally_visited:
                continue
            globally_visited.add(caller_name)
            queue.append([caller] + current_path)

    return paths


def _strip_qualifier(name):
    """Return the unqualified name from 'ClassName.method', or name unchanged."""
    if '.' in name:
        return name.rsplit('.', 1)[1]
    return name


def _hash_directory_sources(directory):
    """
    Deterministic hash of all .py paths and their sizes/mtimes. Used to
    invalidate stale call graph caches when sources change between runs.
    """
    h = hashlib.sha256()
    entries = []
    for root, _, files in os.walk(directory):
        for file_name in sorted(files):
            if file_name.endswith(SUPPORTED_EXTENSIONS):
                file_path = os.path.join(root, file_name)
                try:
                    st = os.stat(file_path)
                    entries.append((file_path, st.st_size, int(st.st_mtime)))
                except OSError:
                    continue
    for path, size, mtime in sorted(entries):
        h.update(f"{path}:{size}:{mtime}".encode('utf-8'))
    return h.hexdigest()


def save_cache(analyzer, cache_path):
    """Save call graph, public entries, and a source fingerprint as JSON."""
    cache_data = {
        'directory': analyzer.directory,
        'source_hash': _hash_directory_sources(analyzer.directory),
        'call_graph': analyzer.call_graph,
        'public_entries': sorted(analyzer.public_entries),
    }
    with open(cache_path, 'w') as f:
        json.dump(cache_data, f)
    print(f"--- Call graph saved to {cache_path} ---")


def load_cache(cache_path, directory):
    """
    Load call graph from JSON and rebuild AST cache from source. No pickle:
    eliminates arbitrary-code-execution risk. Raises ValueError if the
    cached source fingerprint doesn't match the current directory state.
    """
    with open(cache_path, 'r') as f:
        cache_data = json.load(f)

    if os.path.abspath(cache_data['directory']) != os.path.abspath(directory):
        raise ValueError("Cache directory mismatch.")

    current_hash = _hash_directory_sources(directory)
    cached_hash = cache_data.get('source_hash')
    if cached_hash != current_hash:
        raise ValueError(
            "Source files have changed since cache was written. "
            "Call graph would be misaligned with current source code."
        )

    analyzer = CodebaseAnalyzer.__new__(CodebaseAnalyzer)
    analyzer.directory = cache_data['directory']
    analyzer.call_graph = cache_data['call_graph']
    analyzer.public_entries = set(cache_data.get('public_entries', []))
    analyzer.ast_cache = {}
    analyzer.code_cache = {}

    for root, _, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(SUPPORTED_EXTENSIONS):
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        analyzer.code_cache[file_path] = content
                        analyzer.ast_cache[file_path] = ast.parse(
                            content, filename=file_path
                        )
                except Exception:
                    pass

    print(f"--- Call graph loaded from JSON, ASTs rebuilt from source ---")
    return analyzer


def call_gemini_for_scan(prompt, api_key):
    """
    Call Gemini Flash with a structured JSON schema. Temperature 0.0 for
    reproducibility. Distinguishes "API returned zero findings" (legitimate)
    from "request failed to parse" (suppressed bug).
    """
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "findings": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "line":           {"type": "INTEGER"},
                                "vuln_type":      {"type": "STRING"},
                                "description":    {"type": "STRING"},
                                "severity":       {"type": "STRING"},
                                "recommendation": {"type": "STRING"}
                            },
                            "required": ["line", "vuln_type", "description", "severity", "recommendation"]
                        }
                    }
                },
                "required": ["findings"]
            }
        }
    }
    def api_request():
        response = requests.post(f"{SCAN_API_URL}?key={api_key}", headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        return response.json()
    api_response = _retry_with_backoff(api_request)
    if not api_response or 'candidates' not in api_response:
        return {"findings": []}
    try:
        response_text = api_response['candidates'][0]['content']['parts'][0]['text']
        return json.loads(response_text)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"WARNING: Gemini scan response unparseable, treating as zero findings: {e}", file=sys.stderr)
        return {"findings": [], "_parse_error": str(e)}


def extract_nodes_from_file(file_path):
    """
    Extract FunctionDef/AsyncFunctionDef nodes for per-function analysis.
    ClassDef nodes are intentionally excluded so methods aren't double-analysed
    (once standalone, once as part of their enclosing class).
    """
    nodes = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code_content = f.read()
            tree = ast.parse(code_content, filename=file_path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                source_segment = ast.get_source_segment(code_content, node)
                if source_segment:
                    # Use node.lineno (the def line), not the first decorator:
                    # ast.get_source_segment() returns text starting at lineno,
                    # so reported offsets are relative to that.
                    nodes.append({
                        "name": node.name,
                        "type": type(node).__name__,
                        "code": source_segment,
                        "start_line": node.lineno
                    })
    except Exception as e:
        print(f"Error parsing {file_path} with ast: {e}", file=sys.stderr)
    return nodes

def analyze_node(node_data, file_name, api_key, args):
    """Send a single code node to Gemini Flash for scanning."""
    safe_code = json.dumps(node_data['code'])

    prompt = f"""You are a Senior Security Researcher specialising in database internals and ORM security. Your task is to identify logic-based vulnerabilities arising from implicit trust violations in framework internals -- not generic syntactic patterns.

**Search Space (restrict analysis to these three categories only):**
1. **Unsafe Identifier Handling**: Object attributes used as SQL identifiers or operators without validation (e.g., connector strings, alias names, operator flags interpolated into raw SQL).
2. **Subversion of ORM Abstractions**: Patterns where a public-facing API (e.g., `Q()`, `QuerySet.filter()`, `.annotate()`) accepts arguments that flow into internal query compilation logic without sanitisation or whitelisting.
3. **Attribute Injection via Dictionary Unpacking**: Any pattern where `**kwargs` or `**user_dict` is passed to a constructor or method that sets internal attributes later used in SQL generation.

**Negative Constraints (do NOT flag these -- they are false positives):**
- Explicit raw SQL APIs such as `.raw()`, `.extra()`, `RawSQL()`, or `execute()` where the developer intentionally handles SQL. These are unsafe by design and documented as such.
- Standard parameterised queries where user input is passed as a parameter tuple (e.g., `cursor.execute(sql, [param])`) -- the database driver handles escaping.
- Internal framework methods that only receive values from other internal, trusted sources with no public API exposure.

**Analogical Grounding (what a True Positive looks like):**
The historical WhereNode vulnerability class is the canonical example: the framework's SQL compiler interpolated `self.connector` directly into a WHERE clause string. The connector value was settable via the public `Q()` constructor through dictionary unpacking. No taint rule was violated -- the input was passed to a syntactically valid ORM method. The vulnerability existed entirely in the semantic gap: the framework implicitly trusted that `connector` would only ever hold an internal constant (`AND`/`OR`), but a developer could pass an arbitrary string via `Q(**user_dict)`. A True Positive requires this combination: (a) an attribute used unsafely in SQL generation, AND (b) a plausible mechanism by which a public API caller could control that attribute's value.

**Reasoning Protocol (Chain-of-Thought -- work through these steps before classifying):**
1. Identify any SQL string construction in this function. What attributes or variables are interpolated?
2. For each interpolated value: is it hardcoded, derived from a validated internal source, or potentially controllable by a caller?
3. Is there a public API pathway (constructor argument, `**kwargs`, method parameter) through which a developer or end-user could influence this value?
4. Is there a whitelist, regex check, or immutability constraint that prevents arbitrary values?
5. Based on steps 1-4, classify as: High (clear logic flaw with no guardrail), Medium (plausible but requires unusual calling pattern), or Low (internal only, no realistic external pathway).

**Exclusion from output:** Do not report stylistic issues, missing type hints, performance concerns, or any finding that does not map to the three categories above.

Framework File: {file_name}
Node: {node_data['name']} (Type: {node_data['type']})
Code:
{safe_code}"""

    if args.show_prompts:
        print("\n" + "="*80)
        print("--- SCAN PROMPT (Flash) ---")
        print(f"File: {file_name}, Node: {node_data['name']}")
        print("="*80)
        print(prompt)
        print("="*80 + "\n")
        return []

    api_response = call_gemini_for_scan(prompt, api_key)
    findings = api_response.get('findings', [])
    for finding in findings:
        # Snippet line 1 == start_line in the source file, so offset is start_line - 1.
        finding['line'] = finding['line'] + node_data['start_line'] - 1
        finding['file'] = file_name
        finding['function'] = node_data['name']
    return findings

def scan_file(file_path, api_key, args):
    """Extract nodes from a file and analyze each one."""
    print(f"Scanning file: {file_path}")
    nodes = extract_nodes_from_file(file_path)
    if not nodes:
        return []
    all_findings = []
    # When the scan target is a single file, os.path.relpath returns '.', which
    # is unusable for source lookup during triage. Fall back to basename so the
    # endswith match in CodebaseAnalyzer.get_node_source can resolve it.
    if os.path.isfile(args.directory):
        relative_path = os.path.basename(file_path)
    else:
        relative_path = os.path.relpath(file_path, args.directory)
    for node in nodes:
        findings = analyze_node(node, relative_path, api_key, args)
        if findings:
            print(f"  - Found {len(findings)} potential issue(s) in node '{node['name']}'.")
            all_findings.extend(findings)
    return all_findings

def run_scan(args):
    """Main function for the 'scan' subcommand."""
    print(f"--- Starting Django Code Scan (Stage 1 - Flash) in: {args.directory} ---")
    if args.show_prompts:
        print("--- SHOW PROMPTS MODE: Prompts will be displayed instead of calling the API. ---")

    all_results = []
    if os.path.isfile(args.directory):
        files_to_scan = [args.directory]
    else:
        files_to_scan = [
            os.path.join(root, file_name)
            for root, _, files in os.walk(args.directory)
            for file_name in files
            if file_name.endswith(SUPPORTED_EXTENSIONS)
        ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_MAX_WORKERS) as executor:
        future_to_file = {
            executor.submit(scan_file, file_path, args.api_key, args): file_path
            for file_path in files_to_scan
        }
        for future in concurrent.futures.as_completed(future_to_file):
            try:
                result = future.result()
                if result:
                    all_results.extend(result)
            except Exception as exc:
                print(f"Error processing file '{future_to_file[future]}': {exc}", file=sys.stderr)

    if args.show_prompts:
        print("\n--- Prompt display complete. No results were generated. ---")
        return

    if not all_results:
        print("\n--- Scan Complete: No security vulnerabilities were detected. ---")
    else:
        print("\n--- Scan Complete: Summary of Findings ---")
        all_results.sort(key=lambda x: (x.get('file', ''), x.get('line', 0)))
        for finding in all_results:
            print(
                f"\n[{finding.get('severity', 'Unknown')}] {finding.get('vuln_type', 'N/A')} "
                f"in {finding.get('file', 'N/A')}:{finding.get('line', 'N/A')} "
                f"(Function: {finding.get('function', 'N/A')})"
            )
            print(f"  Description: {finding.get('description', 'No description provided.')}")

    with open(args.output, 'w') as f:
        json.dump({"findings": all_results}, f, indent=4)
    print(f"\nFull initial scan results have been saved to {args.output}")


class CodebaseAnalyzer:
    """
    Parses an entire Python codebase once and caches ASTs and a call graph.
    Also computes the public entry-point set: a function is public if its
    parameter list contains a name in PUBLIC_ENTRY_PARAM_NAMES.
    """
    def __init__(self, directory):
        print("Building codebase AST cache and call graph... (This may take a moment)")
        self.directory = directory
        self.ast_cache = {}
        self.code_cache = {}
        self.call_graph = {}  # { 'callee_name': [ { 'name': 'caller_name', 'file': 'caller_file.py' }, ... ] }
        self.public_entries = set()  # names of functions accepting a `request` parameter

        # First pass: cache files and ASTs.
        for root, _, files in os.walk(directory):
            for file_name in files:
                if file_name.endswith(SUPPORTED_EXTENSIONS):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            self.code_cache[file_path] = content
                            self.ast_cache[file_path] = ast.parse(content, filename=file_path)
                    except Exception as e:
                        print(f"Warning: Could not parse {file_path}: {e}", file=sys.stderr)

        # Second pass: build call graph and identify public entries.
        for file_path, tree in self.ast_cache.items():
            self._index_tree(tree, file_path)

        print(f"--- Call graph built: {len(self.call_graph)} callees, "
              f"{len(self.public_entries)} public entry points identified ---")

    def _is_public_entry(self, func_node):
        """True if func_node accepts a parameter whose name is in PUBLIC_ENTRY_PARAM_NAMES."""
        try:
            args = func_node.args
            all_args = list(args.args) + list(getattr(args, 'posonlyargs', [])) + list(args.kwonlyargs)
            for a in all_args:
                if a.arg in PUBLIC_ENTRY_PARAM_NAMES:
                    return True
        except AttributeError:
            pass
        return False

    def _record_public_entry(self, func_node, class_name=None):
        """Add a function to public_entries under both qualified and unqualified names."""
        if self._is_public_entry(func_node):
            self.public_entries.add(func_node.name)
            if class_name:
                self.public_entries.add(f"{class_name}.{func_node.name}")

    def _index_tree(self, tree, file_path):
        """Walk an AST once, populating call_graph and public_entries."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                current_class = node.name
                for child in ast.walk(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._record_public_entry(child, current_class)
                        qualified_name = f"{current_class}.{child.name}"
                        for subnode in ast.walk(child):
                            if isinstance(subnode, ast.Call):
                                callee_name = None
                                callee_class = None
                                if isinstance(subnode.func, ast.Name):
                                    callee_name = subnode.func.id
                                elif isinstance(subnode.func, ast.Attribute):
                                    callee_name = subnode.func.attr
                                    if (isinstance(subnode.func.value, ast.Name) and
                                            subnode.func.value.id == 'self'):
                                        callee_class = current_class

                                if callee_name:
                                    caller_info = {
                                        'name': qualified_name,
                                        'unqualified': child.name,
                                        'file': os.path.basename(file_path),
                                        'class': current_class
                                    }
                                    if callee_class:
                                        qualified_callee = f"{callee_class}.{callee_name}"
                                        if qualified_callee not in self.call_graph:
                                            self.call_graph[qualified_callee] = []
                                        if caller_info not in self.call_graph[qualified_callee]:
                                            self.call_graph[qualified_callee].append(caller_info)
                                    if callee_name not in self.call_graph:
                                        self.call_graph[callee_name] = []
                                    if caller_info not in self.call_graph[callee_name]:
                                        self.call_graph[callee_name].append(caller_info)

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._record_public_entry(node)
                current_function = node.name
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Call):
                        callee_name = None
                        if isinstance(subnode.func, ast.Name):
                            callee_name = subnode.func.id
                        elif isinstance(subnode.func, ast.Attribute):
                            callee_name = subnode.func.attr
                        if callee_name:
                            caller_info = {
                                'name': current_function,
                                'unqualified': current_function,
                                'file': os.path.basename(file_path),
                                'class': None
                            }
                            if callee_name not in self.call_graph:
                                self.call_graph[callee_name] = []
                            if caller_info not in self.call_graph[callee_name]:
                                self.call_graph[callee_name].append(caller_info)

    def get_node_source(self, file_name, node_name):
        """
        Resolve (file_name, node_name) to function source text.

        Filename ambiguity is the main hazard: short names like 'query.py'
        match multiple files in Django's tree. We consider all endswith
        candidates (longest suffix first) and return source from the first
        one that actually contains a definition for node_name.
        """
        # Exact path first.
        expected_full_path = os.path.normpath(os.path.join(self.directory, file_name))
        candidates = []
        if expected_full_path in self.ast_cache:
            candidates.append(expected_full_path)

        # Then fuzzy endswith matches, longest suffix first so 'sql/query.py'
        # beats 'query.py' when both are present.
        suffix_matches = [
            p for p in self.ast_cache
            if p.endswith(file_name) or p.endswith(os.sep + file_name)
        ]
        suffix_matches.sort(key=len, reverse=True)
        for p in suffix_matches:
            if p not in candidates:
                candidates.append(p)

        for full_path in candidates:
            tree = self.ast_cache[full_path]
            code_content = self.code_cache[full_path]
            for node in ast.walk(tree):
                if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        and node.name == node_name):
                    return ast.get_source_segment(code_content, node)
        return None

    def find_call_paths(self, target_function_name, max_depth=8):
        """Reverse BFS from target sink toward public entry points."""
        return _bfs_reverse(self.call_graph, self.public_entries, target_function_name, max_depth)

    def analyze_data_flow(self, path):
        """
        Analyse a call path for taint from web input vectors. Checks the entry
        point for assignments from request.GET / request.POST / request.FILES /
        request.COOKIES.
        """
        if not path:
            return "Could not analyze data flow: path is empty."

        web_taint_sources = {'request': ['GET', 'POST', 'data', 'query_params', 'FILES', 'COOKIES', 'body']}
        taint_summary = []
        entry_func_info = path[0]
        entry_func_name = entry_func_info['name']
        entry_code = self.get_node_source(entry_func_info.get('file'), entry_func_name)

        if entry_code:
            try:
                entry_tree = ast.parse(entry_code)
                for node in ast.walk(entry_tree):
                    if isinstance(node, ast.Assign):
                        value_node = node.value
                        source_description = None
                        if (isinstance(value_node, ast.Subscript) and
                                isinstance(value_node.value, ast.Attribute) and
                                isinstance(value_node.value.value, ast.Name) and
                                value_node.value.value.id in web_taint_sources):
                            source_description = f"request.{value_node.value.attr}"
                        if source_description:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    taint_summary.append(
                                        f"- Web Input: In '{entry_func_name}', variable '{target.id}' "
                                        f"is tainted by web input from '{source_description}'."
                                    )
            except Exception:
                pass

        for i, func_info in enumerate(path[:-1]):
            func_name = func_info['name']
            if not func_name.startswith('_'):
                next_func_name = path[i + 1]['name']
                # Compare against the unqualified name so 'ClassName.method'
                # in the path matches a 'method' call site.
                next_unqualified = _strip_qualifier(next_func_name)
                caller_code = self.get_node_source(func_info.get('file'), func_name)
                if caller_code:
                    try:
                        caller_tree = ast.parse(caller_code)
                        for node in ast.walk(caller_tree):
                            if isinstance(node, ast.Call):
                                called_name = (
                                    node.func.attr if isinstance(node.func, ast.Attribute)
                                    else (node.func.id if isinstance(node.func, ast.Name) else None)
                                )
                                if called_name == next_unqualified:
                                    taint_summary.append(
                                        f"- API Input: Public function '{func_name}' passes "
                                        f"developer-controlled arguments to '{next_func_name}'."
                                    )
                                    break
                    except Exception:
                        continue

        if not taint_summary:
            return "No obvious web or public API data sources were identified in the path."

        return "\n".join(taint_summary)


def call_gemini_for_triage(prompt, api_key):
    """
    Call Gemini Pro for a single triage finding. Distinguishes parse failures
    from API success-with-no-content so bugs surface in logs.
    """
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.0,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "verdict": {
                        "type": "STRING",
                        "enum": ["Likely True Positive", "Likely False Positive", "Uncertain"]
                    },
                    "reasoning":             {"type": "STRING"},
                    "exploitation_scenario": {"type": "STRING"}
                },
                "required": ["verdict", "reasoning", "exploitation_scenario"]
            }
        }
    }
    def api_request():
        response = requests.post(f"{TRIAGE_API_URL}?key={api_key}", headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        return response.json()
    api_response = _retry_with_backoff(api_request)
    if not api_response:
        return None
    if 'candidates' not in api_response:
        # Prompt-level safety blocks or quota issues return no candidates but
        # often include promptFeedback explaining why. Surface it.
        feedback = api_response.get('promptFeedback', {})
        if feedback:
            print(
                f"WARNING: Gemini returned no candidates. "
                f"promptFeedback: {json.dumps(feedback)}",
                file=sys.stderr
            )
        else:
            print(f"WARNING: Gemini returned no candidates and no promptFeedback. "
                  f"Response keys: {list(api_response.keys())}", file=sys.stderr)
        return None
    try:
        candidate = api_response['candidates'][0]
        finish_reason = candidate.get('finishReason', 'UNKNOWN')
        # Detect safety-blocked or empty completions.
        if finish_reason in ('SAFETY', 'BLOCKED', 'PROHIBITED_CONTENT', 'RECITATION'):
            safety_ratings = candidate.get('safetyRatings', [])
            print(
                f"WARNING: Gemini blocked the response. finishReason={finish_reason}, "
                f"safetyRatings={json.dumps(safety_ratings)}",
                file=sys.stderr
            )
            return None
        response_text = candidate['content']['parts'][0]['text']
        return json.loads(response_text)
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        try:
            finish_reason = api_response['candidates'][0].get('finishReason', 'UNKNOWN')
            print(
                f"WARNING: Gemini triage response unparseable (finishReason={finish_reason}): {e}",
                file=sys.stderr
            )
        except Exception:
            print(f"WARNING: Gemini triage response unparseable: {e}", file=sys.stderr)
        return None


def triage_single_finding(finding, analyzer, api_key, args):
    """Gather context for a single finding and ask the Judge to verify it."""
    function_code = analyzer.get_node_source(finding['file'], finding['function'])
    if not function_code:
        print(
            f"ERROR: Could not find code for '{finding['function']}' in '{finding['file']}'. Skipping.",
            file=sys.stderr
        )
        return None

    safe_code = json.dumps(function_code)
    context_str = "No call graph analysis performed yet.\n"
    call_paths = None

    # Time-limited call graph analysis via a worker thread.
    #
    # Previously used multiprocessing.Process, but spawning a child process
    # from inside a ThreadPoolExecutor is unreliable across platforms (macOS
    # and Windows default to 'spawn' which re-imports the module; Linux 'fork'
    # after threads is documented as unsafe). The BFS already has cycle
    # detection and depth bounding, so it can't loop forever -- the timeout
    # is a belt-and-braces guard and a thread is sufficient.
    import threading

    result_container = {'paths': None, 'error': None}

    def _bfs_thread():
        try:
            result_container['paths'] = _bfs_reverse(
                analyzer.call_graph,
                analyzer.public_entries,
                finding['function'],
                8
            )
        except Exception as e:
            import traceback
            result_container['error'] = f"{e}\n{traceback.format_exc()}"

    bfs_thread = threading.Thread(target=_bfs_thread, daemon=True)
    bfs_thread.start()
    bfs_thread.join(timeout=CALL_GRAPH_TIMEOUT)

    if bfs_thread.is_alive():
        # Daemon thread can't be killed but won't block process exit.
        print(
            f"  -> WARNING: Call graph analysis for '{finding['function']}' timed out "
            f"after {CALL_GRAPH_TIMEOUT}s. Triage will use local context only.",
            file=sys.stderr
        )
        context_str = (
            f"Call graph analysis timed out after {CALL_GRAPH_TIMEOUT} seconds. "
            f"Triage is based on local function context only."
        )
    elif result_container['error']:
        print(
            f"  -> ERROR: BFS failed for '{finding['function']}': {result_container['error']}",
            file=sys.stderr
        )
        context_str = (
            f"Call graph analysis failed: {result_container['error']}. "
            f"Triage is based on local function context only."
        )
    else:
        call_paths = result_container['paths']

    if call_paths is not None:
        if call_paths:
            formatted_paths = []
            call_paths.sort(key=len)
            for i, path in enumerate(call_paths[:5]):
                path_str = f"Path {i + 1}:\n"
                display_path = list(reversed(path))
                for func_info in display_path:
                    path_str += f"  -> {func_info['name']}() in {func_info.get('file', 'UNKNOWN')}\n"
                formatted_paths.append(path_str)

            context_str = (
                "The following call paths terminate at a public entry point "
                "(member of S_public, i.e. function accepting a `request` parameter):\n"
                + "\n".join(formatted_paths)
            )
            context_str += "\n--- Data Flow Analysis (for Path 1) ---\n"
            data_flow_info = analyzer.analyze_data_flow(list(reversed(call_paths[0])))
            context_str += data_flow_info
            context_str += "\n"
        else:
            context_str = (
                "No call paths to a public entry point were found within max_depth. "
                "The sink is either unreachable from S_public or routed through "
                "polymorphic dispatch the name-based call graph cannot resolve.\n"
            )

    prompt = f"""You are a Senior Security Research Engineer specializing in ORM (Object-Relational Mapping) internals and Framework Security.

Your objective is to audit the provided code for **Logic-Based SQL Injection** vulnerabilities that arise from "State Contamination."

**The Core Security Principle:**
Frameworks often assume that internal object attributes (e.g., configuration flags, operator strings, alias definitions) are "Trusted Constants" defined exclusively by the developer. A critical vulnerability exists if an attacker can manipulate these internal attributes via a public API, causing the framework to unknowingly interpolate malicious data into a SQL string or sensitive query compiler.

**Analysis Directives:**

1.  **Locate the Sink:** Identify where SQL or query strings are constructed. Look for unsafe interpolation patterns (e.g., `sql = "... %s ..." % self.attribute`, f-strings, or `.format()`) that use object attributes rather than immediate function arguments.

2.  **Trace the Attribute:** Analyze the origin of the interpolated attribute. Is it hardcoded? Is it derived from safe internal logic? Or is it exposed?

3.  **Analyze Trust Boundaries (The Critical Step):**
    * Examine the class constructor (`__init__`) and public setup methods.
    * Check for **Mass Assignment** or **Dynamic Dispatch** patterns (e.g., `setattr`, loop-based assignment, or unrestricted `**kwargs` unpacking) that allow external inputs to bind to internal attributes.
    * *Heuristic:* If a public API allows a user to define a dictionary that flows into a constructor, and that constructor sets attributes used in SQL generation without whitelisting, this is a Critical Logic Flaw.

**Exclusion Criteria (False Positives):**
* Do NOT flag explicit raw SQL APIs (e.g., `.raw()`, `.extra()`) where the developer intentionally passes SQL.
* Do NOT flag standard parameterization where the database driver handles escaping.

**Structured Reasoning Protocol (five steps -- address each explicitly):**

1.  **Mechanism Analysis**: How does data flow from the `Input Vector` (Public API) to the `Sink` (SQL Generation)?
2.  **Immutability Check**: Can the attribute used at the sink be modified by the caller? (e.g., does the constructor blindly accept arguments?)
3.  **Sanitization Gap**: Is there a validation step (e.g., regex, whitelist) between the input and the sink?
4.  **Verdict Synthesis**:
    * **Likely True Positive**: The code allows "Object State Contamination" leading to SQLi.
    * **Likely False Positive**: The attribute is immutable, whitelisted, or the API is explicitly unsafe by design.
    * **Uncertain**: The call graph timed out, the path is incomplete, or reasoning identifies ambiguous state. Flag for manual review.
5.  **Exploitation Scenario**: Describe the concrete steps an attacker would take to exploit this finding, or explain why exploitation is not feasible.

**Finding Details:**
- **File:** {finding['file']}
- **Function:** {finding['function']}
- **Line:** {finding['line']}

**Code Context:**
{safe_code}

**Execution Context (Call Graph & Taint):**
{context_str}
"""

    if args.show_prompts:
        print("\n" + "="*80)
        print("--- TRIAGE PROMPT (Pro) ---")
        print(f"File: {finding['file']}, Function: {finding['function']}")
        print("="*80)
        print(prompt)
        print("="*80 + "\n")
        return {"verdict": "PROMPT_SHOWN", "reasoning": "Displayed prompt instead of calling API.", "exploitation_scenario": "N/A"}

    return call_gemini_for_triage(prompt, api_key)


def run_triage(args):
    """Main function for the 'triage' subcommand with stateful resume logic."""
    print(f"--- Starting Triage Session (Stage 2 - Pro) for: {args.codebase_dir} ---")
    all_findings = []

    if os.path.exists(args.output):
        print(f"--- Resuming previous triage session from {args.output} ---")
        try:
            with open(args.output, 'r') as f:
                all_findings = json.load(f).get('findings', [])
        except json.JSONDecodeError as e:
            print(
                f"Error: Output file '{args.output}' is corrupted. "
                f"Please repair or delete it to continue. Error: {e}", file=sys.stderr
            )
            return
    else:
        print(f"--- Starting new triage session from {args.results_file} ---")
        try:
            with open(args.results_file, 'r') as f:
                all_findings = json.load(f).get('findings', [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error: Could not load initial results file '{args.results_file}': {e}", file=sys.stderr)
            return

    if not all_findings:
        print("No findings to triage. Exiting.")
        return

    manual_findings_indices = [i for i, f in enumerate(all_findings) if 'triage_analysis' not in f]
    triaged_count = len(all_findings) - len(manual_findings_indices)

    if args.show_prompts:
        print("--- SHOW PROMPTS MODE: Prompts will be displayed instead of calling the API. ---")
    else:
        if triaged_count > 0:
            print(f"--- {triaged_count} findings already triaged. ---")

    cache_path = os.path.join(os.path.dirname(args.output) or '.', 'django_framework_scan.cache')
    analyzer = None
    cache_valid = False

    if os.path.exists(cache_path):
        try:
            analyzer = load_cache(cache_path, args.codebase_dir)
            if manual_findings_indices:
                test_finding = all_findings[manual_findings_indices[0]]
                if analyzer.get_node_source(test_finding['file'], test_finding['function']):
                    cache_valid = True
                    print(f"--- Loaded and verified cached codebase analysis from {cache_path} ---")
                else:
                    print("--- Cached analysis is stale (cannot find files). Rebuilding... ---")
            else:
                cache_valid = True
        except ValueError as e:
            print(f"--- Cache invalid: {e}. Rebuilding... ---")
            analyzer = None
        except Exception as e:
            print(f"--- Warning: Cache load failed ({e}). Rebuilding... ---")
            analyzer = None

    if not cache_valid:
        if os.path.exists(cache_path):
            try:
                os.remove(cache_path)
                print(f"--- Deleted stale cache file: {cache_path} ---")
            except OSError as e:
                print(f"--- Warning: Could not delete stale cache: {e} ---", file=sys.stderr)

        analyzer = CodebaseAnalyzer(args.codebase_dir)
        try:
            save_cache(analyzer, cache_path)
        except Exception as e:
            print(f"Warning: Could not save analyzer cache: {e}", file=sys.stderr)

    findings_to_process = [(i, all_findings[i]) for i in manual_findings_indices]

    if not findings_to_process:
        print("--- All findings have already been triaged. Exiting. ---")
        return

    if args.show_prompts:
        print(f"--- Displaying prompts for {len(findings_to_process)} untriaged findings ---")
        for (abs_index, finding) in findings_to_process:
            print(f"\n--- Preparing prompt for {finding['function']} in {finding['file']} ---")
            triage_single_finding(finding, analyzer, args.api_key, args)
            time.sleep(1)
        print("\n--- Prompt display complete. No results were saved. ---")
        return

    print(f"--- Starting parallel triage for {len(findings_to_process)} untriaged findings... ---")

    completed_count = 0
    total_to_process = len(findings_to_process)

    with concurrent.futures.ThreadPoolExecutor(max_workers=TRIAGE_MAX_WORKERS) as executor:
        future_to_index = {
            executor.submit(triage_single_finding, finding, analyzer, args.api_key, args): index
            for (index, finding) in findings_to_process
        }

        for future in concurrent.futures.as_completed(future_to_index):
            abs_index = future_to_index[future]
            finding_info = f"{all_findings[abs_index]['function']} in {all_findings[abs_index]['file']}"
            analysis_result = None
            try:
                analysis_result = future.result()
                if analysis_result:
                    print(f"  -> Triage complete for: {finding_info} (Verdict: {analysis_result.get('verdict', 'N/A')})")
                else:
                    analysis_result = {
                        "verdict": "Uncertain",
                        "reasoning": "API call or JSON parsing failed during triage.",
                        "exploitation_scenario": "N/A"
                    }
                    print(f"  -> Triage FAILED for: {finding_info} (API/JSON error)")
            except Exception as exc:
                print(f"  -> Triage FAILED for: {finding_info} (Exception: {exc})", file=sys.stderr)
                analysis_result = {
                    "verdict": "Uncertain",
                    "reasoning": f"Triage function failed with exception: {exc}",
                    "exploitation_scenario": "N/A"
                }

            if analysis_result:
                all_findings[abs_index]['triage_analysis'] = analysis_result
                try:
                    with open(args.output, 'w') as f:
                        json.dump({"findings": all_findings}, f, indent=4)
                except Exception as e:
                    print(f"  -> CRITICAL: Failed to save progress to {args.output}: {e}", file=sys.stderr)

                time.sleep(1)

            completed_count += 1
            print(f"  (Progress: {completed_count}/{total_to_process})")

    print(f"\n--- Triage Session Complete ---")
    print(f"A total of {len(all_findings)} findings have been processed and saved to {args.output}")


def main():
    """Parse arguments and run the appropriate stage."""
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="A stateful, two-stage, AI-powered vulnerability scanner for Django codebases."
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Perform the initial broad scan (Stage 1 - Flash).")
    scan_parser.add_argument("directory", help="The directory containing the source code to scan.")
    scan_parser.add_argument("-o", "--output", default="scan_results.json", help="Output file for scan results.")
    scan_parser.add_argument(
        "--show-prompts", action="store_true",
        help="Display the generated prompts instead of sending them to the API."
    )

    triage_parser = subparsers.add_parser(
        "triage",
        help="Perform deep analysis (Stage 2 - Pro). Resumes if output file exists."
    )
    triage_parser.add_argument("results_file", help="The JSON file from the 'scan' stage (used for first run).")
    triage_parser.add_argument("codebase_dir", help="The root directory of the codebase that was scanned.")
    triage_parser.add_argument(
        "-o", "--output", default="triaged_results.json",
        help="Output file for triaged results. This file is also used to resume progress."
    )
    triage_parser.add_argument(
        "--show-prompts", action="store_true",
        help="Display the generated prompts instead of sending them to the API."
    )

    args = parser.parse_args()
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("ERROR: GEMINI_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
    args.api_key = api_key

    if args.command == "scan":
        run_scan(args)
    elif args.command == "triage":
        run_triage(args)


if __name__ == "__main__":
    main()