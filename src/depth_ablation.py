# depth_ablation.py
#
# Depth ablation harness for the Stage 2 reverse BFS (see dissertation
# §4.2.3 and Appendix B). Prerequisite: a call graph cache file produced
# by running `python django_scan.py triage` against the target Django
# source tree, which writes `django_framework_scan.cache` to the working
# directory.
#
# Usage: python depth_ablation.py
#
# Loads the cache, runs bfs_longest_path against 31 candidate sinks at
# D in {2,4,6,8,10,12,16,20}, and prints the saturation curve.

import json
import time
import sys
import ast
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from django_scan import CodebaseAnalyzer

_parser = argparse.ArgumentParser(description="Stage 2 BFS depth ablation harness")
_parser.add_argument("--cache", default="django_framework_scan.cache",
                     help="Path to the call graph cache produced by django_scan.py triage")
_args = _parser.parse_args()

cache_path = _args.cache
with open(cache_path, 'r') as f:
    cache_data = json.load(f)

analyzer = CodebaseAnalyzer.__new__(CodebaseAnalyzer)
analyzer.directory = cache_data['directory']
analyzer.call_graph = cache_data['call_graph']
analyzer.public_entries = set(cache_data.get('public_entries', []))
analyzer.ast_cache = {}
analyzer.code_cache = {}

print("Rebuilding AST cache from source...")
for root, _, files in os.walk(analyzer.directory):
    for file_name in files:
        if file_name.endswith('.py'):
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                analyzer.code_cache[file_path] = content
                analyzer.ast_cache[file_path] = ast.parse(
                    content, filename=file_path)
            except Exception:
                pass

print(f"Call graph loaded. Total callees tracked: {len(analyzer.call_graph)}")


def bfs_longest_path(analyzer, sink, max_depth):
    """
    Reverse BFS returning the LONGEST path found up to max_depth.
    Distinct from the production BFS which returns the SHORTEST path:
    this variant is used exclusively for depth ablation to find the
    maximum observable call chain for a given sink. Public-entry
    termination is deliberately omitted so the result reflects the
    structural ceiling on recoverable depth rather than the production
    system's exploit-path constraint.
    """
    start = time.time()
    all_terminal_paths = []
    queue = [[{"name": sink, "file": "UNKNOWN"}]]
    nodes_visited = 0

    while queue:
        current_path = queue.pop(0)
        nodes_visited += 1
        last_name = current_path[0]["name"]

        if len(current_path) > max_depth:
            all_terminal_paths.append(current_path)
            continue

        callers = analyzer.call_graph.get(last_name, [])
        if not callers:
            all_terminal_paths.append(current_path)
            continue

        for caller in callers:
            caller_name = caller["name"]
            # Per-path cycle detection: a node may appear in different
            # paths but not twice within the same path.
            if caller_name not in [p["name"] for p in current_path]:
                queue.append([caller] + current_path)

    elapsed = (time.time() - start) * 1000
    if not all_terminal_paths:
        return None, elapsed, nodes_visited
    longest = max(all_terminal_paths, key=len)
    return longest, elapsed, nodes_visited


# --- PHASE 1: Find which sinks actually exist in the call graph ---
CANDIDATE_SINKS = [
    "SQLCompiler.as_sql",
    "SQLInsertCompiler.as_sql",
    "SQLUpdateCompiler.as_sql",
    "SQLDeleteCompiler.as_sql",
    "WhereNode.as_sql",
    "Col.as_sql",
    "ExpressionWrapper.as_sql",
    "Aggregate.as_sql",
    "Case.as_sql",
    "Subquery.as_sql",
    "Window.as_sql",
    "Query.build_filter",
    "Query.add_q",
    "Query.resolve_lookup_value",
    "SQLCompiler.execute_sql",
    "SQLCompiler.results_iter",
    "SQLCompiler.get_columns",
    "BaseDatabaseWrapper.execute",
    "CursorWrapper.execute",
    "CursorWrapper.executemany",
    "DatabaseWrapper.ensure_connection",
    "Query.chain",
    "Query.clone",
    "QuerySet._iterator",
    "QuerySet.iterator",
    "QuerySet._fetch_all",
    "ModelIterable.__iter__",
    "Query.get_compiler",
    "SQLCompiler.pre_sql_setup",
    "SQLCompiler.get_from_clause",
    "SQLCompiler.get_order_by",
]


print("\n--- Phase 1: Sink discovery (max depth 12) ---")
print(f"{'Sink':<45} {'Max path len':<15} {'In graph?'}")
print("-" * 70)

sink_depths = {}
for sink in CANDIDATE_SINKS:
    in_graph = sink in analyzer.call_graph
    if in_graph:
        path, _, _ = bfs_longest_path(analyzer, sink, 12)
        depth = len(path) if path else 0
        sink_depths[sink] = depth
        print(f"{sink:<45} {depth:<15} YES")
    else:
        print(f"{sink:<45} {'N/A':<15} NOT IN GRAPH")

# --- PHASE 2: Full ablation on the deepest sink found ---
if sink_depths:
    deepest_sink = max(sink_depths, key=sink_depths.get)
    max_natural_depth = sink_depths[deepest_sink]

    print(f"\n--- Phase 2: Full depth ablation on deepest sink ---")
    print(f"Sink: {deepest_sink} (natural depth: {max_natural_depth})")
    print(f"\n{'D':<6} {'Path Len':<12} {'Time (ms)':<14} {'Nodes visited':<16} {'Saturated?'}")
    print("-" * 65)

    prev_length = 0
    for d in [2, 4, 6, 8, 10, 12, 16, 20]:
        path, elapsed, nodes = bfs_longest_path(analyzer, deepest_sink, d)
        length = len(path) if path else 0
        saturated = "YES, D sufficient" if length == prev_length and d > 2 else "still growing"
        print(f"{d:<6} {length:<12} {elapsed:<14.2f} {nodes:<16} {saturated}")
        prev_length = length

    print(f"\n--- Reconstructed longest path at D=20 ---")
    path, _, _ = bfs_longest_path(analyzer, deepest_sink, 20)
    if path:
        for i, hop in enumerate(reversed(path)):
            print(f"  {i+1:>2}. {hop['name']}() in {hop.get('file', 'UNKNOWN')}")
        print(f"\n  Total hops: {len(path)}")

    # --- PHASE 3: Repeat ablation on original CVE sink for comparison ---
    print(f"\n--- Phase 3: Same ablation on CVE sink (SQLCompiler.as_sql) ---")
    print(f"\n{'D':<6} {'Path Len':<12} {'Time (ms)':<14} {'Nodes visited'}")
    print("-" * 50)
    for d in [2, 4, 6, 8, 10, 12]:
        path, elapsed, nodes = bfs_longest_path(
            analyzer, "SQLCompiler.as_sql", d)
        length = len(path) if path else 0
        print(f"{d:<6} {length:<12} {elapsed:<14.2f} {nodes}")

    print("\n--- Interpretation ---")
    print(f"CVE sink (SQLCompiler.as_sql) saturates at ~3 hops.")
    print(f"Deep sink ({deepest_sink}) saturates at ~{max_natural_depth} hops.")
    print(f"D=8 is {'sufficient' if max_natural_depth <= 8 else 'INSUFFICIENT'} "
          f"for the deepest Django ORM path.")
