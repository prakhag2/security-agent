#!/usr/bin/env python3
"""
OWASP Juice Shop Security Analysis UI Server.

Serves:
- Juice Shop test ontology graphs and vulnerability scanning
- Graph-guided vulnerability scanning with SSE streaming
"""

import http.server
import json
import os
import re
import sys
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from strands.hooks import BeforeToolCallEvent, AfterToolCallEvent, HookProvider, HookRegistry


class LockAfterSuccess(HookProvider):
    """Lock verifier tools after a test exits successfully (exit code 0).
    Also ensures write_test is only called once."""

    def __init__(self):
        self.locked = False
        self.written = False

    def register_hooks(self, registry: HookRegistry, **kwargs):
        registry.add_callback(AfterToolCallEvent, self._track)
        registry.add_callback(BeforeToolCallEvent, self._gate)

    def _track(self, event: AfterToolCallEvent):
        if event.tool_use["name"] not in ("write_test", "fix_test"):
            return
        if event.tool_use["name"] == "write_test":
            self.written = True
        result_content = str(event.result.get("content", "")) if isinstance(event.result, dict) else str(event.result)
        if "exit code 0)" in result_content or "TEST PASSED" in result_content:
            self.locked = True

    def _gate(self, event: BeforeToolCallEvent):
        if event.tool_use["name"] == "write_test" and self.written:
            event.cancel_tool = "write_test can only be called once. Use fix_test to fix errors."
            return
        if self.locked and event.tool_use["name"] in ("write_test", "fix_test"):
            event.cancel_tool = "Test already ran successfully. Issue your verdict based on the output you have."


BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BENCH_DIR)
SCAN_RESULTS_DIR = os.path.join(DATA_DIR, "scan_results")
NEO4J_JUICESHOP_URI = os.environ.get("NEO4J_JUICESHOP_URI", os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
NEO4J_AUTH = (os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "password123"))


def _resolve_trace_path(filename):
    return os.path.join(BENCH_DIR, filename)


def _parse_json_from_text(text, container='{'):
    close = '}' if container == '{' else ']'
    s = text.find(container)
    if s < 0:
        return None
    d = 0
    for j in range(s, len(text)):
        if text[j] == container: d += 1
        elif text[j] == close:
            d -= 1
            if d == 0:
                try:
                    return json.loads(text[s:j+1])
                except json.JSONDecodeError:
                    return None
    return None






def _extract_usage_metrics(result):
    try:
        metrics = result.metrics
        u = metrics.accumulated_usage
        uncached_input = u.get("inputTokens", 0)
        output_tokens = u.get("outputTokens", 0)
        cache_read = u.get("cacheReadInputTokens", 0)
        cache_write = u.get("cacheWriteInputTokens", 0)

        total_input = uncached_input + cache_read + cache_write
        cost = (
            uncached_input * 3.0 / 1_000_000
            + output_tokens * 15.0 / 1_000_000
            + cache_read * 0.30 / 1_000_000
            + cache_write * 3.75 / 1_000_000
        )
        cache_hit_pct = (cache_read / total_input * 100) if total_input > 0 else 0

        return {
            "input_tokens": total_input,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read,
            "cache_write_tokens": cache_write,
            "uncached_input_tokens": uncached_input,
            "cache_hit_pct": round(cache_hit_pct, 1),
            "cost_usd": round(cost, 4),
            "cycles": metrics.cycle_count,
        }
    except Exception:
        return {}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, path):
        with open(path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content)

    def _static(self, path, content_type, cache=False):
        with open(path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if cache:
            self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(content)

    def _error(self, code):
        self.send_response(code)
        self.end_headers()

    def _sse_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _make_sse_sender(self):
        wfile = self.wfile

        def send_sse(event_type, data):
            try:
                sse = f"data: {json.dumps({'type': event_type, **data})}\n\n"
                wfile.write(sse.encode())
                wfile.flush()
            except Exception:
                pass
        return send_sse

    def _params(self):
        params = {}
        if "?" in self.path:
            for kv in self.path.split("?")[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[k] = unquote(v)
        return params

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if path in ("/", "/index.html", "/ui.html", "/ui"):
            self._html(os.path.join(BENCH_DIR, "ui.html"))

        elif path == "/d3.v7.min.js":
            self._static(os.path.join(BENCH_DIR, "d3.v7.min.js"), "application/javascript", cache=True)

        elif path.startswith("/static/"):
            static_file = path[len("/static/"):]
            static_path = os.path.join(BENCH_DIR, "static", static_file)
            if not os.path.isfile(static_path) or ".." in static_file:
                return self._error(404)
            ct = "text/css" if static_file.endswith(".css") else "application/javascript" if static_file.endswith(".js") else "application/octet-stream"
            self._static(static_path, ct)

        elif path == "/api/scan-results":
            params = self._params()
            scan_id = params.get("id", "")
            project = params.get("project", "")
            if scan_id:
                scan_path = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
                if not os.path.exists(scan_path):
                    return self._error(404)
                with open(scan_path) as f:
                    self._json(json.load(f))
            else:
                results = []
                if os.path.isdir(SCAN_RESULTS_DIR):
                    for f in sorted(os.listdir(SCAN_RESULTS_DIR), reverse=True):
                        if not f.endswith(".json"):
                            continue
                        if f == "juiceshop_batch_progress.json":
                            continue
                        fpath = os.path.join(SCAN_RESULTS_DIR, f)
                        try:
                            with open(fpath) as fh:
                                data = json.load(fh)
                            if not data.get("test"):
                                continue
                            file_project = data.get("project", "")
                            if project == "juiceshop":
                                if file_project and file_project != "juiceshop":
                                    continue
                                if not file_project and "__" not in data["test"]:
                                    continue
                            results.append({"id": data.get("id", f[:-5]), "test": data.get("test", ""), "timestamp": data.get("timestamp", ""), "targets": data.get("targets", 0), "confirmed": data.get("confirmed", 0)})
                        except Exception:
                            pass
                self._json(results)

        elif path == "/api/label-targets":
            params = self._params()
            scan_id = params.get("id", "")
            if not scan_id:
                return self._error(400)
            scan_path = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
            if not os.path.exists(scan_path):
                return self._error(404)
            with open(scan_path) as f:
                data = json.load(f)
            test_name = data.get("test", "")
            targets = data.get("all_targets", [])
            rows = []
            for t in targets:
                tid = t.get("id", "")
                priority = t.get("priority", "")
                angle = t.get("attack_angle", "")
                for role, node_key in [("source", "source_node"), ("control", "control_point"), ("sink", "sink_node")]:
                    node = t.get(node_key, {})
                    if not isinstance(node, dict):
                        continue
                    node_id = node.get("fid", "") or node.get("id", "")
                    if not node_id or node_id == "none":
                        continue
                    fid = node_id if node_id.startswith(test_name) or node_id.startswith("f") else f"{test_name}_{node_id}"
                    rows.append({
                        "fid": fid, "role": role, "tid": tid,
                        "priority": priority, "angle": angle,
                        "name": node.get("display_name", "") or node.get("name", ""),
                        "file": node.get("file", ""),
                    })
            if not rows:
                return self._json({"restored": 0})
            project = data.get("project") or "juiceshop"
            try:
                if project == "juiceshop":
                    self._load_juiceshop_to_neo4j(test_name)
                self._restore_targets_neo4j(test_name, rows, targets, project=project)
                self._json({"restored": len(targets), "labeled": len(rows)})
            except Exception as e:
                self._json({"restored": 0, "error": str(e)})

        elif path == "/api/neo4j-cypher":
            params = self._params()
            q = params.get("q", "")
            project = params.get("project", "juiceshop")
            if not q:
                return self._error(400)
            from neo4j import GraphDatabase as _GD
            uri = NEO4J_JUICESHOP_URI
            try:
                driver = _GD.driver(uri, auth=NEO4J_AUTH)
                with driver.session() as session:
                    result = session.run(q)
                    records = [dict(r) for r in result]
                driver.close()
                self._json({"records": records[:100]})
            except Exception as e:
                self._json({"error": str(e)})

        elif path == "/api/juiceshop/ground-truth":
            gt_path = os.path.join(os.path.dirname(__file__), "juiceshop_ground_truth.json")
            if os.path.exists(gt_path):
                with open(gt_path) as f:
                    self._json(json.load(f))
            else:
                self._error(404)

        elif path == "/api/neo4j-cleanup-attacks":
            self._cleanup_attack_data()
            self._json({"status": "ok"})

        elif path == "/api/static-findings":
            params = self._params()
            trace_file = params.get("file", "")
            project = params.get("project", "juiceshop")
            self._json(self._get_static_findings(trace_file, project))

        # --- Juice Shop API endpoints ---
        elif path == "/api/juiceshop/graph":
            graph_path = os.path.join(BENCH_DIR, "juiceshop_graph.json")
            if os.path.exists(graph_path):
                with open(graph_path) as f:
                    self._json(json.load(f))
            else:
                self._json({"nodes": [], "edges": [], "total_funcs": 0, "total_edges": 0})

        elif path == "/api/juiceshop/tests":
            index_path = os.path.join(BENCH_DIR, "juiceshop_traces", "_index.json")
            if os.path.exists(index_path):
                with open(index_path) as f:
                    self._json(json.load(f))
            else:
                self._json([])

        elif path == "/api/juiceshop/flow":
            params = self._params()
            test_name = params.get("test", "")
            if not test_name:
                return self._error(400)
            trace_path = os.path.join(BENCH_DIR, "juiceshop_traces", f"{test_name}.json")
            if os.path.exists(trace_path):
                with open(trace_path) as f:
                    self._json(json.load(f))
            else:
                self._json({"error": "Test not found"})

        elif path == "/api/juiceshop/neo4j-graph":
            params = self._params()
            test_name = params.get("test", "")
            if not test_name:
                return self._error(400)
            self._json(self._get_juiceshop_neo4j_graph(test_name))

        elif path == "/api/juiceshop/neo4j-load":
            params = self._params()
            test_name = params.get("test", "")
            scan_id = params.get("scan", "")
            target_rows = None
            if scan_id:
                scan_path = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
                if os.path.exists(scan_path):
                    with open(scan_path) as f:
                        scan_data = json.load(f)
                    targets = scan_data.get("all_targets", [])
                    tn = scan_data.get("test", test_name)
                    target_rows = []
                    for t in targets:
                        tid = t.get("id", "")
                        priority = t.get("priority", "")
                        angle = t.get("attack_angle", "")
                        for role, nk in [("source", "source_node"), ("control", "control_point"), ("sink", "sink_node")]:
                            node = t.get(nk, {})
                            nid = node.get("id", "") if isinstance(node, dict) else ""
                            if nid:
                                fid = nid if nid.startswith(tn) else f"{tn}_{nid}"
                                target_rows.append({"fid": fid, "role": role, "tid": tid, "priority": priority, "angle": angle})
            if test_name:
                self._json(self._load_juiceshop_to_neo4j(test_name, target_rows=target_rows))
            else:
                self._json(self._load_all_juiceshop_to_neo4j())

        elif path == "/api/juiceshop/neo4j-query":
            params = self._params()
            test_name = params.get("test", "")
            if not test_name:
                return self._error(400)
            self._json(self._run_juiceshop_attack_queries(test_name))

        elif path == "/api/juiceshop/vuln-scan":
            params = self._params()
            test_name = params.get("test", "")
            if not test_name:
                return self._error(400)
            self._sse_headers()
            self._run_juiceshop_vuln_scan(test_name)

        elif path == "/api/juiceshop/vuln-scan-all":
            params = self._params()
            subset_param = params.get("tests", "")
            count_param = params.get("count", "")
            self._sse_headers()
            self._run_juiceshop_vuln_scan_all(subset=subset_param, count=count_param)

        elif path == "/api/juiceshop/vuln-scan-all-status":
            self._json(self._get_juiceshop_batch_status())

        else:
            self._error(404)


    def _cleanup_attack_data(self):
        from neo4j import GraphDatabase as _GD
        driver = _GD.driver(NEO4J_JUICESHOP_URI, auth=NEO4J_AUTH)
        with driver.session() as session:
            session.run("MATCH ()-[r:ATTACK_FLOW]->() DELETE r")
            session.run("MATCH ()-[r:ATTACK_PATH]->() DELETE r")
            session.run("MATCH (t:AttackTarget) DETACH DELETE t")
            session.run("MATCH (n:Targeted) REMOVE n:Targeted REMOVE n.attack_role REMOVE n.attack_target_id REMOVE n.attack_priority REMOVE n.attack_angle")
        driver.close()

    def _get_juiceshop_neo4j_graph(self, test_name):
        """Return Juice Shop ontology graph from Neo4j."""
        from neo4j import GraphDatabase as _GD
        NEO4J_URI = NEO4J_JUICESHOP_URI
        try:
            driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
            with driver.session() as session:
                nodes_result = session.run(
                    "MATCH (n:Function) WHERE n.test = $test "
                    "RETURN n.fid AS id, n.display_name AS name, n.file AS file, "
                    "n.role AS role, n.trust AS trust, n.tainted AS tainted, "
                    "n.subsystem AS subsystem, n.sensitivity AS sensitivity, n.depth AS depth",
                    test=test_name
                )
                nodes = [dict(r) for r in nodes_result]

                rels_result = session.run(
                    "MATCH (a:Function {test: $test})-[r]->(b:Function {test: $test}) "
                    "RETURN a.fid AS source, b.fid AS target, type(r) AS type, "
                    "r.data AS data, r.tainted AS tainted, r.reason AS reason",
                    test=test_name
                )
                edges = [dict(r) for r in rels_result]
            driver.close()
            return {"nodes": nodes, "edges": edges, "test": test_name}
        except Exception as e:
            return {"nodes": [], "edges": [], "test": test_name, "error": str(e)}

    def _resolve_node_fid(self, session, test_name, fid, name, file):
        """Resolve a target node to its actual fid in Neo4j."""
        result = session.run("MATCH (n:Function {fid: $fid, test: $test}) RETURN n.fid AS fid LIMIT 1", fid=fid, test=test_name)
        rec = result.single()
        if rec:
            return rec["fid"]
        # Try without test constraint (for juiceshop where fid is globally unique)
        result = session.run("MATCH (n:Function {fid: $fid}) RETURN n.fid AS fid LIMIT 1", fid=fid)
        rec = result.single()
        if rec:
            return rec["fid"]
        if name and file and name != "none":
            result = session.run(
                "MATCH (n:Function {test: $test}) WHERE (n.func = $name OR n.display_name = $name) AND n.file ENDS WITH $file "
                "RETURN n.fid AS fid LIMIT 1",
                test=test_name, name=name, file=file
            )
            rec = result.single()
            if rec:
                return rec["fid"]
        return None

    def _restore_targets_neo4j(self, test_name, rows, targets=None, project="juiceshop"):
        """Label nodes as Targeted in Neo4j and create ATTACK_PATH edges."""
        from neo4j import GraphDatabase as _GD
        uri = NEO4J_JUICESHOP_URI
        driver = _GD.driver(uri, auth=NEO4J_AUTH)
        with driver.session() as session:
            # Clear ALL existing Targeted labels and ATTACK_PATH edges (global cleanup for on-demand loading)
            session.run(
                "MATCH (n:Function:Targeted) "
                "REMOVE n:Targeted REMOVE n.attack_role REMOVE n.attack_target_id REMOVE n.attack_priority REMOVE n.attack_angle"
            )
            session.run(
                "MATCH ()-[r]->() WHERE type(r) STARTS WITH 'ATTACK_PATH' DELETE r"
            )
            # Label each node
            for row in rows:
                resolved = self._resolve_node_fid(session, test_name, row["fid"], row.get("name", ""), row.get("file", ""))
                if resolved:
                    session.run(
                        "MATCH (n:Function {fid: $fid, test: $test}) "
                        "SET n:Targeted, n.attack_role = $role, n.attack_target_id = $tid, "
                        "n.attack_priority = $priority, n.attack_angle = $angle",
                        fid=resolved, test=test_name, role=row["role"], tid=row["tid"],
                        priority=row["priority"], angle=row["angle"]
                    )
            # Create ATTACK_PATH_N edges: source→control→sink for each target
            if targets:
                for idx, t in enumerate(targets):
                    rel_type = f"ATTACK_PATH_{idx+1}"
                    tid = t.get("id", f"T{idx+1}")
                    priority = t.get("priority", "")
                    node_fids = {}
                    for role, nk in [("source", "source_node"), ("control", "control_point"), ("sink", "sink_node")]:
                        node = t.get(nk, {})
                        if not isinstance(node, dict):
                            continue
                        nid = node.get("fid", "") or node.get("id", "")
                        if not nid or nid == "none":
                            continue
                        fid_candidate = nid if (nid.startswith(test_name) or nid.startswith("f")) else f"{test_name}_{nid}"
                        resolved = self._resolve_node_fid(session, test_name, fid_candidate, node.get("display_name", "") or node.get("name", ""), node.get("file", ""))
                        if resolved:
                            node_fids[role] = resolved
                    if "source" in node_fids and "sink" in node_fids:
                        if "control" in node_fids:
                            session.run(
                                f"MATCH (a:Function {{fid: $src, test: $test}}), (b:Function {{fid: $ctl, test: $test}}) "
                                f"CREATE (a)-[:{rel_type} {{target_id: $tid, priority: $pri, step: 'source→control'}}]->(b)",
                                src=node_fids["source"], ctl=node_fids["control"],
                                test=test_name, tid=tid, pri=priority
                            )
                            session.run(
                                f"MATCH (a:Function {{fid: $ctl, test: $test}}), (b:Function {{fid: $snk, test: $test}}) "
                                f"CREATE (a)-[:{rel_type} {{target_id: $tid, priority: $pri, step: 'control→sink'}}]->(b)",
                                ctl=node_fids["control"], snk=node_fids["sink"],
                                test=test_name, tid=tid, pri=priority
                            )
                        else:
                            session.run(
                                f"MATCH (a:Function {{fid: $src, test: $test}}), (b:Function {{fid: $snk, test: $test}}) "
                                f"CREATE (a)-[:{rel_type} {{target_id: $tid, priority: $pri, step: 'source→sink'}}]->(b)",
                                src=node_fids["source"], snk=node_fids["sink"],
                                test=test_name, tid=tid, pri=priority
                            )
        driver.close()

    def _load_juiceshop_to_neo4j(self, test_name, target_rows=None):
        """Load a single Juice Shop test's ontology into Neo4j. Optionally label targets."""
        from neo4j import GraphDatabase as _GD
        NEO4J_URI = NEO4J_JUICESHOP_URI

        trace_path = os.path.join(BENCH_DIR, "juiceshop_raw_traces", f"{test_name}.json")
        if not os.path.exists(trace_path):
            return {"error": "Test trace not found"}

        try:
            with open(trace_path) as f:
                trace = json.load(f)

            from juiceshop_ontology import apply_ontology
            result = apply_ontology(trace)

            driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
            with driver.session() as session:
                # Clear existing data for this test
                session.run("MATCH (n:JuiceShop {test: $test}) DETACH DELETE n", test=test_name)

                # Build index for parent lookup
                entries_by_id = {e['id']: e for e in result['entries']}

                def _get_display_name(e):
                    func = e.get('func', '?')
                    file_path = e.get('file', '')
                    base = (file_path.split('/')[-1]) if file_path else ''
                    is_synthetic = func in ('<anonymous>', 'get', '?') or bool(re.match(r'^_ret\d+$|^_anon\d+$', func))
                    if not is_synthetic:
                        return func
                    # Walk up to find nearest named parent
                    parent_name = None
                    pid = e.get('parent')
                    seen = set()
                    while pid is not None and pid not in seen:
                        seen.add(pid)
                        parent = entries_by_id.get(pid)
                        if not parent:
                            break
                        pf = parent.get('func', '?')
                        if pf and not re.match(r'^_ret\d+$|^_anon\d+$', pf) and pf not in ('<anonymous>', 'get', '?'):
                            parent_name = pf
                            break
                        pid = parent.get('parent')
                    role = e.get('role', '')
                    role_str = f" ({role})" if role and role != 'unknown' else ''
                    if parent_name:
                        return f"{base} → {parent_name}{role_str}"
                    return f"{base}{role_str}" if base else func

                # Create nodes
                for e in result['entries']:
                    display = _get_display_name(e)

                    session.run(
                        "CREATE (f:Function:JuiceShop $props)",
                        props={
                            'fid': f"{test_name}_{e['id']}",
                            'test': test_name,
                            'entry_id': e['id'],
                            'display_name': display,
                            'file': e.get('file', ''),
                            'func': e.get('func', ''),
                            'role': e['role'],
                            'trust': e['trust_level'],
                            'tainted': e['tainted'],
                            'subsystem': e['subsystem'],
                            'sensitivity': e['data_sensitivity'],
                            'depth': e.get('depth', 0),
                        }
                    )

                # Create CALLS edges
                for e in result['entries']:
                    if e.get('parent') is not None:
                        session.run(
                            "MATCH (a:Function {fid: $pfid}), (b:Function {fid: $cfid}) CREATE (a)-[:CALLS]->(b)",
                            pfid=f"{test_name}_{e['parent']}", cfid=f"{test_name}_{e['id']}"
                        )

                # Create DATA_FLOWS edges
                for flow in result['data_flows']:
                    session.run(
                        "MATCH (a:Function {fid: $ffid}), (b:Function {fid: $tfid}) "
                        "CREATE (a)-[:DATA_FLOWS {data: $data, mechanism: $mech, tainted: $tainted}]->(b)",
                        ffid=f"{test_name}_{flow['from']}", tfid=f"{test_name}_{flow['to']}",
                        data=flow.get('data', ''), mech=flow.get('mechanism', ''),
                        tainted=flow.get('tainted', False)
                    )

                # Create relationship edges
                for rel in result['relationships']:
                    session.run(
                        f"MATCH (a:Function {{fid: $ffid}}), (b:Function {{fid: $tfid}}) "
                        f"CREATE (a)-[:{rel['type']} {{reason: $reason}}]->(b)",
                        ffid=f"{test_name}_{rel['from']}", tfid=f"{test_name}_{rel['to']}",
                        reason=rel.get('reason', '')
                    )

            # Optionally label target nodes
            if target_rows:
                with driver.session() as session2:
                    session2.run("MATCH (n:Targeted {test: $test}) REMOVE n:Targeted REMOVE n.attack_role REMOVE n.attack_target_id REMOVE n.attack_priority REMOVE n.attack_angle", test=test_name)
                    for row in target_rows:
                        session2.run(
                            "MATCH (n:JuiceShop {fid: $fid, test: $test}) "
                            "SET n:Targeted, n.attack_role = $role, n.attack_target_id = $tid, "
                            "n.attack_priority = $priority, n.attack_angle = $angle",
                            fid=row["fid"], test=test_name, role=row["role"],
                            tid=row["tid"], priority=row["priority"], angle=row["angle"]
                        )

            driver.close()
            return {
                "status": "loaded",
                "test": test_name,
                "nodes": len(result['entries']),
                "calls": sum(1 for e in result['entries'] if e.get('parent') is not None),
                "data_flows": len(result['data_flows']),
                "relationships": len(result['relationships']),
                "tainted": result['stats']['tainted_count'],
            }
        except Exception as e:
            return {"error": str(e)}

    def _load_all_juiceshop_to_neo4j(self):
        """Batch-load all Juice Shop tests into Neo4j."""
        from neo4j import GraphDatabase as _GD
        NEO4J_URI = NEO4J_JUICESHOP_URI

        traces_dir = os.path.join(BENCH_DIR, "juiceshop_raw_traces")
        if not os.path.isdir(traces_dir):
            return {"error": "juiceshop_raw_traces directory not found"}

        from juiceshop_ontology import apply_ontology

        files = sorted(f for f in os.listdir(traces_dir) if f.endswith('.json') and not f.startswith('_'))
        driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)

        with driver.session() as session:
            session.run("CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.fid)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.test)")
            session.run("MATCH (n:JuiceShop) DETACH DELETE n")

        loaded = 0
        errors = []
        for fname in files:
            test_name = fname.replace('.json', '')
            try:
                with open(os.path.join(traces_dir, fname)) as fh:
                    trace = json.load(fh)
                result = apply_ontology(trace)

                with driver.session() as session:
                    # Batch create nodes
                    entries_data = []
                    for e in result['entries']:
                        func = e.get('func', '?')
                        fp = e.get('file', '')
                        base = fp.split('/')[-1].replace('.ts', '').replace('.js', '') if fp else ''
                        display = func if func not in ('<anonymous>', 'get', '?') else f"{base}:{func}"
                        entries_data.append({
                            'fid': f"{test_name}_{e['id']}",
                            'test': test_name, 'entry_id': e['id'],
                            'display_name': display, 'file': fp,
                            'func': e.get('func', ''), 'role': e['role'],
                            'trust': e['trust_level'], 'tainted': e['tainted'],
                            'subsystem': e['subsystem'], 'sensitivity': e['data_sensitivity'],
                            'depth': e.get('depth', 0),
                        })
                    session.run(
                        "UNWIND $batch AS props CREATE (f:Function:JuiceShop) SET f = props",
                        batch=entries_data
                    )

                    # Batch create CALLS
                    calls = [{'pfid': f"{test_name}_{e['parent']}", 'cfid': f"{test_name}_{e['id']}"}
                             for e in result['entries'] if e.get('parent') is not None]
                    if calls:
                        session.run(
                            "UNWIND $batch AS row "
                            "MATCH (a:Function {fid: row.pfid}), (b:Function {fid: row.cfid}) "
                            "CREATE (a)-[:CALLS]->(b)",
                            batch=calls
                        )

                    # Batch create DATA_FLOWS
                    flows = [{'ffid': f"{test_name}_{f['from']}", 'tfid': f"{test_name}_{f['to']}",
                              'data': f.get('data', ''), 'mech': f.get('mechanism', ''),
                              'tainted': f.get('tainted', False)}
                             for f in result['data_flows']]
                    if flows:
                        session.run(
                            "UNWIND $batch AS row "
                            "MATCH (a:Function {fid: row.ffid}), (b:Function {fid: row.tfid}) "
                            "CREATE (a)-[:DATA_FLOWS {data: row.data, mechanism: row.mech, tainted: row.tainted}]->(b)",
                            batch=flows
                        )

                    # Batch create relationships by type
                    for rel_type in ('GATES', 'VALIDATES', 'PRODUCES_TOKEN', 'ACCESSES_DATA'):
                        rels = [{'ffid': f"{test_name}_{r['from']}", 'tfid': f"{test_name}_{r['to']}",
                                 'reason': r.get('reason', '')}
                                for r in result['relationships'] if r['type'] == rel_type]
                        if rels:
                            session.run(
                                f"UNWIND $batch AS row "
                                f"MATCH (a:Function {{fid: row.ffid}}), (b:Function {{fid: row.tfid}}) "
                                f"CREATE (a)-[:{rel_type} {{reason: row.reason}}]->(b)",
                                batch=rels
                            )

                loaded += 1
            except Exception as e:
                errors.append(f"{fname}: {str(e)[:80]}")

        driver.close()
        return {
            "status": "loaded",
            "total": len(files),
            "loaded": loaded,
            "errors": errors[:10] if errors else [],
        }

    def _run_juiceshop_attack_queries(self, test_name):
        """Run anti-pattern Cypher queries for a Juice Shop test."""
        from neo4j import GraphDatabase as _GD
        NEO4J_URI = NEO4J_JUICESHOP_URI

        queries = [
            {
                "name": "Unguarded tainted flow to sensitive operation",
                "cypher": """
                    MATCH (src:JuiceShop {test: $test, tainted: true})-[:DATA_FLOWS*1..4 {tainted: true}]->(sink:JuiceShop {test: $test})
                    WHERE sink.role IN ['crypto', 'jwt_handler', 'db_writer', 'file_handler']
                    AND NOT EXISTS {
                        MATCH (src)-[:DATA_FLOWS*1..3]->(v:JuiceShop {test: $test, role: 'validator'})-[:DATA_FLOWS*1..3]->(sink)
                    }
                    RETURN src.display_name AS source, sink.display_name AS sink,
                           src.file AS source_file, sink.file AS sink_file
                    LIMIT 10
                """,
            },
            {
                "name": "Trust boundary crossing without validation",
                "cypher": """
                    MATCH (a:JuiceShop {test: $test, trust: 'user_controlled'})-[r:DATA_FLOWS {tainted: true}]->(b:JuiceShop {test: $test, trust: 'privileged'})
                    WHERE NOT EXISTS {
                        MATCH (a)-[:DATA_FLOWS]->(v:JuiceShop {test: $test, role: 'validator'})-[:DATA_FLOWS]->(b)
                    }
                    RETURN a.display_name AS source, b.display_name AS target, r.data AS data
                    LIMIT 10
                """,
            },
            {
                "name": "Entry point with no downstream validation",
                "cypher": """
                    MATCH (entry:JuiceShop {test: $test, role: 'entry_point', trust: 'user_controlled'})
                    WHERE NOT entry.subsystem IN ['observability', 'gamification']
                    AND NOT EXISTS {
                        MATCH (entry)-[:CALLS*1..5]->(v:JuiceShop {test: $test, role: 'validator'})
                    }
                    RETURN entry.display_name AS entry_point, entry.file AS file, entry.subsystem AS subsystem
                    LIMIT 10
                """,
            },
        ]

        try:
            driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
            findings = []
            with driver.session() as session:
                for q in queries:
                    try:
                        result = session.run(q['cypher'], test=test_name)
                        records = [dict(r) for r in result]
                        if records:
                            findings.append({"query": q['name'], "results": records})
                    except Exception as e:
                        findings.append({"query": q['name'], "error": str(e)})
            driver.close()
            return {"test": test_name, "findings": findings}
        except Exception as e:
            return {"error": str(e)}

    def _get_static_findings(self, trace_file, project="juiceshop"):
        """Map static findings against a trace, returning overlap info."""
        static_path = os.path.join(BENCH_DIR, "juiceshop_static_findings.json")
        if not os.path.exists(static_path):
            return {"error": "juiceshop_static_findings.json not found"}

        with open(static_path) as f:
            static_data = json.load(f)

        # If no trace specified, return all findings with no overlap info
        if not trace_file:
            for finding in static_data["findings"]:
                finding["in_trace"] = False
                finding["overlap_details"] = []
            return static_data

        # Load trace and build file->lines index
        trace_path = _resolve_trace_path(trace_file)
        if not os.path.exists(trace_path):
            return {"error": f"Trace not found: {trace_file}"}

        with open(trace_path) as f:
            trace = json.load(f)

        traced = {}
        for entry in trace:
            fp = entry.get("file", "")
            line = entry.get("line")
            if fp and line:
                if fp not in traced:
                    traced[fp] = set()
                traced[fp].add(line)

        # Also load dynamic scan results if available
        dynamic_findings = []
        basename = os.path.basename(trace_path).replace(".json", "")
        # Extract short test name (e.g. "test_known_user" from the trace filename)
        short_name = basename.split("_(")[0] if "_(" in basename else basename
        scan_result_path = None
        scan_dirs = [DATA_DIR, BENCH_DIR]
        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            for candidate in sorted(os.listdir(scan_dir)):
                if candidate.startswith("scan_results") and candidate.endswith(".json"):
                    if short_name in candidate:
                        scan_result_path = os.path.join(scan_dir, candidate)
                        break
            if scan_result_path:
                break
        if scan_result_path and os.path.exists(scan_result_path):
            with open(scan_result_path) as f:
                try:
                    dynamic_findings = json.load(f)
                    if isinstance(dynamic_findings, dict):
                        dynamic_findings = dynamic_findings.get("findings", [])
                except (json.JSONDecodeError, KeyError):
                    dynamic_findings = []

        PROXIMITY = 30

        for finding in static_data["findings"]:
            in_trace = False
            overlap_details = []
            for loc in finding["locations"]:
                fp = loc["file"]
                lines = loc["lines"]
                if fp in traced:
                    direct_hits = [l for l in lines if l in traced[fp]]
                    if direct_hits:
                        in_trace = True
                        overlap_details.append({
                            "file": fp,
                            "match": "direct",
                            "finding_lines": direct_hits,
                        })
                    else:
                        traced_lines = sorted(traced[fp])
                        nearby = []
                        for l in lines:
                            for tl in traced_lines:
                                if abs(l - tl) <= PROXIMITY:
                                    nearby.append({"finding_line": l, "traced_line": tl})
                                    break
                        if nearby:
                            in_trace = True
                            overlap_details.append({
                                "file": fp,
                                "match": "proximity",
                                "details": nearby,
                            })

            finding["in_trace"] = in_trace
            finding["overlap_details"] = overlap_details

        static_data["dynamic_findings"] = dynamic_findings
        static_data["trace_file"] = trace_file
        static_data["trace_entries"] = len(trace)
        return static_data

    def _run_juiceshop_vuln_scan(self, test_name):
        """Run the 3-agent vulnerability scan pipeline for Juice Shop with SSE streaming."""
        send_sse = self._make_sse_sender()
        send_sse("phase", {"agent": "pipeline", "status": "starting", "test": test_name})

        import threading

        scan_done = threading.Event()

        def keepalive():
            wfile = self.wfile
            while not scan_done.is_set():
                scan_done.wait(timeout=15)
                if not scan_done.is_set():
                    try:
                        wfile.write(b": keepalive\n\n")
                        wfile.flush()
                    except Exception:
                        break

        def run_in_thread():
            try:
                self._juiceshop_vuln_scan_inner(test_name, send_sse)
            except Exception as e:
                send_sse("error", {"message": str(e)})
            finally:
                scan_done.set()

        ka = threading.Thread(target=keepalive, daemon=True)
        ka.start()
        t = threading.Thread(target=run_in_thread, daemon=True)
        t.start()
        t.join(timeout=7200)
        if t.is_alive():
            send_sse("error", {"message": "Scan timed out (2hr)"})
        scan_done.set()

    def _juiceshop_vuln_scan_inner(self, test_name, send_sse):
        """Inner implementation of Juice Shop vuln scan pipeline."""
        import time as _time
        import subprocess as _subprocess
        import tempfile as _tempfile
        from neo4j import GraphDatabase as _GD
        from strands import Agent as _Agent, tool as _tool
        from strands.models.bedrock import BedrockModel as _BM, CacheConfig as _CC
        from strands.multiagent.graph import GraphBuilder

        from scan_juiceshop_planner import SYSTEM_PROMPT as PLANNER_SYSTEM
        from scan_juiceshop_attacker import SYSTEM_PROMPT as ATTACKER_SYSTEM
        from scan_juiceshop_verifier import SYSTEM_PROMPT as VERIFIER_SYSTEM

        NEO4J_URI = NEO4J_JUICESHOP_URI
        MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-6-v1")
        JUICESHOP_ROOT = os.path.join(BENCH_DIR, "juiceshop_source")
        start = _time.time()
        tool_call_counter = [0]

        def make_tool_emitter(agent_name):
            def emit_tool_call(tool_name, args, result):
                tool_call_counter[0] += 1
                send_sse("tool_call", {
                    "id": tool_call_counter[0],
                    "agent": agent_name,
                    "tool": tool_name,
                    "args": args,
                    "result": result[:1500] if len(result) > 1500 else result,
                    "result_length": len(result),
                })
            return emit_tool_call

        # Ensure test is loaded into Neo4j
        try:
            self._load_juiceshop_to_neo4j(test_name)
        except Exception:
            pass

        # ─── PHASE 1: PLANNER ───────────────────
        send_sse("phase", {"agent": "planner", "status": "running"})
        planner_emit = make_tool_emitter("planner")

        @_tool
        def query_graph(cypher_query: str) -> str:
            """Execute a Cypher query against the Neo4j security graph.

            Graph schema (JuiceShop nodes):
            - Node properties: id, name, func, file, role, subsystem, trust, tainted, test, patterns
            - Roles: entry_point, validator, crypto, jwt_handler, gate, input_reader, file_handler,
              challenge_op, orchestrator, operation, leaf, db_reader, db_writer
            - Edge types: CALLS, DATA_FLOWS, GATES, VALIDATES, PRODUCES_TOKEN, ACCESSES_DATA
            - Trust levels: external_input, user_controlled, app_internal, crypto_boundary, system

            All JuiceShop nodes have the :JuiceShop label. Filter by test: WHERE n.test = 'test_name'
            """
            driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
            try:
                with driver.session() as session:
                    result = session.run(cypher_query)
                    records = [dict(r) for r in result]
                    out = json.dumps(records, indent=2, default=str)
                    planner_emit("query_graph", {"cypher": cypher_query}, out)
                    return out
            except Exception as e:
                err = f"ERROR: {e}"
                planner_emit("query_graph", {"cypher": cypher_query}, err)
                return err
            finally:
                driver.close()

        planner_prompt = f"""Analyze the Neo4j security graph to identify ALL attack targets for test '{test_name}'.

Start with these queries to understand the landscape:
1. MATCH (n:JuiceShop {{test: '{test_name}'}}) RETURN count(n) as nodes
2. MATCH (n:JuiceShop {{test: '{test_name}'}})-[r]->(m) RETURN type(r) as rel_type, count(r) as count
3. MATCH (n:JuiceShop {{test: '{test_name}', role: 'entry_point'}}) RETURN n.name, n.file, n.tainted, n.subsystem
4. MATCH (n:JuiceShop {{test: '{test_name}', tainted: true}}) WHERE n.role IN ['db_writer', 'db_reader', 'file_handler'] RETURN n.name, n.file, n.role
5. MATCH (n:JuiceShop {{test: '{test_name}', role: 'entry_point'}})-[*1..5]->(m {{tainted: true}}) WHERE m.role IN ['db_writer', 'db_reader'] RETURN n.name, m.name, m.file
6. MATCH (n:JuiceShop {{test: '{test_name}', role: 'validator'}}) RETURN n.name, n.file, n.subsystem
7. MATCH path = (src:JuiceShop {{test: '{test_name}', role: 'entry_point'}})-[*1..4]->(sink:JuiceShop {{role: 'db_writer'}}) WHERE NOT any(x IN nodes(path) WHERE x.role = 'validator') RETURN src.name, sink.name, sink.file

After thorough graph exploration, output your targets as a JSON array."""

        model_planner = _BM(model_id=MODEL_ID, region_name=os.environ.get("AWS_REGION", "us-east-1"), max_tokens=8192, cache_config=_CC(strategy="auto"))
        model_agents = _BM(model_id=MODEL_ID, region_name=os.environ.get("AWS_REGION", "us-east-1"), max_tokens=16384, cache_config=_CC(strategy="auto"))
        planner = _Agent(model=model_planner, tools=[query_graph], system_prompt=PLANNER_SYSTEM)

        def planner_callback(**kwargs):
            data = kwargs.get("data", "")
            if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                send_sse("thinking", {"agent": "planner", "text": data})

        planner.callback_handler = planner_callback
        planner_result = planner(planner_prompt)
        planner_text = str(planner_result)

        targets = _parse_json_from_text(planner_text, '[') or []

        planner_usage = _extract_usage_metrics(planner_result)
        total_usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0, "uncached_input_tokens": 0, "cost_usd": 0.0, "cycles": 0}
        for k in total_usage:
            total_usage[k] += planner_usage.get(k, 0)

        send_sse("phase", {"agent": "planner", "status": "done", "targets": len(targets)})
        send_sse("targets", {"targets": targets})

        # Label targets in Neo4j immediately so "Examine" works during the scan
        if targets:
            try:
                rows = []
                for t in targets:
                    tid = t.get("id", "")
                    priority = t.get("priority", "")
                    angle = t.get("attack_angle", "")
                    for role, nk in [("source", "source_node"), ("control", "control_point"), ("sink", "sink_node")]:
                        node = t.get(nk, {})
                        if not isinstance(node, dict):
                            continue
                        nid = node.get("fid", "") or node.get("id", "")
                        if not nid or nid == "none":
                            continue
                        fid = nid if nid.startswith(test_name) or nid.startswith("f") else f"{test_name}_{nid}"
                        rows.append({"fid": fid, "role": role, "tid": tid, "priority": priority, "angle": angle, "name": node.get("display_name", "") or node.get("name", ""), "file": node.get("file", "")})
                if rows:
                    self._restore_targets_neo4j(test_name, rows, targets, project="juiceshop")
            except Exception:
                pass

        if not targets:
            total_usage["cache_hit_pct"] = round((total_usage["cache_read_tokens"] / total_usage["input_tokens"] * 100) if total_usage["input_tokens"] > 0 else 0, 1)
            total_usage["cost_usd"] = round(total_usage["cost_usd"], 4)
            send_sse("done", {
                "elapsed": round(_time.time() - start, 1),
                "targets": 0, "reachable": 0, "confirmed": 0, "hardening": 0,
                "findings": [], "recommendations": [],
                "all_targets": [], "all_attacks": [], "all_verifications": [],
                "usage": total_usage,
            })
            return

        # ─── PHASE 2+3: ATTACKER↔VERIFIER (per target) ──────
        send_sse("phase", {"agent": "attacker", "status": "running", "total": len(targets)})

        attacks = []
        verifications = []

        for i, target in enumerate(targets):
            target_id = target.get("id", f"target_{i}")
            send_sse("attacker_progress", {"index": i, "total": len(targets), "target_id": target_id, "target": target})

            atk_emit = make_tool_emitter("attacker")
            ver_emit = make_tool_emitter("verifier")

            # ── Attacker tools ──

            @_tool
            def read_source_atk(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
                """Read Juice Shop source code. file_path is relative to project root
                (e.g. 'routes/login.ts', 'lib/insecurity.ts'). Optionally specify start_line
                and end_line for a range. Returns numbered source lines."""
                full_path = os.path.join(JUICESHOP_ROOT, file_path)
                if not os.path.exists(full_path):
                    err = f"ERROR: File not found: {file_path}"
                    atk_emit("read_source", {"file": file_path, "start_line": start_line, "end_line": end_line}, err)
                    return err
                with open(full_path) as f:
                    lines = f.readlines()
                if start_line > 0 and end_line > 0:
                    selected = lines[start_line-1:end_line]
                    header = f"[{file_path}:{start_line}-{end_line}]\n"
                else:
                    selected = lines[:300]
                    header = f"[{file_path} ({len(lines)} total lines, showing first 300)]\n"
                out = header + ''.join(f"{ln+1:4d}  {l}" for ln, l in enumerate(selected))
                atk_emit("read_source", {"file": file_path, "start_line": start_line, "end_line": end_line}, out)
                return out

            @_tool
            def grep_source_atk(pattern: str, path: str = "routes") -> str:
                """Search Juice Shop source for a pattern (regex). Searches within
                the specified path relative to project root. Returns matching lines."""
                full_path = os.path.join(JUICESHOP_ROOT, path)
                try:
                    result = _subprocess.run(
                        ['grep', '-rn', '-P', pattern, full_path],
                        capture_output=True, text=True, timeout=10
                    )
                    output = result.stdout.replace(JUICESHOP_ROOT + '/', '')
                    lines = output.strip().split('\n')
                    if len(lines) > 50:
                        lines = lines[:50] + [f"... ({len(lines) - 50} more matches)"]
                    out = '\n'.join(lines) if lines[0] else "No matches found."
                    atk_emit("grep_source", {"pattern": pattern, "path": path}, out)
                    return out
                except Exception as e:
                    err = f"ERROR: {e}"
                    atk_emit("grep_source", {"pattern": pattern, "path": path}, err)
                    return err

            @_tool
            def query_graph_atk(cypher_query: str) -> str:
                """Execute a Cypher query against Neo4j security graph."""
                driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
                try:
                    with driver.session() as session:
                        result = session.run(cypher_query)
                        records = [dict(r) for r in result]
                        out = json.dumps(records, indent=2, default=str)
                        atk_emit("query_graph", {"cypher": cypher_query}, out)
                        return out
                except Exception as e:
                    err = f"ERROR: {e}"
                    atk_emit("query_graph", {"cypher": cypher_query}, err)
                    return err
                finally:
                    driver.close()

            # ── Verifier tools ──
            _current_test_code = [None]

            def _execute_code(code):
                """Internal: execute code and return (exit_code, output_string)."""
                with _tempfile.NamedTemporaryFile(mode='w', suffix='.py', dir=BENCH_DIR, delete=False, prefix='jscan_') as f:
                    f.write(code)
                    tf = f.name
                try:
                    env = os.environ.copy()
                    r = _subprocess.run([sys.executable, tf], capture_output=True, text=True, timeout=60, cwd=BENCH_DIR, env=env)
                    output = r.stdout + r.stderr
                    if len(output) > 4000:
                        output = output[:2000] + "\n...[truncated]...\n" + output[-2000:]
                    status = "PASSED" if r.returncode == 0 else "FAILED"
                    return r.returncode, f"TEST {status} (exit code {r.returncode})\n\n{output}"
                except _subprocess.TimeoutExpired:
                    return 1, "TEST TIMEOUT (>60s)"
                finally:
                    os.unlink(tf)

            @_tool
            def write_test(test_code: str) -> str:
                """Write and execute a Python test script. Call this once with the complete test."""
                _current_test_code[0] = test_code
                exit_code, out = _execute_code(test_code)
                verifier_test_runs.append({"code": test_code, "output": out})
                ver_emit("run_test", {"code_length": len(test_code)}, out)
                return out

            @_tool
            def fix_test(fix_description: str, fixed_code: str) -> str:
                """Fix ONLY the error in the previous test. Do not change the logic or add new functionality."""
                _current_test_code[0] = fixed_code
                exit_code, out = _execute_code(fixed_code)
                verifier_test_runs.append({"code": fixed_code, "output": out, "modification": fix_description})
                ver_emit("fix_test", {"fix": fix_description, "code_length": len(fixed_code)}, out)
                return out


            @_tool
            def read_source_ver(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
                """Read Juice Shop source code to verify claims about code behavior."""
                full_path = os.path.join(JUICESHOP_ROOT, file_path)
                if not os.path.exists(full_path):
                    err = f"ERROR: File not found: {file_path}"
                    ver_emit("read_source", {"file": file_path, "start_line": start_line, "end_line": end_line}, err)
                    return err
                with open(full_path) as f:
                    lines = f.readlines()
                if start_line > 0 and end_line > 0:
                    selected = lines[start_line-1:end_line]
                    header = f"[{file_path}:{start_line}-{end_line}]\n"
                else:
                    selected = lines[:200]
                    header = f"[{file_path}]\n"
                out = header + ''.join(f"{ln+1:4d}  {l}" for ln, l in enumerate(selected))
                ver_emit("read_source", {"file": file_path, "start_line": start_line, "end_line": end_line}, out)
                return out

            # Create agent instances
            attacker_thinking = []
            verifier_thinking = []
            verifier_test_runs = []

            def attacker_callback(**kwargs):
                data = kwargs.get("data", "")
                if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                    attacker_thinking.append(data)
                    send_sse("thinking", {"agent": "attacker", "target_id": target_id, "text": data})

            def verifier_callback(**kwargs):
                data = kwargs.get("data", "")
                if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                    verifier_thinking.append(data)
                    send_sse("thinking", {"agent": "verifier", "target_id": target_id, "text": data})

            attacker_agent = _Agent(model=model_agents, tools=[read_source_atk, grep_source_atk, query_graph_atk], system_prompt=ATTACKER_SYSTEM)
            attacker_agent.callback_handler = attacker_callback

            verifier_hook = LockAfterSuccess()
            verifier_agent = _Agent(model=model_agents, tools=[write_test, fix_test], system_prompt=VERIFIER_SYSTEM, hooks=[verifier_hook])
            verifier_agent.callback_handler = verifier_callback

            # Build attacker→verifier graph
            builder = GraphBuilder()
            builder.add_node(attacker_agent, "attacker")
            builder.add_node(verifier_agent, "verifier")
            builder.add_edge("attacker", "verifier")
            builder.set_entry_point("attacker")
            builder.set_node_timeout(900.0)
            target_graph = builder.build()

            task_prompt = f"""Analyze this attack target in OWASP Juice Shop:

{json.dumps(target, indent=2)}

Read the source code of the functions on the path. Understand the exact logic. Determine if this is reachable from an external HTTP request and describe the attack scenario.

Output your analysis as JSON."""

            try:
                graph_result = target_graph(task_prompt)

                graph_usage = graph_result.accumulated_usage
                input_tokens = graph_usage.get("inputTokens", 0)
                output_tokens = graph_usage.get("outputTokens", 0)
                cache_read = graph_usage.get("cacheReadInputTokens", 0)
                cache_write = graph_usage.get("cacheWriteInputTokens", 0)
                total_input = input_tokens + cache_read + cache_write
                cost = (
                    input_tokens * 3.0 / 1_000_000
                    + output_tokens * 15.0 / 1_000_000
                    + cache_read * 0.30 / 1_000_000
                    + cache_write * 3.75 / 1_000_000
                )
                total_usage["input_tokens"] += total_input
                total_usage["output_tokens"] += output_tokens
                total_usage["cache_read_tokens"] += cache_read
                total_usage["cache_write_tokens"] += cache_write
                total_usage["uncached_input_tokens"] += input_tokens
                total_usage["cost_usd"] += cost
                total_usage["cycles"] += graph_result.execution_count

                atk_result_node = graph_result.results.get("attacker")
                atk_text = str(atk_result_node.result) if atk_result_node else ""
                attack = _parse_json_from_text(atk_text) or {"target_id": target_id, "reachable": False, "classification": "error", "reasoning": atk_text[:300] if atk_text else "No output from attacker agent"}
                attack["_thinking"] = ''.join(attacker_thinking)[:2000]
                attack["_attempts"] = 1

                ver_result_node = graph_result.results.get("verifier")
                ver_text = str(ver_result_node.result) if ver_result_node else ""
                verification = _parse_json_from_text(ver_text)

                if verification:
                    verification["_thinking"] = ''.join(verifier_thinking)[:2000]
                    verification["_attempts"] = len(verifier_test_runs)
                    verification["_test_runs"] = verifier_test_runs[:]

            except Exception as e:
                attack = {"target_id": target_id, "reachable": False, "classification": "error", "reasoning": str(e)}
                attack["_thinking"] = ''.join(attacker_thinking)[:2000]
                verification = None

            attacks.append(attack)
            send_sse("attack_result", {"index": i, "result": attack})

            if verification:
                verifications.append(verification)
                send_sse("verification_result", {"index": i, "result": verification})
            else:
                fallback = {"target_id": target_id, "verdict": "inconclusive", "severity": "NONE", "evidence": "Verifier produced no parseable output"}
                verifications.append(fallback)
                send_sse("verification_result", {"index": i, "result": fallback})

            # Save partial results
            try:
                os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
                import datetime as _dt
                partial_record = {
                    "id": f"juiceshop_{test_name}_latest",
                    "test": test_name,
                    "project": "juiceshop",
                    "timestamp": _dt.datetime.now().isoformat(),
                    "partial": True,
                    "completed_targets": i + 1,
                    "elapsed": round(_time.time() - start, 1),
                    "targets": len(targets),
                    "confirmed": sum(1 for v in verifications if v.get("verdict") == "confirmed_vulnerability"),
                    "hardening": sum(1 for a in attacks if a.get("classification") == "hardening_recommendation"),
                    "reachable": sum(1 for a in attacks if a.get("reachable")),
                    "all_targets": targets,
                    "all_attacks": attacks,
                    "all_verifications": verifications,
                    "usage": total_usage,
                }
                with open(os.path.join(SCAN_RESULTS_DIR, f"juiceshop_{test_name}_latest.json"), "w") as sf:
                    json.dump(partial_record, sf, indent=2, default=str)
            except Exception:
                pass

        # Phase completion
        send_sse("phase", {"agent": "attacker", "status": "done", "reachable": sum(1 for a in attacks if a.get("reachable"))})
        send_sse("phase", {"agent": "verifier", "status": "done"})

        # ─── FINAL REPORT ───────────────────────────────────────────
        elapsed = round(_time.time() - start, 1)
        confirmed = [v for v in verifications if v.get("verdict") == "confirmed_vulnerability"]
        hardening = [a for a in attacks if a.get("classification") == "hardening_recommendation"]
        reachable = [a for a in attacks if a.get("reachable")]

        total_input_all = total_usage["input_tokens"]
        cache_hit_pct = (total_usage["cache_read_tokens"] / total_input_all * 100) if total_input_all > 0 else 0
        total_usage["cache_hit_pct"] = round(cache_hit_pct, 1)
        total_usage["cost_usd"] = round(total_usage["cost_usd"], 4)

        done_payload = {
            "elapsed": elapsed,
            "targets": len(targets),
            "reachable": len(reachable),
            "confirmed": len(confirmed),
            "hardening": len(hardening),
            "findings": confirmed,
            "recommendations": hardening,
            "all_targets": targets,
            "all_attacks": attacks,
            "all_verifications": verifications,
            "usage": total_usage,
        }
        send_sse("done", done_payload)

        # Persist scan result
        try:
            os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
            import datetime as _dt
            scan_id = f"juiceshop_{test_name}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_record = {"id": scan_id, "test": test_name, "project": "juiceshop", "timestamp": _dt.datetime.now().isoformat(), **done_payload}
            with open(os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json"), "w") as sf:
                json.dump(scan_record, sf, indent=2, default=str)
            partial_path = os.path.join(SCAN_RESULTS_DIR, f"juiceshop_{test_name}_latest.json")
            if os.path.exists(partial_path):
                os.unlink(partial_path)
            send_sse("status", {"message": f"Scan saved: {scan_id}"})
            # Auto-label attack targets in Neo4j
            try:
                rows = []
                for t in targets:
                    tid = t.get("id", "")
                    priority = t.get("priority", "")
                    angle = t.get("attack_angle", "")
                    for role, nk in [("source", "source_node"), ("control", "control_point"), ("sink", "sink_node")]:
                        node = t.get(nk, {})
                        if not isinstance(node, dict):
                            continue
                        nid = node.get("fid", "") or node.get("id", "")
                        if not nid or nid == "none":
                            continue
                        fid = nid if nid.startswith(test_name) or nid.startswith("f") else f"{test_name}_{nid}"
                        rows.append({"fid": fid, "role": role, "tid": tid, "priority": priority, "angle": angle, "name": node.get("display_name", "") or node.get("name", ""), "file": node.get("file", "")})
                if rows:
                    self._load_juiceshop_to_neo4j(test_name)
                    self._restore_targets_neo4j(test_name, rows, targets, project="juiceshop")
            except Exception:
                pass
        except Exception as e:
            send_sse("status", {"message": f"Warning: could not save scan results: {e}"})

    def _get_juiceshop_batch_status(self):
        """Return current batch scan progress from disk with computed summary."""
        batch_path = os.path.join(SCAN_RESULTS_DIR, "juiceshop_batch_progress.json")
        if not os.path.exists(batch_path):
            return {"status": "not_started"}
        with open(batch_path) as f:
            state = json.load(f)

        # Compute summary
        completed = len(state.get("completed_tests", []))
        skipped = len(state.get("skipped_tests", []))
        total = state.get("total_tests", 0)
        confirmed = len(state.get("all_confirmed", []))
        hardening = len(state.get("all_hardening", []))

        # Current test progress
        current_test = None
        current_targets_total = 0
        current_targets_done = 0
        test_progress = state.get("test_progress", {})
        for test_name, tp in test_progress.items():
            if test_name not in state.get("completed_tests", []):
                current_test = test_name
                current_targets_total = len(tp.get("targets", []))
                current_targets_done = len(tp.get("completed_target_ids", []))
                break

        state["_summary"] = {
            "total_tests": total,
            "completed_tests": completed,
            "skipped_tests": skipped,
            "remaining_tests": total - completed - skipped,
            "confirmed_vulnerabilities": confirmed,
            "hardening_recommendations": hardening,
            "current_test": current_test,
            "current_test_targets_total": current_targets_total,
            "current_test_targets_done": current_targets_done,
            "usage": state.get("total_usage", {}),
        }
        return state

    def _run_juiceshop_vuln_scan_all(self, subset="", count=""):
        """Run the 3-agent scan on ALL (or a subset of) Juice Shop tests sequentially via SSE."""
        send_sse = self._make_sse_sender()

        import threading

        scan_done = threading.Event()

        def keepalive():
            wfile = self.wfile
            while not scan_done.is_set():
                scan_done.wait(timeout=15)
                if not scan_done.is_set():
                    try:
                        wfile.write(b": keepalive\n\n")
                        wfile.flush()
                    except Exception:
                        break

        def run_in_thread():
            try:
                self._juiceshop_batch_scan_inner(send_sse, subset=subset, count=count)
            except Exception as e:
                send_sse("error", {"message": str(e)})
            finally:
                scan_done.set()

        ka = threading.Thread(target=keepalive, daemon=True)
        ka.start()
        t = threading.Thread(target=run_in_thread, daemon=False)
        t.start()
        # Wait for completion — the non-daemon thread survives if SSE connection drops
        t.join()
        scan_done.set()

    def _juiceshop_batch_scan_inner(self, send_sse, subset="", count=""):
        """Run vuln scan on all (or subset of) Juice Shop tests, persisting results after each."""
        import time as _time
        import subprocess as _subprocess
        import tempfile as _tempfile
        import random as _random
        from neo4j import GraphDatabase as _GD
        from strands import Agent as _Agent, tool as _tool
        from strands.models.bedrock import BedrockModel as _BM, CacheConfig as _CC
        from strands.multiagent.graph import GraphBuilder

        from scan_juiceshop_planner import SYSTEM_PROMPT as PLANNER_SYSTEM
        from scan_juiceshop_attacker import SYSTEM_PROMPT as ATTACKER_SYSTEM
        from scan_juiceshop_verifier import SYSTEM_PROMPT as VERIFIER_SYSTEM

        NEO4J_URI = NEO4J_JUICESHOP_URI
        MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-6-v1")
        JUICESHOP_ROOT = os.path.join(BENCH_DIR, "juiceshop_source")

        # Get all test names
        traces_dir = os.path.join(BENCH_DIR, "juiceshop_raw_traces")
        all_tests = sorted([f.replace('.json', '') for f in os.listdir(traces_dir) if f.endswith('.json')])

        # Apply subset filter if provided
        if subset:
            subset_names = [s.strip() for s in subset.split(",") if s.strip()]
            all_tests = [t for t in all_tests if t in subset_names]
        elif count:
            try:
                n = int(count)
                _random.seed(42)
                # Stratified sample: pick from different suites
                suite_map = {}
                for t in all_tests:
                    suite = t.split("__")[0] if "__" in t else "other"
                    suite_map.setdefault(suite, []).append(t)
                selected = []
                # Round-robin from each suite
                suite_lists = list(suite_map.values())
                _random.shuffle(suite_lists)
                for sl in suite_lists:
                    _random.shuffle(sl)
                idx = 0
                while len(selected) < n and idx < max(len(sl) for sl in suite_lists):
                    for sl in suite_lists:
                        if idx < len(sl) and len(selected) < n:
                            selected.append(sl[idx])
                    idx += 1
                all_tests = sorted(selected)
            except ValueError:
                pass

        # Check for resume — skip already-completed tests
        os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
        batch_path = os.path.join(SCAN_RESULTS_DIR, "juiceshop_batch_progress.json")
        if os.path.exists(batch_path):
            with open(batch_path) as f:
                batch_state = json.load(f)
        else:
            batch_state = {
                "status": "running",
                "total_tests": len(all_tests),
                "completed_tests": [],
                "skipped_tests": [],
                "all_confirmed": [],
                "all_hardening": [],
                "total_usage": {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0, "uncached_input_tokens": 0, "cost_usd": 0.0, "cycles": 0},
                "start_time": _time.time(),
            }

        completed_set = set(batch_state.get("completed_tests", []) + batch_state.get("skipped_tests", []))
        # per-test target progress: {test_name: {targets: [...], completed_target_ids: [...]}}
        test_progress = batch_state.setdefault("test_progress", {})
        remaining = [t for t in all_tests if t not in completed_set]

        send_sse("batch_start", {
            "total": len(all_tests),
            "remaining": len(remaining),
            "already_completed": len(completed_set),
        })

        batch_start = _time.time()

        for test_idx, test_name in enumerate(remaining):
            test_start = _time.time()
            send_sse("batch_test_start", {
                "test": test_name,
                "index": len(completed_set) + test_idx,
                "total": len(all_tests),
            })

            # Load test into Neo4j
            try:
                self._load_juiceshop_to_neo4j(test_name)
            except Exception as e:
                send_sse("batch_test_skip", {"test": test_name, "reason": str(e)})
                batch_state.setdefault("skipped_tests", []).append(test_name)
                self._save_batch_state(batch_state, batch_path)
                continue

            # Run planner for this test
            tool_call_counter = [0]

            def make_tool_emitter(agent_name):
                def emit_tool_call(tool_name, args, result):
                    tool_call_counter[0] += 1
                    send_sse("tool_call", {
                        "id": tool_call_counter[0],
                        "agent": agent_name,
                        "tool": tool_name,
                        "args": args,
                        "result": result[:800] if len(result) > 800 else result,
                        "result_length": len(result),
                        "test": test_name,
                    })
                return emit_tool_call

            planner_emit = make_tool_emitter("planner")

            @_tool
            def query_graph_plan(cypher_query: str) -> str:
                """Execute a Cypher query against the Neo4j JuiceShop graph."""
                driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
                try:
                    with driver.session() as session:
                        result = session.run(cypher_query)
                        records = [dict(r) for r in result]
                        out = json.dumps(records, indent=2, default=str)
                        planner_emit("query_graph", {"cypher": cypher_query}, out)
                        return out
                except Exception as e:
                    err = f"ERROR: {e}"
                    planner_emit("query_graph", {"cypher": cypher_query}, err)
                    return err
                finally:
                    driver.close()

            planner_prompt = f"""Analyze the Neo4j security graph to identify ALL attack targets for test '{test_name}'.

Start with these queries:
1. MATCH (n:JuiceShop {{test: '{test_name}'}}) RETURN count(n) as nodes
2. MATCH (n:JuiceShop {{test: '{test_name}'}})-[r]->(m) RETURN type(r) as rel_type, count(r) as count
3. MATCH (n:JuiceShop {{test: '{test_name}', role: 'entry_point'}}) RETURN n.name, n.file, n.tainted, n.subsystem
4. MATCH (n:JuiceShop {{test: '{test_name}', tainted: true}}) WHERE n.role IN ['db_writer', 'db_reader', 'file_handler'] RETURN n.name, n.file, n.role
5. MATCH path = (src:JuiceShop {{test: '{test_name}', role: 'entry_point'}})-[*1..4]->(sink:JuiceShop {{role: 'db_writer'}}) WHERE NOT any(x IN nodes(path) WHERE x.role = 'validator') RETURN src.name, sink.name, sink.file

Output your targets as a JSON array."""

            model_planner = _BM(model_id=MODEL_ID, region_name=os.environ.get("AWS_REGION", "us-east-1"), max_tokens=8192, cache_config=_CC(strategy="auto"))
            model_agents = _BM(model_id=MODEL_ID, region_name=os.environ.get("AWS_REGION", "us-east-1"), max_tokens=16384, cache_config=_CC(strategy="auto"))

            planner = _Agent(model=model_planner, tools=[query_graph_plan], system_prompt=PLANNER_SYSTEM)

            def planner_callback(**kwargs):
                data = kwargs.get("data", "")
                if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                    send_sse("thinking", {"agent": "planner", "text": data, "test": test_name})

            planner.callback_handler = planner_callback

            # Check if we have saved planner results for this test (resume mid-test)
            if test_name in test_progress and test_progress[test_name].get("targets"):
                targets = test_progress[test_name]["targets"]
                send_sse("batch_test_targets", {"test": test_name, "targets": len(targets), "resumed": True})
            else:
                try:
                    planner_result = planner(planner_prompt)
                    planner_text = str(planner_result)
                    targets = _parse_json_from_text(planner_text, '[') or []
                except Exception as e:
                    send_sse("batch_test_skip", {"test": test_name, "reason": f"Planner error: {e}"})
                    batch_state.setdefault("skipped_tests", []).append(test_name)
                    self._save_batch_state(batch_state, batch_path)
                    continue

                planner_usage = _extract_usage_metrics(planner_result)
                for k in batch_state["total_usage"]:
                    batch_state["total_usage"][k] += planner_usage.get(k, 0)

                # Checkpoint planner results
                test_progress[test_name] = {"targets": targets, "completed_target_ids": []}
                self._save_batch_state(batch_state, batch_path)
                send_sse("batch_test_targets", {"test": test_name, "targets": len(targets)})

            if not targets:
                batch_state.setdefault("completed_tests", []).append(test_name)
                self._save_batch_state(batch_state, batch_path)
                send_sse("batch_test_done", {"test": test_name, "confirmed": 0, "elapsed": round(_time.time() - test_start, 1)})
                continue

            # Run attacker↔verifier for each target (skip already-completed targets)
            completed_target_ids = set(test_progress.get(test_name, {}).get("completed_target_ids", []))
            test_confirmed = []
            test_hardening = []

            for ti, target in enumerate(targets):
                target_id = target.get("id", f"{test_name}_t{ti}")
                if target_id in completed_target_ids:
                    continue
                atk_emit = make_tool_emitter("attacker")
                ver_emit = make_tool_emitter("verifier")

                @_tool
                def read_source_atk(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
                    """Read Juice Shop source code (e.g. 'routes/login.ts')."""
                    full_path = os.path.join(JUICESHOP_ROOT, file_path)
                    if not os.path.exists(full_path):
                        err = f"ERROR: File not found: {file_path}"
                        atk_emit("read_source", {"file": file_path}, err)
                        return err
                    with open(full_path) as f:
                        lines = f.readlines()
                    if start_line > 0 and end_line > 0:
                        selected = lines[start_line-1:end_line]
                        header = f"[{file_path}:{start_line}-{end_line}]\n"
                    else:
                        selected = lines[:300]
                        header = f"[{file_path} ({len(lines)} lines)]\n"
                    out = header + ''.join(f"{ln+1:4d}  {l}" for ln, l in enumerate(selected))
                    atk_emit("read_source", {"file": file_path}, out)
                    return out

                @_tool
                def grep_source_atk(pattern: str, path: str = "routes") -> str:
                    """Search Juice Shop source for a pattern."""
                    full_path = os.path.join(JUICESHOP_ROOT, path)
                    try:
                        result = _subprocess.run(['grep', '-rn', '-P', pattern, full_path], capture_output=True, text=True, timeout=10)
                        output = result.stdout.replace(JUICESHOP_ROOT + '/', '')
                        lines = output.strip().split('\n')
                        if len(lines) > 50:
                            lines = lines[:50]
                        out = '\n'.join(lines) if lines[0] else "No matches."
                        atk_emit("grep_source", {"pattern": pattern, "path": path}, out)
                        return out
                    except Exception as e:
                        err = f"ERROR: {e}"
                        atk_emit("grep_source", {"pattern": pattern}, err)
                        return err

                @_tool
                def query_graph_atk(cypher_query: str) -> str:
                    """Execute Cypher query against Neo4j."""
                    driver = _GD.driver(NEO4J_URI, auth=NEO4J_AUTH)
                    try:
                        with driver.session() as session:
                            result = session.run(cypher_query)
                            records = [dict(r) for r in result]
                            out = json.dumps(records, indent=2, default=str)
                            atk_emit("query_graph", {"cypher": cypher_query}, out)
                            return out
                    except Exception as e:
                        err = f"ERROR: {e}"
                        atk_emit("query_graph", {"cypher": cypher_query}, err)
                        return err
                    finally:
                        driver.close()

                def _execute_code_b(code):
                    with _tempfile.NamedTemporaryFile(mode='w', suffix='.py', dir=BENCH_DIR, delete=False, prefix='jbatch_') as f:
                        f.write(code)
                        tf = f.name
                    try:
                        r = _subprocess.run([sys.executable, tf], capture_output=True, text=True, timeout=60, cwd=BENCH_DIR, env=os.environ.copy())
                        output = r.stdout + r.stderr
                        if len(output) > 4000:
                            output = output[:2000] + "\n...[truncated]...\n" + output[-2000:]
                        status = "PASSED" if r.returncode == 0 else "FAILED"
                        return r.returncode, f"TEST {status} (exit code {r.returncode})\n\n{output}"
                    except _subprocess.TimeoutExpired:
                        return 1, "TEST TIMEOUT (>60s)"
                    finally:
                        os.unlink(tf)

                @_tool
                def write_test(test_code: str) -> str:
                    """Write and execute a Python test script. Call this once with the complete test."""
                    exit_code, out = _execute_code_b(test_code)
                    ver_emit("run_test", {"code_length": len(test_code)}, out)
                    return out

                @_tool
                def fix_test(fix_description: str, fixed_code: str) -> str:
                    """Fix ONLY the error in the previous test. Do not change the logic or add new functionality."""
                    exit_code, out = _execute_code_b(fixed_code)
                    ver_emit("fix_test", {"fix": fix_description, "code_length": len(fixed_code)}, out)
                    return out


                @_tool
                def read_source_ver(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
                    """Read Juice Shop source to verify claims."""
                    full_path = os.path.join(JUICESHOP_ROOT, file_path)
                    if not os.path.exists(full_path):
                        err = f"ERROR: File not found: {file_path}"
                        ver_emit("read_source", {"file": file_path}, err)
                        return err
                    with open(full_path) as f:
                        lines = f.readlines()
                    if start_line > 0 and end_line > 0:
                        selected = lines[start_line-1:end_line]
                        header = f"[{file_path}:{start_line}-{end_line}]\n"
                    else:
                        selected = lines[:200]
                        header = f"[{file_path}]\n"
                    out = header + ''.join(f"{ln+1:4d}  {l}" for ln, l in enumerate(selected))
                    ver_emit("read_source", {"file": file_path}, out)
                    return out

                attacker_thinking = []
                verifier_thinking = []

                def attacker_callback(**kwargs):
                    data = kwargs.get("data", "")
                    if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                        attacker_thinking.append(data)
                        send_sse("thinking", {"agent": "attacker", "target_id": target_id, "text": data})

                def verifier_callback(**kwargs):
                    data = kwargs.get("data", "")
                    if data and "tool_use" not in str(kwargs.get("current_tool_use", {})):
                        verifier_thinking.append(data)
                        send_sse("thinking", {"agent": "verifier", "target_id": target_id, "text": data})

                attacker_agent = _Agent(model=model_agents, tools=[read_source_atk, grep_source_atk, query_graph_atk], system_prompt=ATTACKER_SYSTEM)
                attacker_agent.callback_handler = attacker_callback
                verifier_hook_b = LockAfterSuccess()
                verifier_agent = _Agent(model=model_agents, tools=[write_test, fix_test], system_prompt=VERIFIER_SYSTEM, hooks=[verifier_hook_b])
                verifier_agent.callback_handler = verifier_callback

                builder = GraphBuilder()
                builder.add_node(attacker_agent, "attacker")
                builder.add_node(verifier_agent, "verifier")
                builder.add_edge("attacker", "verifier")
                builder.set_entry_point("attacker")
                builder.set_node_timeout(900.0)
                target_graph = builder.build()

                task_prompt = f"""Analyze this attack target in OWASP Juice Shop:

{json.dumps(target, indent=2)}

Read the source code. Determine reachability. Output JSON."""

                try:
                    graph_result = target_graph(task_prompt)

                    graph_usage = graph_result.accumulated_usage
                    input_tokens = graph_usage.get("inputTokens", 0)
                    output_tokens = graph_usage.get("outputTokens", 0)
                    cache_read = graph_usage.get("cacheReadInputTokens", 0)
                    cache_write = graph_usage.get("cacheWriteInputTokens", 0)
                    cost = (input_tokens * 3.0 + output_tokens * 15.0 + cache_read * 0.30 + cache_write * 3.75) / 1_000_000
                    batch_state["total_usage"]["input_tokens"] += input_tokens + cache_read + cache_write
                    batch_state["total_usage"]["output_tokens"] += output_tokens
                    batch_state["total_usage"]["cache_read_tokens"] += cache_read
                    batch_state["total_usage"]["cache_write_tokens"] += cache_write
                    batch_state["total_usage"]["uncached_input_tokens"] += input_tokens
                    batch_state["total_usage"]["cost_usd"] += cost
                    batch_state["total_usage"]["cycles"] += graph_result.execution_count

                    atk_result_node = graph_result.results.get("attacker")
                    atk_text = str(atk_result_node.result) if atk_result_node else ""
                    attack = _parse_json_from_text(atk_text) or {"target_id": target_id, "reachable": False, "classification": "error"}

                    ver_result_node = graph_result.results.get("verifier")
                    ver_text = str(ver_result_node.result) if ver_result_node else ""
                    verification = _parse_json_from_text(ver_text)

                    if verification and verification.get("verdict") == "confirmed_vulnerability":
                        finding = {
                            "test": test_name,
                            "target_id": target_id,
                            "target": target,
                            "attack": attack,
                            "verification": verification,
                        }
                        test_confirmed.append(finding)
                        batch_state["all_confirmed"].append(finding)
                        send_sse("batch_confirmed", {"test": test_name, "target_id": target_id, "finding": finding})

                    if attack.get("classification") == "hardening_recommendation":
                        rec = {"test": test_name, "target_id": target_id, "target": target, "attack": attack}
                        test_hardening.append(rec)
                        batch_state["all_hardening"].append(rec)

                except Exception as e:
                    send_sse("batch_target_error", {"test": test_name, "target_id": target_id, "error": str(e)})

                # Checkpoint after each target
                test_progress.setdefault(test_name, {}).setdefault("completed_target_ids", []).append(target_id)
                self._save_batch_state(batch_state, batch_path)
                send_sse("batch_target_done", {
                    "test": test_name,
                    "target_id": target_id,
                    "target_index": ti + 1,
                    "targets_total": len(targets),
                })

            # Test complete — all targets processed
            batch_state.setdefault("completed_tests", []).append(test_name)
            # Clean up per-test progress since test is done
            test_progress.pop(test_name, None)
            self._save_batch_state(batch_state, batch_path)

            send_sse("batch_test_done", {
                "test": test_name,
                "targets": len(targets),
                "confirmed": len(test_confirmed),
                "hardening": len(test_hardening),
                "elapsed": round(_time.time() - test_start, 1),
                "total_confirmed_so_far": len(batch_state["all_confirmed"]),
                "tests_remaining": len(all_tests) - len(batch_state["completed_tests"]) - len(batch_state.get("skipped_tests", [])),
            })

        # ─── ALL DONE ───
        batch_state["status"] = "complete"
        batch_state["elapsed"] = round(_time.time() - batch_start, 1)
        batch_state["total_usage"]["cost_usd"] = round(batch_state["total_usage"]["cost_usd"], 4)
        total_in = batch_state["total_usage"]["input_tokens"]
        batch_state["total_usage"]["cache_hit_pct"] = round((batch_state["total_usage"]["cache_read_tokens"] / total_in * 100) if total_in > 0 else 0, 1)
        self._save_batch_state(batch_state, batch_path)

        send_sse("batch_done", {
            "total_tests": len(all_tests),
            "completed": len(batch_state["completed_tests"]),
            "skipped": len(batch_state.get("skipped_tests", [])),
            "confirmed_vulnerabilities": len(batch_state["all_confirmed"]),
            "hardening_recommendations": len(batch_state["all_hardening"]),
            "elapsed": batch_state["elapsed"],
            "usage": batch_state["total_usage"],
            "findings": batch_state["all_confirmed"],
        })

    def _save_batch_state(self, state, path):
        with open(path, 'w') as f:
            json.dump(state, f, indent=2, default=str)



def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"OWASP Juice Shop Security Analysis UI at http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
