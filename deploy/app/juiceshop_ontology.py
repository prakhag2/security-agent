"""
Deterministic security ontology engine for OWASP Juice Shop.

Assigns roles, trust levels, data flows, and relationships based on:
1. Source pattern analysis (Express/Sequelize/JWT patterns)
2. File path (which Juice Shop subsystem)
3. Call graph position (parent/child/leaf)
4. Trace data (actual values that flowed at runtime)

Analogous to ontology.py for Django, adapted for Node.js/Express/TypeScript.
"""

import json
import os
import re
from collections import defaultdict

JUICESHOP_ROOT = os.environ.get("JUICESHOP_ROOT", "juice-shop")


# ─── SOURCE PATTERN DETECTION ─────────────────────────────────────────────────

class SourcePatterns:
    """
    Detect what a function does by scanning its source.
    Since we don't have full TS AST here, we use the trace data
    (function names, file paths, input/output values) as primary signal.
    """

    def __init__(self, func_name, file_path, inputs=None, output=None):
        self.patterns = set()
        self.reads_from = set()
        self.writes_to = set()

        self._from_func_name(func_name, file_path)
        self._from_inputs(inputs or {})
        self._from_output(output)

    def _from_func_name(self, func_name, file_path):
        fn = func_name.lower()
        fp = file_path.lower()

        # JWT operations
        if 'jwt' in fn or 'token' in fn or 'jwt' in fp:
            self.patterns.add('jwt_op')
        if 'verify' in fn and ('jwt' in fp or 'token' in fn):
            self.patterns.add('jwt_verify')
        if 'sign' in fn or 'encode' in fn:
            self.patterns.add('jwt_sign')

        # Auth/login
        if 'login' in fn or 'authenticate' in fn:
            self.patterns.add('auth_op')
        if 'password' in fn or 'hash' in fn or 'bcrypt' in fn:
            self.patterns.add('crypto_op')
        if 'publickey' in fn or 'privatekey' in fn or 'rsa' in fn:
            self.patterns.add('crypto_op')

        # SQL/DB
        if 'sequelize' in fp or 'model' in fp:
            self.patterns.add('db_op')
        if 'findone' in fn or 'findall' in fn or 'findbyid' in fn:
            self.patterns.add('db_read')
        if 'create' in fn or 'save' in fn or 'update' in fn or 'destroy' in fn:
            self.patterns.add('db_write')

        # Input reading (Express req)
        if 'jwtfrom' in fn:
            self.reads_from.add('http_header')
            self.patterns.add('reads_auth_header')
        if fn in ('handler', 'middleware') or fn.startswith('_ret'):
            if 'routes/' in fp:
                self.patterns.add('route_handler')

        # File I/O
        if 'file' in fn or 'upload' in fn or 'write' in fn or 'read' in fn:
            if 'file' in fp or 'upload' in fp:
                self.patterns.add('file_op')
        if 'angular' in fp and 'routes/' in fp:
            self.patterns.add('file_op')
        if 'serve' in fn or 'sendfile' in fn:
            self.patterns.add('file_op')

        # Challenge/gamification (Juice Shop specific)
        if 'challenge' in fn or 'solve' in fn:
            self.patterns.add('challenge_op')
        if 'anticheat' in fp or 'accuracy' in fp:
            self.patterns.add('challenge_op')

        # Insecurity module (intentionally vulnerable)
        if 'insecurity' in fp:
            self.patterns.add('insecurity_module')
            if 'authorize' in fn or 'isauthorized' in fn:
                self.patterns.add('authz_check')
            if 'isaccounting' in fn:
                self.patterns.add('authz_check')

        # Validation
        if 'valid' in fn or 'check' in fn or 'sanitiz' in fn:
            self.patterns.add('validation_op')

        # Utils
        if 'utils' in fp:
            self.patterns.add('utility')

    def _from_inputs(self, inputs):
        if not isinstance(inputs, dict):
            return

        # Check if input contains HTTP request
        req = inputs.get('req')
        if isinstance(req, dict) and req.get('__type') == 'Request':
            self.reads_from.add('http_request')
            self.patterns.add('receives_request')
            if req.get('body'):
                self.reads_from.add('request_body')
                self.patterns.add('reads_body')
            if req.get('query') and req['query'] != {}:
                self.reads_from.add('query_params')
                self.patterns.add('reads_query')
            if req.get('params') and req['params'] != {}:
                self.reads_from.add('url_params')
                self.patterns.add('reads_params')
            headers = req.get('headers', {})
            if headers.get('authorization'):
                self.reads_from.add('auth_header')
                self.patterns.add('reads_auth_header')

        # Express middleware pattern: (res, next) without req
        res = inputs.get('res')
        if isinstance(res, dict) and res.get('__type') == 'Response' and 'next' in inputs:
            self.patterns.add('middleware_callback')

        # Check for token/password in inputs
        for key, val in inputs.items():
            if key in ('token', 'jwt', 'authorization'):
                self.reads_from.add('auth_token')
                self.patterns.add('handles_token')
            if key in ('password', 'passwd', 'secret'):
                self.reads_from.add('password')
                self.patterns.add('handles_password')
            if key in ('email', 'username', 'user'):
                self.reads_from.add('user_identifier')

    def _from_output(self, output):
        if not output:
            return
        out_s = str(output).lower()
        if 'eyj' in out_s[:10]:  # JWT token prefix
            self.writes_to.add('jwt_token')
            self.patterns.add('produces_jwt')
        if 'begin rsa' in out_s or 'begin public' in out_s:
            self.patterns.add('crypto_op')
        if output == 'True' or output == 'False' or output is True or output is False:
            self.patterns.add('boolean_gate')


# ─── FILE PATH → SUBSYSTEM ───────────────────────────────────────────────────

def get_subsystem(file_path):
    """Determine which Juice Shop subsystem a file belongs to."""
    if not file_path:
        return 'unknown'
    fp = file_path.lower()

    if 'insecurity' in fp:
        return 'auth_security'
    if 'verify' in fp and 'routes/' in fp:
        return 'auth_verification'
    if '2fa' in fp:
        return 'auth_2fa'
    if 'login' in fp:
        return 'auth_login'
    if 'user' in fp and 'routes/' in fp:
        return 'user_management'
    if 'basket' in fp or 'order' in fp or 'payment' in fp or 'wallet' in fp:
        return 'commerce'
    if 'file' in fp or 'upload' in fp or 'angular' in fp or 'export' in fp or 'erasure' in fp:
        return 'file_handling'
    if 'search' in fp:
        return 'search'
    if 'redirect' in fp:
        return 'redirect'
    if 'chat' in fp or 'complaint' in fp or 'feedback' in fp:
        return 'user_content'
    if 'challenge' in fp or 'accuracy' in fp or 'anticheat' in fp:
        return 'gamification'
    if 'utils' in fp:
        return 'utility'
    if 'metrics' in fp:
        return 'observability'
    if 'routes/' in fp:
        return 'route_handler'
    if 'lib/' in fp:
        return 'library'

    return 'other'


# ─── ROLE CLASSIFICATION ─────────────────────────────────────────────────────

def classify_role(patterns, subsystem, num_children, has_parent, func_name):
    """
    Assign role based on what the function does.

    Role vocabulary (same as Django ontology):
    - input_reader:    reads from user-controlled source (req.body, req.query, headers)
    - orchestrator:    calls multiple children, primary work is delegation
    - gate:            returns boolean, controlling caller's flow
    - validator:       checks conditions (authorization, validation)
    - jwt_handler:     JWT sign/verify operations
    - crypto:          password hashing, key operations
    - db_reader:       database read
    - db_writer:       database write
    - file_handler:    file system operations
    - entry_point:     route handler (top-level, receives HTTP request)
    - challenge_op:    gamification/challenge logic
    - leaf:            no children, no strong patterns
    - operation:       fallback
    """
    p = patterns.patterns

    # Priority 1: Route handler receiving HTTP request
    if 'receives_request' in p and not has_parent:
        return 'entry_point'
    if 'receives_request' in p and 'route_handler' in p:
        return 'entry_point'

    # Priority 2: Auth/JWT operations
    if 'jwt_verify' in p:
        return 'validator'
    if 'jwt_sign' in p or 'produces_jwt' in p:
        return 'jwt_handler'
    if 'authz_check' in p:
        return 'validator'

    # Priority 3: Crypto
    if 'crypto_op' in p:
        return 'crypto'
    if 'handles_password' in p and subsystem == 'auth_security':
        return 'crypto'

    # Priority 4: DB operations
    if 'db_write' in p:
        return 'db_writer'
    if 'db_read' in p:
        return 'db_reader'
    if 'db_op' in p:
        return 'db_reader'

    # Priority 5: Input reader (reads body/params/query but doesn't have request directly)
    if ('reads_body' in p or 'reads_query' in p or 'reads_params' in p) and has_parent:
        return 'input_reader'
    if 'reads_auth_header' in p:
        return 'input_reader'
    if 'middleware_callback' in p and 'route_handler' in p and has_parent:
        return 'input_reader'

    # Priority 6: File operations
    if 'file_op' in p:
        return 'file_handler'

    # Priority 7: Validation
    if 'validation_op' in p:
        return 'validator'
    if 'boolean_gate' in p and num_children == 0:
        return 'gate'

    # Priority 8: Challenge/gamification
    if 'challenge_op' in p:
        return 'challenge_op'

    # Priority 9: Structural
    if not has_parent and num_children > 0:
        if 'route_handler' in p or 'receives_request' in p or 'middleware_callback' in p:
            return 'entry_point'
        return 'orchestrator'
    if num_children >= 3:
        return 'orchestrator'

    # Leaf or generic
    if not num_children:
        return 'leaf'

    return 'operation'


# ─── TRUST CLASSIFICATION ────────────────────────────────────────────────────

def classify_trust(role, patterns, subsystem):
    """Trust level based on what data the function handles."""
    if role == 'input_reader':
        return 'user_controlled'
    if role == 'entry_point' and 'receives_request' in patterns.patterns:
        return 'user_controlled'
    if 'handles_token' in patterns.patterns or 'handles_password' in patterns.patterns:
        return 'privileged'
    if subsystem == 'auth_security':
        return 'privileged'
    if 'crypto_op' in patterns.patterns:
        return 'privileged'
    return 'framework_internal'


# ─── SENSITIVITY CLASSIFICATION ──────────────────────────────────────────────

def classify_sensitivity(role, patterns, subsystem):
    """What kind of sensitive data this function handles."""
    if role == 'jwt_handler' or 'produces_jwt' in patterns.patterns:
        return 'auth_token'
    if role == 'crypto':
        return 'credential'
    if 'handles_password' in patterns.patterns:
        return 'credential'
    if 'handles_token' in patterns.patterns:
        return 'auth_token'
    if role in ('db_reader', 'db_writer'):
        return 'user_record'
    if role == 'input_reader':
        return 'user_input'
    if role == 'file_handler':
        return 'file_data'
    if subsystem == 'commerce':
        return 'financial'
    return 'none'


# ─── DATA FLOW ANALYSIS ─────────────────────────────────────────────────────

def build_data_flows(trace_entries):
    """
    Build data flow edges from parent-child trace relationships.

    Rules:
    1. Parent input flows to child if matching values found
    2. Sibling output → next sibling input (data chain)
    3. Child output == parent output (return propagation)
    """
    flows = []
    entry_by_id = {e['id']: e for e in trace_entries}

    children_of = defaultdict(list)
    for e in trace_entries:
        if e.get('parent'):
            children_of[e['parent']].append(e['id'])

    for entry in trace_entries:
        eid = entry['id']
        children = children_of.get(eid, [])
        if not children:
            continue

        parent_input = entry.get('input', {})
        parent_output = str(entry.get('output', ''))
        if not isinstance(parent_input, dict):
            parent_input = {}

        prev_output = None
        prev_id = None

        for child_id in children:
            child = entry_by_id.get(child_id)
            if not child:
                continue
            child_input = child.get('input', {})
            if not isinstance(child_input, dict):
                child_input = {}
            child_output = str(child.get('output', ''))

            # Rule 1: Value match parent input → child input
            for ck, cv in child_input.items():
                cv_s = str(cv)
                if not cv_s or cv_s in ('None', '{}', '[]', '""', "''", 'null', 'undefined'):
                    continue
                for pk, pv in parent_input.items():
                    pv_s = str(pv)
                    if pv_s and len(pv_s) > 2 and cv_s == pv_s:
                        flows.append({
                            'from': eid, 'to': child_id,
                            'data': pk, 'mechanism': 'argument_pass',
                        })

            # Rule 2: Previous sibling output → current input
            if prev_output and prev_output not in ('', 'None', 'True', 'False', 'null', '<void>'):
                for ck, cv in child_input.items():
                    cv_s = str(cv)
                    if cv_s == prev_output or (len(prev_output) > 5 and prev_output in cv_s):
                        flows.append({
                            'from': prev_id, 'to': child_id,
                            'data': ck, 'mechanism': 'sibling_chain',
                        })

            # Rule 3: Child output propagates up
            if child_output and parent_output and child_output == parent_output:
                flows.append({
                    'from': child_id, 'to': eid,
                    'data': 'return_value', 'mechanism': 'return_propagation',
                })

            prev_output = child_output
            prev_id = child_id

    # Deduplicate
    seen = set()
    unique = []
    for f in flows:
        key = (f['from'], f['to'], f['data'])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ─── TAINT PROPAGATION ───────────────────────────────────────────────────────

def propagate_taint(enriched_entries, data_flows):
    """
    Propagate taint from user-controlled inputs through the call graph.

    Source: entry_point + input_reader nodes
    Stops at: db_reader output, crypto output, jwt_handler output

    Two propagation mechanisms:
    1. Data flows (value-matched argument passing, return propagation)
    2. Structural (parent→child via call tree — JS closures access parent scope)
    """
    by_id = {e['id']: e for e in enriched_entries}
    output_clean_roles = {'db_reader', 'db_writer', 'crypto', 'jwt_handler'}

    # Build parent→children map
    children_of = defaultdict(list)
    for e in enriched_entries:
        if e.get('parent'):
            children_of[e['parent']].append(e['id'])

    tainted = set()
    for e in enriched_entries:
        if e['trust_level'] == 'user_controlled':
            tainted.add(e['id'])

    # Heuristic: top-level async callbacks in the same file as a tainted entry_point
    # inherit taint (they're promise/callback continuations that lost parent in trace)
    tainted_files = set()
    for e in enriched_entries:
        if e['id'] in tainted and e['role'] == 'entry_point':
            tainted_files.add(e.get('file', ''))
    for e in enriched_entries:
        if (e.get('parent') is None and e['id'] not in tainted
                and e.get('file', '') in tainted_files
                and 'receives_request' not in e.get('patterns', [])):
            tainted.add(e['id'])

    changed = True
    iterations = 0
    while changed and iterations < 30:
        changed = False
        iterations += 1

        # Propagate via data flows
        for flow in data_flows:
            src, dst = flow['from'], flow['to']
            if src in tainted and dst not in tainted:
                dst_entry = by_id.get(dst)
                if dst_entry and dst_entry['role'] not in output_clean_roles:
                    tainted.add(dst)
                    changed = True

        # Propagate structurally: tainted parent → direct children
        # Conditions for structural taint:
        # 1. Same file = closure scope access (child reads parent locals)
        # 2. Cross-file child with non-empty input (data explicitly passed)
        for e in enriched_entries:
            if e['id'] in tainted and e['role'] not in output_clean_roles:
                parent_file = e.get('file', '')
                for child_id in children_of.get(e['id'], []):
                    if child_id not in tainted:
                        child = by_id.get(child_id)
                        if not child or child['role'] in output_clean_roles:
                            continue
                        child_file = child.get('file', '')
                        child_input = child.get('input', {})
                        has_explicit_args = (
                            isinstance(child_input, dict) and len(child_input) > 0
                        )
                        if child_file == parent_file or has_explicit_args:
                            tainted.add(child_id)
                            changed = True

    for flow in data_flows:
        flow['tainted'] = flow['from'] in tainted

    return tainted


# ─── RELATIONSHIP DETECTION ──────────────────────────────────────────────────

def _display_name(entry, entries_by_id=None):
    """Get a useful display name for an entry, avoiding bare <anonymous> and synthetic _retN/_anonN."""
    func = entry.get('func', '?')
    file_path = entry.get('file', '')
    base = file_path.split('/')[-1] if file_path else ''
    is_synthetic = func in ('<anonymous>', 'get', '?') or re.match(r'^_ret\d+$|^_anon\d+$', func)
    if not is_synthetic:
        return func
    # Walk up to find nearest named parent
    parent_name = None
    if entries_by_id:
        pid = entry.get('parent')
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
    role = entry.get('role', '')
    role_str = f" ({role})" if role and role != 'unknown' else ''
    if parent_name:
        return f"{base} → {parent_name}{role_str}"
    return f"{base}{role_str}" if base else func


def detect_relationships(enriched_entries):
    """
    Detect security relationships from structure.

    - VALIDATES: validator child before other operations
    - GATES: boolean gate controlling subsequent flow
    - PRODUCES_TOKEN: jwt_handler producing auth tokens
    - ACCESSES_DATA: db operations on user records
    """
    by_id = {e['id']: e for e in enriched_entries}
    children_of = defaultdict(list)
    for e in enriched_entries:
        if e.get('parent'):
            children_of[e['parent']].append(e['id'])

    relationships = []

    for entry in enriched_entries:
        eid = entry['id']
        children = children_of.get(eid, [])
        if not children:
            continue

        entry_name = _display_name(entry)
        for i, child_id in enumerate(children):
            child = by_id.get(child_id)
            if not child:
                continue

            child_name = _display_name(child)

            if child['role'] == 'validator' and i < len(children) - 1:
                relationships.append({
                    'type': 'VALIDATES',
                    'from': child_id, 'to': eid,
                    'reason': f"{child_name} validates before {entry_name} proceeds",
                })

            if child['role'] == 'gate' and i < len(children) - 1:
                relationships.append({
                    'type': 'GATES',
                    'from': child_id, 'to': eid,
                    'reason': f"{child_name} gates {entry_name}'s flow",
                })

            if child['role'] == 'jwt_handler':
                relationships.append({
                    'type': 'PRODUCES_TOKEN',
                    'from': child_id, 'to': eid,
                    'reason': f"JWT token produced within {entry_name}",
                })

            if child['role'] == 'db_reader' and child.get('tainted'):
                relationships.append({
                    'type': 'ACCESSES_DATA',
                    'from': child_id, 'to': eid,
                    'reason': f"{child_name} reads user data for {entry_name}",
                })

    return relationships


# ─── MAIN ENTRY POINT ────────────────────────────────────────────────────────

def apply_ontology(trace_entries):
    """
    Apply full deterministic ontology to a Juice Shop trace.

    Input: list of trace entries [{id, parent, depth, func, file, line, input, output, error}]
    Output: enrichment dict with roles, flows, taint, relationships
    """
    # Step 1: Pattern analysis + role classification for each entry
    children_of = defaultdict(list)
    parent_of = {}
    for e in trace_entries:
        if e.get('parent'):
            children_of[e['parent']].append(e['id'])
            parent_of[e['id']] = e['parent']

    enriched = []
    for e in trace_entries:
        patterns = SourcePatterns(
            func_name=e.get('func', ''),
            file_path=e.get('file', ''),
            inputs=e.get('input'),
            output=e.get('output'),
        )
        subsystem = get_subsystem(e.get('file', ''))
        num_children = len(children_of.get(e['id'], []))
        has_parent = e['id'] in parent_of

        role = classify_role(patterns, subsystem, num_children, has_parent, e.get('func', ''))
        trust = classify_trust(role, patterns, subsystem)
        sensitivity = classify_sensitivity(role, patterns, subsystem)

        enriched.append({
            'id': e['id'],
            'parent': e.get('parent'),
            'depth': e.get('depth', 0),
            'func': e.get('func', ''),
            'file': e.get('file', ''),
            'line': e.get('line', 0),
            'role': role,
            'trust_level': trust,
            'data_sensitivity': sensitivity,
            'subsystem': subsystem,
            'patterns': sorted(patterns.patterns),
            'reads_from': sorted(patterns.reads_from),
            'writes_to': sorted(patterns.writes_to),
            'input': e.get('input'),
            'output': e.get('output'),
            'error': e.get('error'),
        })

    # Step 2: Data flows
    data_flows = build_data_flows(trace_entries)

    # Step 3: Taint propagation
    tainted_set = propagate_taint(enriched, data_flows)

    # Step 4: Mark taint on entries
    for e in enriched:
        e['tainted'] = e['id'] in tainted_set

    # Step 5: Relationships
    relationships = detect_relationships(enriched)

    # Summary stats
    role_counts = defaultdict(int)
    trust_counts = defaultdict(int)
    for e in enriched:
        role_counts[e['role']] += 1
        trust_counts[e['trust_level']] += 1

    return {
        'entries': enriched,
        'data_flows': data_flows,
        'relationships': relationships,
        'tainted_nodes': sorted(tainted_set),
        'stats': {
            'total_entries': len(enriched),
            'roles': dict(role_counts),
            'trust_levels': dict(trust_counts),
            'tainted_count': len(tainted_set),
            'data_flow_count': len(data_flows),
            'relationship_count': len(relationships),
        },
    }


# ─── CLI TEST ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python juiceshop_ontology.py <trace_file.json>")
        sys.exit(1)

    trace_path = sys.argv[1]
    with open(trace_path) as f:
        trace = json.load(f)

    result = apply_ontology(trace)

    print(f"\n{'═' * 60}")
    print(f"  Ontology Analysis: {os.path.basename(trace_path)}")
    print(f"{'═' * 60}")
    print(f"\n  Total entries: {result['stats']['total_entries']}")
    print(f"  Tainted nodes: {result['stats']['tainted_count']}")
    print(f"  Data flows:    {result['stats']['data_flow_count']}")
    print(f"  Relationships: {result['stats']['relationship_count']}")

    print(f"\n  Roles:")
    for role, count in sorted(result['stats']['roles'].items(), key=lambda x: -x[1]):
        print(f"    {role:20s} {count:4d}")

    print(f"\n  Trust levels:")
    for level, count in sorted(result['stats']['trust_levels'].items(), key=lambda x: -x[1]):
        print(f"    {level:20s} {count:4d}")

    # Show taint propagation path
    print(f"\n  Taint sources (entry points receiving HTTP):")
    for e in result['entries']:
        if e['tainted'] and e['role'] == 'entry_point':
            print(f"    [{e['id']}] {e['file']}:{e['func']} ({e['subsystem']})")

    # Show security-relevant nodes
    print(f"\n  Security-critical nodes:")
    for e in result['entries']:
        if e['role'] in ('validator', 'jwt_handler', 'crypto', 'db_writer') and e['tainted']:
            print(f"    [{e['id']}] {e['role']:12s} {e['file']}:{e['func']} (tainted={e['tainted']})")

    # Show relationships
    if result['relationships']:
        print(f"\n  Relationships:")
        by_id = {e['id']: e for e in result['entries']}
        for rel in result['relationships'][:10]:
            src = by_id.get(rel['from'], {})
            print(f"    {rel['type']:18s} {src.get('func', '?')} → {rel['reason'][:60]}")

    # Show data flows involving tainted data
    tainted_flows = [f for f in result['data_flows'] if f['tainted']]
    if tainted_flows:
        by_id = {e['id']: e for e in result['entries']}
        print(f"\n  Tainted data flows ({len(tainted_flows)} total, showing first 10):")
        for flow in tainted_flows[:10]:
            src = by_id.get(flow['from'], {})
            dst = by_id.get(flow['to'], {})
            print(f"    {src.get('func', '?'):20s} →({flow['data']:15s})→ {dst.get('func', '?'):20s} [{flow['mechanism']}]")
