"""
Load Juice Shop ontology-annotated traces into Neo4j.

Per-test graphs stored with test label so the web portal can query them.
Schema matches Django's Neo4j structure for UI compatibility:
  - Function nodes: id, name, file, role, trust, tainted, subsystem, sensitivity
  - CALLS edges: parent→child call relationships
  - DATA_FLOWS edges: data flow with taint marking
  - GATES/VALIDATES/PRODUCES_TOKEN relationship edges
"""

import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from juiceshop_ontology import apply_ontology

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password123")

TRACES_DIR = os.environ.get("TRACES_DIR", "traces_juiceshop")


def display_name(entry):
    func = entry.get('func', '?')
    file_path = entry.get('file', '')
    base = file_path.split('/')[-1].replace('.ts', '').replace('.js', '') if file_path else ''
    if func in ('<anonymous>', 'get', '?'):
        return f"{base}:{func}" if base else func
    return func


def load_test_to_neo4j(session, test_name, trace_entries, ontology_result):
    """Load a single test's ontology graph into Neo4j."""
    entries = ontology_result['entries']
    data_flows = ontology_result['data_flows']
    relationships = ontology_result['relationships']

    by_id = {e['id']: e for e in entries}

    # Create Function nodes
    for e in entries:
        props = {
            'fid': f"{test_name}_{e['id']}",
            'test': test_name,
            'entry_id': e['id'],
            'display_name': display_name(e),
            'file': e.get('file', ''),
            'func': e.get('func', ''),
            'line': e.get('line', 0),
            'role': e['role'],
            'trust': e['trust_level'],
            'tainted': e['tainted'],
            'subsystem': e['subsystem'],
            'sensitivity': e['data_sensitivity'],
            'depth': e.get('depth', 0),
        }
        session.run(
            "CREATE (f:Function:JuiceShop $props)",
            props=props
        )

    # Create CALLS edges (parent→child)
    for e in entries:
        if e.get('parent') is not None:
            session.run(
                """MATCH (a:Function {fid: $parent_fid}), (b:Function {fid: $child_fid})
                   CREATE (a)-[:CALLS]->(b)""",
                parent_fid=f"{test_name}_{e['parent']}",
                child_fid=f"{test_name}_{e['id']}"
            )

    # Create DATA_FLOWS edges
    for flow in data_flows:
        session.run(
            """MATCH (a:Function {fid: $from_fid}), (b:Function {fid: $to_fid})
               CREATE (a)-[:DATA_FLOWS {data: $data, mechanism: $mech, tainted: $tainted}]->(b)""",
            from_fid=f"{test_name}_{flow['from']}",
            to_fid=f"{test_name}_{flow['to']}",
            data=flow.get('data', ''),
            mech=flow.get('mechanism', ''),
            tainted=flow.get('tainted', False)
        )

    # Create security relationship edges
    for rel in relationships:
        session.run(
            """MATCH (a:Function {fid: $from_fid}), (b:Function {fid: $to_fid})
               CREATE (a)-[:""" + rel['type'] + """ {reason: $reason}]->(b)""",
            from_fid=f"{test_name}_{rel['from']}",
            to_fid=f"{test_name}_{rel['to']}",
            reason=rel.get('reason', '')
        )


def setup_constraints(session):
    """Create indexes and constraints."""
    session.run("CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.fid)")
    session.run("CREATE INDEX IF NOT EXISTS FOR (f:Function) ON (f.test)")


def clear_juiceshop_data(session):
    """Remove all JuiceShop-labeled nodes."""
    session.run("MATCH (n:JuiceShop) DETACH DELETE n")


def load_all_tests(limit=None, clear=True):
    """Load all (or limited) Juice Shop tests into Neo4j."""
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    files = sorted(f for f in os.listdir(TRACES_DIR)
                   if f.endswith('.json') and not f.startswith('_'))
    if limit:
        files = files[:limit]

    with driver.session() as session:
        setup_constraints(session)
        if clear:
            print("Clearing existing JuiceShop data...")
            clear_juiceshop_data(session)

    t0 = time.time()
    loaded = 0
    errors = []

    for i, fname in enumerate(files):
        test_name = fname.replace('.json', '')
        try:
            with open(os.path.join(TRACES_DIR, fname)) as fh:
                trace = json.load(fh)

            ontology_result = apply_ontology(trace)

            with driver.session() as session:
                load_test_to_neo4j(session, test_name, trace, ontology_result)

            loaded += 1
            if (i + 1) % 50 == 0:
                elapsed = time.time() - t0
                print(f"  {i+1}/{len(files)} loaded ({elapsed:.1f}s)")

        except Exception as e:
            errors.append((fname, str(e)))

    elapsed = time.time() - t0
    driver.close()

    print(f"\nLoaded {loaded}/{len(files)} tests in {elapsed:.1f}s")
    if errors:
        print(f"Errors ({len(errors)}):")
        for f, e in errors[:10]:
            print(f"  {f}: {e}")

    return loaded, errors


# Anti-pattern queries adapted for Juice Shop
ATTACK_QUERIES = [
    {
        "name": "Unguarded tainted flow to sensitive operation",
        "description": "Tainted data reaches crypto/JWT/DB without passing through a validator",
        "cypher": """
            MATCH path = (src:Function:JuiceShop)-[:DATA_FLOWS*1..5 {tainted: true}]->(sink:Function:JuiceShop)
            WHERE src.test = $test
            AND sink.role IN ['crypto', 'jwt_handler', 'db_writer', 'file_handler']
            AND NOT EXISTS {
                MATCH (src)-[:DATA_FLOWS*1..4]->(v:Function:JuiceShop)-[:DATA_FLOWS*1..4]->(sink)
                WHERE v.role = 'validator' AND v.test = $test
            }
            RETURN src.display_name AS source, sink.display_name AS sink,
                   src.file AS source_file, sink.file AS sink_file,
                   length(path) AS hops
            LIMIT 10
        """,
    },
    {
        "name": "User-controlled input to JWT signing",
        "description": "User data flows directly into JWT token production",
        "cypher": """
            MATCH (src:Function:JuiceShop {trust: 'user_controlled'})-[:DATA_FLOWS*1..4 {tainted: true}]->(jwt:Function:JuiceShop {role: 'jwt_handler'})
            WHERE src.test = $test
            RETURN src.display_name AS source, jwt.display_name AS jwt_op,
                   src.file AS source_file
            LIMIT 10
        """,
    },
    {
        "name": "Trust boundary crossing without validation",
        "description": "Tainted data crosses from user_controlled to privileged without a validator gate",
        "cypher": """
            MATCH (a:Function:JuiceShop {trust: 'user_controlled'})-[r:DATA_FLOWS {tainted: true}]->(b:Function:JuiceShop {trust: 'privileged'})
            WHERE a.test = $test
            AND NOT EXISTS {
                MATCH (a)-[:DATA_FLOWS]->(v:Function:JuiceShop {role: 'validator'})-[:DATA_FLOWS]->(b)
                WHERE v.test = $test
            }
            RETURN a.display_name AS source, b.display_name AS target,
                   r.data AS data, a.file AS source_file
            LIMIT 10
        """,
    },
    {
        "name": "Entry point with no downstream validator",
        "description": "HTTP entry point processes user data without any validation in its subtree",
        "cypher": """
            MATCH (entry:Function:JuiceShop {role: 'entry_point', trust: 'user_controlled'})
            WHERE entry.test = $test
            AND entry.subsystem NOT IN ['observability', 'gamification']
            AND NOT EXISTS {
                MATCH (entry)-[:CALLS*1..5]->(v:Function:JuiceShop {role: 'validator'})
                WHERE v.test = $test
            }
            RETURN entry.display_name AS entry_point, entry.file AS file,
                   entry.subsystem AS subsystem
            LIMIT 10
        """,
    },
    {
        "name": "Tainted data reaching file operations",
        "description": "User-controlled data flows to file handler (potential path traversal)",
        "cypher": """
            MATCH path = (src:Function:JuiceShop {tainted: true})-[:CALLS*1..6]->(fh:Function:JuiceShop {role: 'file_handler'})
            WHERE src.test = $test AND src.trust = 'user_controlled'
            RETURN src.display_name AS source, fh.display_name AS file_op,
                   src.file AS source_file, fh.file AS target_file,
                   length(path) AS hops
            LIMIT 10
        """,
    },
]


def run_attack_queries(test_name):
    """Run anti-pattern queries for a specific test."""
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    findings = []

    with driver.session() as session:
        for q in ATTACK_QUERIES:
            try:
                result = session.run(q['cypher'], test=test_name)
                records = [dict(r) for r in result]
                if records:
                    findings.append({
                        'query': q['name'],
                        'description': q['description'],
                        'results': records,
                    })
            except Exception as e:
                findings.append({
                    'query': q['name'],
                    'error': str(e),
                })

    driver.close()
    return findings


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python load_juiceshop_neo4j.py load [limit]   - Load tests into Neo4j")
        print("  python load_juiceshop_neo4j.py query <test>   - Run attack queries")
        print("  python load_juiceshop_neo4j.py clear          - Clear JuiceShop data")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'load':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
        load_all_tests(limit=limit)

    elif cmd == 'query':
        test_name = sys.argv[2] if len(sys.argv) > 2 else 'login__010_POST_login_with_WHERE_clause_disabling_SQL_injection_attack'
        print(f"Running attack queries for: {test_name}")
        print("=" * 60)
        findings = run_attack_queries(test_name)
        for f in findings:
            print(f"\n  {f['query']}")
            if 'error' in f:
                print(f"    ERROR: {f['error']}")
            else:
                print(f"    Found {len(f['results'])} result(s):")
                for r in f['results'][:3]:
                    print(f"      {r}")

    elif cmd == 'clear':
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            clear_juiceshop_data(session)
        driver.close()
        print("Cleared all JuiceShop data from Neo4j")
