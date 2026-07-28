"""Import neo4j_export.json into Neo4j."""
import json
import time
import sys
import boto3
from neo4j import GraphDatabase

s3 = boto3.client('s3', region_name='us-east-2')
obj = s3.get_object(Bucket='django-bench-data-staging-158369963073', Key='neo4j_export.json')
data = json.loads(obj['Body'].read())
print(f'Loaded {len(data["nodes"])} nodes, {len(data["relationships"])} rels')

uri = 'bolt://neo4j.django-bench.local:7687'
driver = None

for attempt in range(30):
    try:
        driver = GraphDatabase.driver(uri, auth=('neo4j', 'password123'))
        with driver.session() as s:
            s.run('RETURN 1')
        print(f'Connected to Neo4j on attempt {attempt+1}')
        break
    except Exception as e:
        print(f'Attempt {attempt+1}: {e}')
        time.sleep(5)

if not driver:
    print('Could not connect to Neo4j')
    sys.exit(1)

with driver.session() as session:
    session.run('MATCH (n) DETACH DELETE n')
    print('Cleared existing data')

    for i, node in enumerate(data['nodes']):
        labels = ':'.join(node['labels'])
        props = dict(node['props'])
        props['_import_id'] = node['id']
        query = f'CREATE (n:{labels}) SET n = $props'
        session.run(query, props=props)
    print(f'Created {len(data["nodes"])} nodes')

    for i, rel in enumerate(data['relationships']):
        query = f'MATCH (a {{_import_id: $src}}), (b {{_import_id: $tgt}}) CREATE (a)-[:{rel["type"]}]->(b)'
        session.run(query, src=rel['src'], tgt=rel['tgt'])
    print(f'Created {len(data["relationships"])} relationships')

    session.run('MATCH (n) REMOVE n._import_id')
    print('Cleaned up import IDs')

    r = session.run('MATCH (n) RETURN count(n) as c')
    print(f'Final count: {r.single()["c"]} nodes')

driver.close()
print('DONE')
