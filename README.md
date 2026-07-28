# security-agent

An LLM security-analysis agent that scans a target web application (OWASP Juice Shop)
for vulnerabilities using a graph-guided plan → attack → verify loop, backed by a Neo4j
knowledge graph and served through a live web UI.

## What runs

The deployed service (`deploy/app/`) is a small HTTP server that:

- Serves a UI (`ui.html` + `static/`) with a D3 graph of the target app's security ontology.
- Runs graph-guided vulnerability scans with SSE streaming (`scan_juiceshop_planner.py`,
  `scan_juiceshop_attacker.py`, `scan_juiceshop_verifier.py`) built on
  [Strands Agents](https://pypi.org/project/strands-agents/) over Amazon Bedrock.
- Reads a Neo4j graph of the target app and pre-computed findings
  (`juiceshop_graph.json`, `juiceshop_ground_truth.json`, `juiceshop_static_findings.json`).

Runtime scan output (traces, call trees) is written to `DATA_DIR` (EFS `/data` in the
deployed setup) and is intentionally not committed — see `.gitignore`.

## Layout

```
deploy/
  app/                     # the container image contents (what actually runs)
    server.py              # HTTP server + SSE scan streaming
    scan_juiceshop_*.py    # planner / attacker / verifier agents
    juiceshop_ontology.py  # target-app security ontology
    load_juiceshop_neo4j.py
    ui.html, static/, d3.v7.min.js
    *.json                 # graph + findings the UI/agent load at boot
  Dockerfile               # python:3.12-slim, runs server.py
  requirements.txt
  infra.sh                 # provisions the AWS deployment (see below)
  build-push.sh            # build + push image to ECR
  upload-efs.sh            # seed EFS data volume
  run_parallel_scans.sh
  teardown.sh
```

## Deployment

`deploy/infra.sh` stands up a **fully private** ECS Fargate deployment in AWS:

```
Internet → CloudFront (HTTPS) → ALB (locked to CloudFront prefix list, secret origin header)
         → App Fargate (private, no public IP) → Neo4j Fargate (private) → EFS (encrypted)
```

Security posture: no `0.0.0.0/0` in any security group, no public task IPs, VPC endpoints
for AWS API traffic (no NAT), ECR scan-on-push, encrypted EFS.

### Neo4j credentials

The Neo4j password is **chosen at deploy time** — it is never hardcoded. Either export it
or let the script prompt you:

```bash
# non-interactive
NEO4J_USER=neo4j NEO4J_PASSWORD='your-strong-password' ./deploy/infra.sh

# or run it and get prompted
./deploy/infra.sh
```

### Run

```bash
cd deploy
./build-push.sh        # build + push image to ECR
NEO4J_PASSWORD=... ./infra.sh   # provision everything
./upload-efs.sh        # seed the EFS data volume
```

Local run:

```bash
docker build -t security-agent deploy/
docker run -p 8081:8081 \
  -e NEO4J_URI=bolt://host.docker.internal:7687 \
  -e NEO4J_USER=neo4j -e NEO4J_PASSWORD=... \
  security-agent
```

## Deploying elsewhere

The container is self-contained. The deploy scripts have a few environment-specific
inputs to set for a different account/machine:

- **Account/region** — `infra.sh` has `ACCOUNT_ID`, `REGION`, and a log-group ARN hardcoded
  near the top; edit them for your account.
- **EFS seed data is not in this repo.** `upload-efs.sh` seeds historical scan traces,
  results, and the analyzed Django source onto EFS — generated/vendored data that is
  intentionally excluded. It requires `BENCH_DIR` (dir holding `traces/`, `results/`,
  `merged_trees/`, ...) and `DJANGO_DIR` (Django source root) to be set, and errors out if
  they aren't. The live vulnerability scan works without this step; only the historical
  trace-viewer and `/api/source` endpoints need the seeded data.
- **`load_juiceshop_neo4j.py`** (offline graph loader) reads `TRACES_DIR` (default
  `traces_juiceshop`); **`juiceshop_ontology.py`** reads `JUICESHOP_ROOT` (default
  `juice-shop`). Override via env if your copies live elsewhere.
