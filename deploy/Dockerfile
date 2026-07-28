FROM python:3.12-slim

WORKDIR /app

# Install system deps for neo4j driver
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY app/ ./

# Data will be mounted via EFS at /data
# - /data/traces
# - /data/traces_semantic
# - /data/results
# - /data/results_sysmon
# - /data/django (django source for /api/source)

ENV PORT=8081
ENV DATA_DIR=/data
ENV NEO4J_URI=bolt://neo4j:7687
ENV NEO4J_USER=neo4j
ENV NEO4J_PASSWORD=changeme
ENV PYTHONPATH=/data/django

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8081/api/tests || exit 1

CMD ["python", "server.py"]
