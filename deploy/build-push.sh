#!/bin/bash
set -euo pipefail

REGION="us-east-2"
ACCOUNT_ID="158369963073"
ECR_REPO="django-bench"
ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

echo "=== Logging into ECR ==="
aws ecr get-login-password --region "${REGION}" | \
    docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo "=== Building Docker image ==="
docker build -t "${ECR_REPO}:latest" -f Dockerfile .

echo "=== Tagging and pushing ==="
docker tag "${ECR_REPO}:latest" "${ECR_URI}:latest"
docker tag "${ECR_REPO}:latest" "${ECR_URI}:$(date +%Y%m%d-%H%M%S)"
docker push "${ECR_URI}:latest"

echo "=== Done ==="
echo "Image pushed: ${ECR_URI}:latest"
echo ""
echo "To deploy: aws ecs update-service --cluster django-bench-cluster --service django-bench-app --force-new-deployment --region ${REGION}"
