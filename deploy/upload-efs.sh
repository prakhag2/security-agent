#!/bin/bash
set -euo pipefail

# Upload data to EFS using a temporary Fargate task that mounts EFS
# and copies data from S3 (we stage to S3 first, then pull into EFS).

REGION="us-east-2"
ACCOUNT_ID="158369963073"
PROJECT="django-bench"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/state.env"

S3_BUCKET="${PROJECT}-data-staging-${ACCOUNT_ID}"
# Trace/results data + Django source to seed onto EFS. NOT included in this repo
# (generated output + vendored source). Point these at your own copies.
BENCH_DIR="${BENCH_DIR:?set BENCH_DIR to the dir holding traces/ results/ merged_trees/ etc.}"
DJANGO_DIR="${DJANGO_DIR:?set DJANGO_DIR to the Django source root (for /api/source)}"

echo "=== Step 1: Create staging S3 bucket ==="
aws s3 mb "s3://${S3_BUCKET}" --region "${REGION}" 2>/dev/null || true

# Block all public access
aws s3api put-public-access-block \
    --bucket "${S3_BUCKET}" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region "${REGION}"

echo "=== Step 2: Upload trace data to S3 ==="
echo "Uploading traces..."
aws s3 sync "${BENCH_DIR}/traces/" "s3://${S3_BUCKET}/traces/" --region "${REGION}" --quiet
echo "Uploading semantic traces..."
aws s3 sync "${BENCH_DIR}/traces_semantic/" "s3://${S3_BUCKET}/traces_semantic/" --region "${REGION}" --quiet
echo "Uploading results..."
aws s3 sync "${BENCH_DIR}/results/" "s3://${S3_BUCKET}/results/" --region "${REGION}" --quiet
aws s3 sync "${BENCH_DIR}/results_sysmon/" "s3://${S3_BUCKET}/results_sysmon/" --region "${REGION}" --quiet
echo "Uploading merged trees..."
aws s3 sync "${BENCH_DIR}/merged_trees/" "s3://${S3_BUCKET}/merged_trees/" --region "${REGION}" --quiet
echo "Uploading top-level trace files..."
for f in "${BENCH_DIR}"/trace_*.json; do
    [ -f "$f" ] && aws s3 cp "$f" "s3://${S3_BUCKET}/" --region "${REGION}" --quiet
done
echo "Uploading static_findings.json..."
aws s3 cp "${BENCH_DIR}/static_findings.json" "s3://${S3_BUCKET}/" --region "${REGION}" --quiet
echo "Uploading Django source (for /api/source endpoint)..."
aws s3 sync "${DJANGO_DIR}/django/" "s3://${S3_BUCKET}/django/django/" --region "${REGION}" --quiet --exclude "*.pyc" --exclude "__pycache__/*"

echo ""
echo "=== Step 3: Run EFS loader task ==="

# Create a task role that can read from the staging bucket
cat > /tmp/efs-loader-policy.json << POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::${S3_BUCKET}",
      "arn:aws:s3:::${S3_BUCKET}/*"
    ]
  }]
}
POLICY

aws iam create-role \
    --role-name "${PROJECT}-efs-loader-role" \
    --assume-role-policy-document file:///tmp/ecs-trust.json 2>/dev/null || true
aws iam put-role-policy \
    --role-name "${PROJECT}-efs-loader-role" \
    --policy-name "s3-read-staging" \
    --policy-document file:///tmp/efs-loader-policy.json

# Add S3 VPC endpoint for the loader (gateway type, free)
# Already created in infra.sh, but ensure it exists
echo "Verifying S3 VPC endpoint..."
aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=service-name,Values=com.amazonaws.${REGION}.s3" \
    --region "${REGION}" --query 'VpcEndpoints[0].VpcEndpointId' --output text

# Register EFS loader task
cat > /tmp/efs-loader-taskdef.json << TASKDEF
{
  "family": "${PROJECT}-efs-loader",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-exec-role",
  "taskRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-efs-loader-role",
  "containerDefinitions": [{
    "name": "loader",
    "image": "amazon/aws-cli:latest",
    "essential": true,
    "command": ["sh", "-c", "aws s3 sync s3://${S3_BUCKET}/ /data/ --region ${REGION} && echo 'DONE: Data loaded to EFS' && ls -la /data/"],
    "mountPoints": [{
      "sourceVolume": "efs-data",
      "containerPath": "/data",
      "readOnly": false
    }],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${PROJECT}/app",
        "awslogs-region": "${REGION}",
        "awslogs-stream-prefix": "efs-loader"
      }
    }
  }],
  "volumes": [{
    "name": "efs-data",
    "efsVolumeConfiguration": {
      "fileSystemId": "${EFS_ID}",
      "transitEncryption": "ENABLED",
      "authorizationConfig": {
        "accessPointId": "${EFS_AP}",
        "iam": "DISABLED"
      }
    }
  }]
}
TASKDEF

aws ecs register-task-definition \
    --cli-input-json file:///tmp/efs-loader-taskdef.json \
    --region "${REGION}"

# Need to allow the loader task's SG to access S3 VPC endpoint and EFS
# We'll reuse the APP_SG for the loader (it already has EFS + VPCE access)

echo "Running EFS loader task..."
TASK_ARN=$(aws ecs run-task \
    --cluster "${PROJECT}-cluster" \
    --task-definition "${PROJECT}-efs-loader" \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[${PRIV_SUB_A}],securityGroups=[${APP_SG}],assignPublicIp=DISABLED}" \
    --region "${REGION}" \
    --query 'tasks[0].taskArn' --output text)

echo "Loader task started: ${TASK_ARN}"
echo "Monitor with: aws ecs describe-tasks --cluster ${PROJECT}-cluster --tasks ${TASK_ARN} --region ${REGION}"
echo ""
echo "Once task completes (STOPPED, exit code 0), data is on EFS."
echo "Then restart the app: aws ecs update-service --cluster ${PROJECT}-cluster --service ${PROJECT}-app --force-new-deployment --region ${REGION}"
