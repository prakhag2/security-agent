#!/bin/bash
set -euo pipefail

# ============================================================
# Django Security Bench — Fully Private ECS Fargate Deployment
# ============================================================
#
# SECURITY POSTURE:
#   - Zero 0.0.0.0/0 in any security group (inbound or outbound)
#   - No public IPs on any Fargate task
#   - ALB restricted to CloudFront managed prefix list
#   - Custom origin header as defense-in-depth
#   - VPC endpoints for all AWS API traffic (no NAT)
#   - All outbound SG rules scoped to specific targets
#
# Architecture:
#   Internet → CloudFront (HTTPS) → ALB (prefix-list locked)
#                                        ↓ (SG: 8081 from ALB only)
#                                   App Fargate (private, no public IP)
#                                        ↓ (SG: 7687 from App only)
#                                   Neo4j Fargate (private, no public IP)
#                                        ↓ (SG: 2049 from App+Neo4j only)
#                                   EFS (encrypted)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REGION="us-east-2"
ACCOUNT_ID="158369963073"
PROJECT="django-bench"
ECR_REPO="${PROJECT}"
ECS_CLUSTER="${PROJECT}-cluster"
NEO4J_SERVICE="${PROJECT}-neo4j"
APP_SERVICE="${PROJECT}-app"
EFS_NAME="${PROJECT}-data"
ALB_NAME="${PROJECT}-alb"

# Neo4j credentials — user-defined at deploy time. Set NEO4J_USER / NEO4J_PASSWORD
# in the environment to run non-interactively, else the script prompts.
NEO4J_USER="${NEO4J_USER:-neo4j}"
if [ -z "${NEO4J_PASSWORD:-}" ]; then
    read -rsp "Set Neo4j password for '${NEO4J_USER}': " NEO4J_PASSWORD; echo
    [ -z "${NEO4J_PASSWORD}" ] && { echo "ERROR: password cannot be empty" >&2; exit 1; }
fi

# Secret header for CloudFront→ALB verification
ORIGIN_SECRET="$(openssl rand -hex 32)"
echo "ORIGIN_SECRET=${ORIGIN_SECRET}" > "${SCRIPT_DIR}/.env.deploy"

echo "=== Step 1: Create ECR Repository ==="
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${REGION}" 2>/dev/null || \
aws ecr create-repository \
    --repository-name "${ECR_REPO}" \
    --region "${REGION}" \
    --image-scanning-configuration scanOnPush=true \
    --encryption-configuration encryptionType=AES256

ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}"
echo "ECR URI: ${ECR_URI}"

echo ""
echo "=== Step 2: Create VPC ==="

VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.100.0.0/16 \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${PROJECT}-vpc}]" \
    --query 'Vpc.VpcId' --output text)
echo "VPC: ${VPC_ID}"

aws ec2 modify-vpc-attribute --vpc-id "${VPC_ID}" --enable-dns-hostnames --region "${REGION}"
aws ec2 modify-vpc-attribute --vpc-id "${VPC_ID}" --enable-dns-support --region "${REGION}"

# Internet Gateway — required for ALB to be internet-facing (CloudFront needs to reach it)
IGW_ID=$(aws ec2 create-internet-gateway \
    --region "${REGION}" \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${PROJECT}-igw}]" \
    --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --internet-gateway-id "${IGW_ID}" --vpc-id "${VPC_ID}" --region "${REGION}"

echo ""
echo "=== Step 3: Subnets ==="

# Public subnets — ALB ONLY lives here (no containers, no public IPs assigned to anything)
PUB_SUB_A=$(aws ec2 create-subnet \
    --vpc-id "${VPC_ID}" --cidr-block 10.100.0.0/24 \
    --availability-zone "${REGION}a" \
    --region "${REGION}" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT}-pub-a}]" \
    --query 'Subnet.SubnetId' --output text)

PUB_SUB_B=$(aws ec2 create-subnet \
    --vpc-id "${VPC_ID}" --cidr-block 10.100.1.0/24 \
    --availability-zone "${REGION}b" \
    --region "${REGION}" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT}-pub-b}]" \
    --query 'Subnet.SubnetId' --output text)

# Disable auto-assign public IP on public subnets (belt + suspenders)
aws ec2 modify-subnet-attribute --subnet-id "${PUB_SUB_A}" --no-map-public-ip-on-launch --region "${REGION}"
aws ec2 modify-subnet-attribute --subnet-id "${PUB_SUB_B}" --no-map-public-ip-on-launch --region "${REGION}"

# Public route table (only for ALB)
PUB_RT=$(aws ec2 create-route-table \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT}-pub-rt}]" \
    --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id "${PUB_RT}" --destination-cidr-block 0.0.0.0/0 --gateway-id "${IGW_ID}" --region "${REGION}"
aws ec2 associate-route-table --route-table-id "${PUB_RT}" --subnet-id "${PUB_SUB_A}" --region "${REGION}"
aws ec2 associate-route-table --route-table-id "${PUB_RT}" --subnet-id "${PUB_SUB_B}" --region "${REGION}"

# Private subnets — all containers + EFS live here, NO internet route
PRIV_SUB_A=$(aws ec2 create-subnet \
    --vpc-id "${VPC_ID}" --cidr-block 10.100.10.0/24 \
    --availability-zone "${REGION}a" \
    --region "${REGION}" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT}-priv-a}]" \
    --query 'Subnet.SubnetId' --output text)

PRIV_SUB_B=$(aws ec2 create-subnet \
    --vpc-id "${VPC_ID}" --cidr-block 10.100.11.0/24 \
    --availability-zone "${REGION}b" \
    --region "${REGION}" \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT}-priv-b}]" \
    --query 'Subnet.SubnetId' --output text)

# Private route table — NO default route, only local VPC traffic
PRIV_RT=$(aws ec2 create-route-table \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT}-priv-rt}]" \
    --query 'RouteTable.RouteTableId' --output text)
aws ec2 associate-route-table --route-table-id "${PRIV_RT}" --subnet-id "${PRIV_SUB_A}" --region "${REGION}"
aws ec2 associate-route-table --route-table-id "${PRIV_RT}" --subnet-id "${PRIV_SUB_B}" --region "${REGION}"

echo "Public subnets (ALB only): ${PUB_SUB_A}, ${PUB_SUB_B}"
echo "Private subnets (containers): ${PRIV_SUB_A}, ${PRIV_SUB_B}"

echo ""
echo "=== Step 4: Security Groups (Zero 0.0.0.0/0) ==="

# --- ALB Security Group ---
ALB_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT}-alb-sg" \
    --description "ALB - inbound from CloudFront prefix list only" \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --query 'GroupId' --output text)

# Remove default outbound 0.0.0.0/0 rule
aws ec2 revoke-security-group-egress \
    --group-id "${ALB_SG}" --region "${REGION}" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

# --- App Security Group ---
APP_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT}-app-sg" \
    --description "App containers - no public access" \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

# --- Neo4j Security Group ---
NEO4J_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT}-neo4j-sg" \
    --description "Neo4j - accepts from app only" \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
    --group-id "${NEO4J_SG}" --region "${REGION}" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

# --- EFS Security Group ---
EFS_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT}-efs-sg" \
    --description "EFS - NFS from app and neo4j only" \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
    --group-id "${EFS_SG}" --region "${REGION}" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

# --- VPC Endpoints Security Group ---
VPCE_SG=$(aws ec2 create-security-group \
    --group-name "${PROJECT}-vpce-sg" \
    --description "VPC Endpoints - HTTPS from app and neo4j" \
    --vpc-id "${VPC_ID}" --region "${REGION}" \
    --query 'GroupId' --output text)

aws ec2 revoke-security-group-egress \
    --group-id "${VPCE_SG}" --region "${REGION}" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' 2>/dev/null || true

echo "Security groups created: ALB=${ALB_SG} APP=${APP_SG} NEO4J=${NEO4J_SG} EFS=${EFS_SG} VPCE=${VPCE_SG}"

echo ""
echo "=== Step 5: Security Group Rules (all scoped, no 0.0.0.0/0) ==="

# CloudFront managed prefix list
CF_PREFIX_LIST=$(aws ec2 describe-managed-prefix-lists \
    --region "${REGION}" \
    --filters "Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing" \
    --query 'PrefixLists[0].PrefixListId' --output text)

echo "CloudFront prefix list: ${CF_PREFIX_LIST}"

# ALB INBOUND: only from CloudFront
aws ec2 authorize-security-group-ingress \
    --group-id "${ALB_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":80,\"ToPort\":80,\"PrefixListIds\":[{\"PrefixListId\":\"${CF_PREFIX_LIST}\"}]}]"

# ALB OUTBOUND: only to App containers on 8081
aws ec2 authorize-security-group-egress \
    --group-id "${ALB_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":8081,\"ToPort\":8081,\"UserIdGroupPairs\":[{\"GroupId\":\"${APP_SG}\"}]}]"

# APP INBOUND: only from ALB on 8081
aws ec2 authorize-security-group-ingress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --protocol tcp --port 8081 --source-group "${ALB_SG}"

# APP OUTBOUND: Neo4j, EFS, VPC Endpoints, S3 prefix list (for ECR image layers)
aws ec2 authorize-security-group-egress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":7687,\"ToPort\":7687,\"UserIdGroupPairs\":[{\"GroupId\":\"${NEO4J_SG}\"}]}]"
aws ec2 authorize-security-group-egress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":2049,\"ToPort\":2049,\"UserIdGroupPairs\":[{\"GroupId\":\"${EFS_SG}\"}]}]"
aws ec2 authorize-security-group-egress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"UserIdGroupPairs\":[{\"GroupId\":\"${VPCE_SG}\"}]}]"

# S3 gateway endpoint uses prefix list routing — SG must allow egress to S3 IPs
S3_PREFIX=$(aws ec2 describe-prefix-lists --region "${REGION}" \
    --filters "Name=prefix-list-name,Values=com.amazonaws.${REGION}.s3" \
    --query 'PrefixLists[0].PrefixListId' --output text)
aws ec2 authorize-security-group-egress \
    --group-id "${APP_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"PrefixListIds\":[{\"PrefixListId\":\"${S3_PREFIX}\"}]}]"

# NEO4J INBOUND: only from App on 7687
aws ec2 authorize-security-group-ingress \
    --group-id "${NEO4J_SG}" --region "${REGION}" \
    --protocol tcp --port 7687 --source-group "${APP_SG}"

# NEO4J OUTBOUND: only EFS, VPC Endpoints, and S3 prefix list (for image pull + logs)
aws ec2 authorize-security-group-egress \
    --group-id "${NEO4J_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":2049,\"ToPort\":2049,\"UserIdGroupPairs\":[{\"GroupId\":\"${EFS_SG}\"}]}]"
aws ec2 authorize-security-group-egress \
    --group-id "${NEO4J_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"UserIdGroupPairs\":[{\"GroupId\":\"${VPCE_SG}\"}]}]"
aws ec2 authorize-security-group-egress \
    --group-id "${NEO4J_SG}" --region "${REGION}" \
    --ip-permissions "[{\"IpProtocol\":\"tcp\",\"FromPort\":443,\"ToPort\":443,\"PrefixListIds\":[{\"PrefixListId\":\"${S3_PREFIX}\"}]}]"

# EFS INBOUND: NFS from App and Neo4j
aws ec2 authorize-security-group-ingress \
    --group-id "${EFS_SG}" --region "${REGION}" \
    --protocol tcp --port 2049 --source-group "${APP_SG}"
aws ec2 authorize-security-group-ingress \
    --group-id "${EFS_SG}" --region "${REGION}" \
    --protocol tcp --port 2049 --source-group "${NEO4J_SG}"
# EFS OUTBOUND: none needed (stateful — responses go back on inbound connections)

# VPCE INBOUND: HTTPS from App and Neo4j
aws ec2 authorize-security-group-ingress \
    --group-id "${VPCE_SG}" --region "${REGION}" \
    --protocol tcp --port 443 --source-group "${APP_SG}"
aws ec2 authorize-security-group-ingress \
    --group-id "${VPCE_SG}" --region "${REGION}" \
    --protocol tcp --port 443 --source-group "${NEO4J_SG}"
# VPCE OUTBOUND: none needed (AWS-managed interface, responses are stateful)

echo "All SG rules applied — zero 0.0.0.0/0 anywhere."

echo ""
echo "=== Step 6: VPC Endpoints (replace NAT — no internet egress) ==="

# S3 Gateway Endpoint (free, needed for ECR image layers)
aws ec2 create-vpc-endpoint \
    --vpc-id "${VPC_ID}" \
    --service-name "com.amazonaws.${REGION}.s3" \
    --route-table-ids "${PRIV_RT}" \
    --vpc-endpoint-type Gateway \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${PROJECT}-s3-gw}]"

# ECR API (image metadata)
aws ec2 create-vpc-endpoint \
    --vpc-id "${VPC_ID}" \
    --service-name "com.amazonaws.${REGION}.ecr.api" \
    --vpc-endpoint-type Interface \
    --subnet-ids "${PRIV_SUB_A}" "${PRIV_SUB_B}" \
    --security-group-ids "${VPCE_SG}" \
    --private-dns-enabled \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${PROJECT}-ecr-api}]"

# ECR DKR (docker pull)
aws ec2 create-vpc-endpoint \
    --vpc-id "${VPC_ID}" \
    --service-name "com.amazonaws.${REGION}.ecr.dkr" \
    --vpc-endpoint-type Interface \
    --subnet-ids "${PRIV_SUB_A}" "${PRIV_SUB_B}" \
    --security-group-ids "${VPCE_SG}" \
    --private-dns-enabled \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${PROJECT}-ecr-dkr}]"

# CloudWatch Logs
aws ec2 create-vpc-endpoint \
    --vpc-id "${VPC_ID}" \
    --service-name "com.amazonaws.${REGION}.logs" \
    --vpc-endpoint-type Interface \
    --subnet-ids "${PRIV_SUB_A}" "${PRIV_SUB_B}" \
    --security-group-ids "${VPCE_SG}" \
    --private-dns-enabled \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${PROJECT}-logs}]"

# Bedrock Runtime (invoke models)
aws ec2 create-vpc-endpoint \
    --vpc-id "${VPC_ID}" \
    --service-name "com.amazonaws.${REGION}.bedrock-runtime" \
    --vpc-endpoint-type Interface \
    --subnet-ids "${PRIV_SUB_A}" "${PRIV_SUB_B}" \
    --security-group-ids "${VPCE_SG}" \
    --private-dns-enabled \
    --region "${REGION}" \
    --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${PROJECT}-bedrock}]"

echo "VPC Endpoints created — containers access AWS APIs without internet."

echo ""
echo "=== Step 7: EFS File System ==="

EFS_ID=$(aws efs create-file-system \
    --region "${REGION}" \
    --encrypted \
    --performance-mode generalPurpose \
    --throughput-mode bursting \
    --tags "Key=Name,Value=${EFS_NAME}" \
    --query 'FileSystemId' --output text)
echo "EFS: ${EFS_ID}"

echo "Waiting for EFS to be available..."
while true; do
    STATE=$(aws efs describe-file-systems --file-system-id "${EFS_ID}" --region "${REGION}" --query 'FileSystems[0].LifeCycleState' --output text)
    [ "${STATE}" = "available" ] && break
    sleep 5
done

# Mount targets in private subnets
aws efs create-mount-target \
    --file-system-id "${EFS_ID}" \
    --subnet-id "${PRIV_SUB_A}" \
    --security-groups "${EFS_SG}" \
    --region "${REGION}"
aws efs create-mount-target \
    --file-system-id "${EFS_ID}" \
    --subnet-id "${PRIV_SUB_B}" \
    --security-groups "${EFS_SG}" \
    --region "${REGION}"

# Access point
EFS_AP=$(aws efs create-access-point \
    --file-system-id "${EFS_ID}" \
    --posix-user "Uid=1000,Gid=1000" \
    --root-directory "Path=/data,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=755}" \
    --region "${REGION}" \
    --query 'AccessPointId' --output text)
echo "EFS Access Point: ${EFS_AP}"

echo ""
echo "=== Step 8: IAM Roles (Least Privilege) ==="

cat > /tmp/ecs-trust.json << 'TRUST'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "ArnLike": {
        "aws:SourceArn": "arn:aws:ecs:us-east-2:158369963073:*"
      }
    }
  }]
}
TRUST

# Execution role (pull images + push logs)
aws iam create-role \
    --role-name "${PROJECT}-exec-role" \
    --assume-role-policy-document file:///tmp/ecs-trust.json 2>/dev/null || true

cat > /tmp/exec-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-2:158369963073:log-group:/ecs/django-bench/*"
    }
  ]
}
POLICY

aws iam put-role-policy \
    --role-name "${PROJECT}-exec-role" \
    --policy-name "ecs-exec-minimal" \
    --policy-document file:///tmp/exec-policy.json

# App task role — only Bedrock on specific models
aws iam create-role \
    --role-name "${PROJECT}-task-role" \
    --assume-role-policy-document file:///tmp/ecs-trust.json 2>/dev/null || true

cat > /tmp/task-policy.json << 'POLICY'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream"
    ],
    "Resource": [
      "arn:aws:bedrock:us-east-1::foundation-model/us.anthropic.claude-opus-4-6-v1",
      "arn:aws:bedrock:us-east-1::foundation-model/us.anthropic.claude-opus-4-7",
      "arn:aws:bedrock:us-east-2::foundation-model/us.anthropic.claude-opus-4-6-v1",
      "arn:aws:bedrock:us-east-2::foundation-model/us.anthropic.claude-opus-4-7"
    ]
  }]
}
POLICY

aws iam put-role-policy \
    --role-name "${PROJECT}-task-role" \
    --policy-name "bedrock-invoke-only" \
    --policy-document file:///tmp/task-policy.json

# Neo4j task role — empty, no AWS API access
aws iam create-role \
    --role-name "${PROJECT}-neo4j-task-role" \
    --assume-role-policy-document file:///tmp/ecs-trust.json 2>/dev/null || true

echo "IAM roles created with minimal permissions."

echo ""
echo "=== Step 9: ECS Cluster ==="

aws ecs create-cluster \
    --cluster-name "${ECS_CLUSTER}" \
    --region "${REGION}" \
    --setting "name=containerInsights,value=disabled"

echo ""
echo "=== Step 10: CloudWatch Log Groups ==="

aws logs create-log-group --log-group-name "/ecs/${PROJECT}/app" --region "${REGION}" 2>/dev/null || true
aws logs create-log-group --log-group-name "/ecs/${PROJECT}/neo4j" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Step 11: ALB (internet-facing, prefix-list locked) ==="

ALB_ARN=$(aws elbv2 create-load-balancer \
    --name "${ALB_NAME}" \
    --type application \
    --scheme internet-facing \
    --subnets "${PUB_SUB_A}" "${PUB_SUB_B}" \
    --security-groups "${ALB_SG}" \
    --region "${REGION}" \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)

ALB_DNS=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns "${ALB_ARN}" \
    --region "${REGION}" \
    --query 'LoadBalancers[0].DNSName' --output text)
echo "ALB DNS: ${ALB_DNS}"

# Target group
TG_ARN=$(aws elbv2 create-target-group \
    --name "${PROJECT}-tg" \
    --protocol HTTP --port 8081 \
    --vpc-id "${VPC_ID}" \
    --target-type ip \
    --health-check-path "/api/tests" \
    --health-check-interval-seconds 30 \
    --healthy-threshold-count 2 \
    --region "${REGION}" \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

# Listener: default action = 403 (reject everything without secret header)
LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "${ALB_ARN}" \
    --protocol HTTP --port 80 \
    --default-actions '[{"Type":"fixed-response","FixedResponseConfig":{"StatusCode":"403","ContentType":"text/plain","MessageBody":"Forbidden"}}]' \
    --region "${REGION}" \
    --query 'Listeners[0].ListenerArn' --output text)

# Rule: only forward if secret header matches
aws elbv2 create-rule \
    --listener-arn "${LISTENER_ARN}" \
    --conditions "[{\"Field\":\"http-header\",\"HttpHeaderConfig\":{\"HttpHeaderName\":\"X-Origin-Verify\",\"Values\":[\"${ORIGIN_SECRET}\"]}}]" \
    --actions "[{\"Type\":\"forward\",\"TargetGroupArn\":\"${TG_ARN}\"}]" \
    --priority 1 \
    --region "${REGION}"

echo "ALB configured: CloudFront prefix list + secret header required."

echo ""
echo "=== Step 12: Service Discovery (Neo4j internal DNS) ==="

NS_OP_ID=$(aws servicediscovery create-private-dns-namespace \
    --name "${PROJECT}.local" \
    --vpc "${VPC_ID}" \
    --region "${REGION}" \
    --query 'OperationId' --output text)

echo "Waiting for namespace creation..."
while true; do
    OP_STATUS=$(aws servicediscovery get-operation --operation-id "${NS_OP_ID}" --region "${REGION}" --query 'Operation.Status' --output text 2>/dev/null)
    [ "${OP_STATUS}" = "SUCCESS" ] && break
    [ "${OP_STATUS}" = "FAIL" ] && echo "ERROR: Namespace creation failed" && exit 1
    sleep 5
done

NS_ID=$(aws servicediscovery get-operation --operation-id "${NS_OP_ID}" --region "${REGION}" --query 'Operation.Targets.NAMESPACE' --output text)
echo "Namespace: ${NS_ID}"

SD_SERVICE_ID=$(aws servicediscovery create-service \
    --name "neo4j" \
    --namespace-id "${NS_ID}" \
    --dns-config "NamespaceId=${NS_ID},DnsRecords=[{Type=A,TTL=10}]" \
    --health-check-custom-config "FailureThreshold=1" \
    --region "${REGION}" \
    --query 'Service.Id' --output text)
echo "Service Discovery: neo4j.${PROJECT}.local → ${SD_SERVICE_ID}"

echo ""
echo "=== Step 13: Neo4j Task Definition & Service ==="

cat > /tmp/neo4j-taskdef.json << TASKDEF
{
  "family": "${NEO4J_SERVICE}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "4096",
  "executionRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-exec-role",
  "taskRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-neo4j-task-role",
  "containerDefinitions": [{
    "name": "neo4j",
    "image": "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/neo4j:5-community",
    "essential": true,
    "portMappings": [{"containerPort": 7687, "protocol": "tcp"}],
    "environment": [
      {"name": "NEO4J_AUTH", "value": "${NEO4J_USER}/${NEO4J_PASSWORD}"},
      {"name": "NEO4J_PLUGINS", "value": "[\"apoc\"]"},
      {"name": "NEO4J_server_memory_heap_initial__size", "value": "2g"},
      {"name": "NEO4J_server_memory_heap_max__size", "value": "2g"}
    ],
    "mountPoints": [{
      "sourceVolume": "efs-data",
      "containerPath": "/neo4j-data",
      "readOnly": false
    }],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${PROJECT}/neo4j",
        "awslogs-region": "${REGION}",
        "awslogs-stream-prefix": "neo4j"
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
    --cli-input-json file:///tmp/neo4j-taskdef.json \
    --region "${REGION}"

aws ecs create-service \
    --cluster "${ECS_CLUSTER}" \
    --service-name "${NEO4J_SERVICE}" \
    --task-definition "${NEO4J_SERVICE}" \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[${PRIV_SUB_A}],securityGroups=[${NEO4J_SG}],assignPublicIp=DISABLED}" \
    --service-registries "registryArn=arn:aws:servicediscovery:${REGION}:${ACCOUNT_ID}:service/${SD_SERVICE_ID}" \
    --region "${REGION}"

echo "Neo4j service created: neo4j.${PROJECT}.local:7687 (private only)"

echo ""
echo "=== Step 14: App Task Definition & Service ==="

cat > /tmp/app-taskdef.json << TASKDEF
{
  "family": "${APP_SERVICE}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "8192",
  "executionRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-exec-role",
  "taskRoleArn": "arn:aws:iam::${ACCOUNT_ID}:role/${PROJECT}-task-role",
  "containerDefinitions": [{
    "name": "app",
    "image": "${ECR_URI}:latest",
    "essential": true,
    "portMappings": [{"containerPort": 8081, "protocol": "tcp"}],
    "environment": [
      {"name": "PORT", "value": "8081"},
      {"name": "DATA_DIR", "value": "/data"},
      {"name": "NEO4J_URI", "value": "bolt://neo4j.${PROJECT}.local:7687"},
      {"name": "NEO4J_USER", "value": "${NEO4J_USER}"},
      {"name": "NEO4J_PASSWORD", "value": "${NEO4J_PASSWORD}"},
      {"name": "MODEL_ID", "value": "us.anthropic.claude-opus-4-6-v1"},
      {"name": "AWS_REGION", "value": "us-east-2"}
    ],
    "mountPoints": [{
      "sourceVolume": "efs-data",
      "containerPath": "/data",
      "readOnly": true
    }],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${PROJECT}/app",
        "awslogs-region": "${REGION}",
        "awslogs-stream-prefix": "app"
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
    --cli-input-json file:///tmp/app-taskdef.json \
    --region "${REGION}"

aws ecs create-service \
    --cluster "${ECS_CLUSTER}" \
    --service-name "${APP_SERVICE}" \
    --task-definition "${APP_SERVICE}" \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[${PRIV_SUB_A},${PRIV_SUB_B}],securityGroups=[${APP_SG}],assignPublicIp=DISABLED}" \
    --load-balancers "targetGroupArn=${TG_ARN},containerName=app,containerPort=8081" \
    --region "${REGION}"

echo "App service created (private, no public IP)."

echo ""
echo "=== Step 15: CloudFront Distribution ==="

cat > /tmp/cf-config.json << CFCONFIG
{
  "CallerReference": "${PROJECT}-$(date +%s)",
  "Comment": "Django Security Analysis",
  "Enabled": true,
  "Origins": {
    "Quantity": 1,
    "Items": [{
      "Id": "alb-origin",
      "DomainName": "${ALB_DNS}",
      "CustomOriginConfig": {
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
        "OriginReadTimeout": 180,
        "OriginKeepaliveTimeout": 60
      },
      "OriginCustomHeaders": {
        "Quantity": 1,
        "Items": [{
          "HeaderName": "X-Origin-Verify",
          "HeaderValue": "${ORIGIN_SECRET}"
        }]
      }
    }]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "alb-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 3,
      "Items": ["GET", "HEAD", "OPTIONS"],
      "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}
    },
    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
    "OriginRequestPolicyId": "216adef6-5c7f-47e4-b989-5492eafa07d3",
    "Compress": true
  },
  "CacheBehaviors": {
    "Quantity": 1,
    "Items": [
      {
        "PathPattern": "/static/*",
        "TargetOriginId": "alb-origin",
        "ViewerProtocolPolicy": "redirect-to-https",
        "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"], "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
        "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        "Compress": true
      }
    ]
  },
  "PriceClass": "PriceClass_100",
  "HttpVersion": "http2"
}
CFCONFIG

CF_DIST_ID=$(aws cloudfront create-distribution \
    --distribution-config file:///tmp/cf-config.json \
    --query 'Distribution.Id' --output text)

CF_DOMAIN=$(aws cloudfront get-distribution \
    --id "${CF_DIST_ID}" \
    --query 'Distribution.DomainName' --output text)

echo ""
echo "============================================"
echo "  DEPLOYMENT COMPLETE"
echo "============================================"
echo ""
echo "CloudFront URL: https://${CF_DOMAIN}"
echo ""
echo "SECURITY SUMMARY:"
echo "  ✓ ALB SG inbound: CloudFront prefix list only (no 0.0.0.0/0)"
echo "  ✓ ALB listener: rejects requests without secret header"
echo "  ✓ CloudFront: injects X-Origin-Verify header automatically"
echo "  ✓ App containers: private subnet, assignPublicIp=DISABLED"
echo "  ✓ Neo4j: private subnet, assignPublicIp=DISABLED, only App can reach it"
echo "  ✓ EFS: encrypted, only App+Neo4j can mount"
echo "  ✓ Outbound: VPC endpoints only, no NAT, no internet egress"
echo "  ✓ All SG outbound rules: scoped to specific security groups"
echo ""
echo "=== Save these for teardown ==="
cat << STATE > "${SCRIPT_DIR}/state.env"
VPC_ID=${VPC_ID}
IGW_ID=${IGW_ID}
PUB_SUB_A=${PUB_SUB_A}
PUB_SUB_B=${PUB_SUB_B}
PRIV_SUB_A=${PRIV_SUB_A}
PRIV_SUB_B=${PRIV_SUB_B}
ALB_SG=${ALB_SG}
APP_SG=${APP_SG}
NEO4J_SG=${NEO4J_SG}
EFS_SG=${EFS_SG}
VPCE_SG=${VPCE_SG}
EFS_ID=${EFS_ID}
EFS_AP=${EFS_AP}
ALB_ARN=${ALB_ARN}
ALB_DNS=${ALB_DNS}
TG_ARN=${TG_ARN}
LISTENER_ARN=${LISTENER_ARN}
CF_DIST_ID=${CF_DIST_ID}
CF_DOMAIN=${CF_DOMAIN}
ECR_URI=${ECR_URI}
NS_ID=${NS_ID}
SD_SERVICE_ID=${SD_SERVICE_ID}
ORIGIN_SECRET=${ORIGIN_SECRET}
STATE
echo "State saved to deploy/state.env"
echo ""
echo "=== Next Steps ==="
echo "1. Build & push Docker image:  ./build-push.sh"
echo "2. Upload data to EFS:         ./upload-efs.sh"
echo "3. Import Neo4j data:          ./import-neo4j.sh"
echo "4. Force redeploy:             aws ecs update-service --cluster ${ECS_CLUSTER} --service ${APP_SERVICE} --force-new-deployment --region ${REGION}"
