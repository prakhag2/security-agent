#!/bin/bash
set -euo pipefail

# Teardown all resources created by infra.sh
# Run with: ./teardown.sh

REGION="us-east-2"
PROJECT="django-bench"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "${SCRIPT_DIR}/state.env" ]; then
    echo "ERROR: state.env not found. Cannot teardown without resource IDs."
    exit 1
fi

source "${SCRIPT_DIR}/state.env"

echo "=== WARNING: This will destroy all ${PROJECT} infrastructure ==="
echo "VPC: ${VPC_ID}"
echo "CloudFront: ${CF_DIST_ID}"
echo ""
read -p "Type 'destroy' to confirm: " CONFIRM
[ "${CONFIRM}" != "destroy" ] && echo "Aborted." && exit 1

echo ""
echo "=== Disabling CloudFront distribution ==="
# Must disable before deleting
CF_CONFIG=$(aws cloudfront get-distribution-config --id "${CF_DIST_ID}" --output json)
CF_ETAG=$(echo "${CF_CONFIG}" | python3 -c "import sys,json; print(json.load(sys.stdin)['ETag'])")
echo "${CF_CONFIG}" | python3 -c "
import sys, json
cfg = json.load(sys.stdin)['DistributionConfig']
cfg['Enabled'] = False
json.dump(cfg, open('/tmp/cf-disable.json','w'))
"
aws cloudfront update-distribution --id "${CF_DIST_ID}" --distribution-config file:///tmp/cf-disable.json --if-match "${CF_ETAG}" 2>/dev/null || true
echo "CloudFront disabled (deletion takes ~15min after disable propagates)"

echo ""
echo "=== Deleting ECS Services ==="
aws ecs update-service --cluster "${PROJECT}-cluster" --service "${PROJECT}-app" --desired-count 0 --region "${REGION}" 2>/dev/null || true
aws ecs update-service --cluster "${PROJECT}-cluster" --service "${PROJECT}-neo4j" --desired-count 0 --region "${REGION}" 2>/dev/null || true
sleep 10
aws ecs delete-service --cluster "${PROJECT}-cluster" --service "${PROJECT}-app" --force --region "${REGION}" 2>/dev/null || true
aws ecs delete-service --cluster "${PROJECT}-cluster" --service "${PROJECT}-neo4j" --force --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting ALB ==="
aws elbv2 delete-listener --listener-arn "${LISTENER_ARN}" --region "${REGION}" 2>/dev/null || true
aws elbv2 delete-target-group --target-group-arn "${TG_ARN}" --region "${REGION}" 2>/dev/null || true
aws elbv2 delete-load-balancer --load-balancer-arn "${ALB_ARN}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting Service Discovery ==="
aws servicediscovery delete-service --id "${SD_SERVICE_ID}" --region "${REGION}" 2>/dev/null || true
aws servicediscovery delete-namespace --id "${NS_ID}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting ECS Cluster ==="
aws ecs delete-cluster --cluster "${PROJECT}-cluster" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting EFS ==="
# Delete mount targets first
for MT in $(aws efs describe-mount-targets --file-system-id "${EFS_ID}" --region "${REGION}" --query 'MountTargets[*].MountTargetId' --output text 2>/dev/null); do
    aws efs delete-mount-target --mount-target-id "${MT}" --region "${REGION}"
done
sleep 30
aws efs delete-access-point --access-point-id "${EFS_AP}" --region "${REGION}" 2>/dev/null || true
aws efs delete-file-system --file-system-id "${EFS_ID}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting VPC Endpoints ==="
for VPCE in $(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=${VPC_ID}" --region "${REGION}" --query 'VpcEndpoints[*].VpcEndpointId' --output text 2>/dev/null); do
    aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "${VPCE}" --region "${REGION}" 2>/dev/null || true
done

echo ""
echo "=== Deleting Security Groups ==="
sleep 10
for SG in "${ALB_SG}" "${APP_SG}" "${NEO4J_SG}" "${EFS_SG}" "${VPCE_SG}"; do
    aws ec2 delete-security-group --group-id "${SG}" --region "${REGION}" 2>/dev/null || true
done

echo ""
echo "=== Deleting Subnets and Route Tables ==="
for SUB in "${PUB_SUB_A}" "${PUB_SUB_B}" "${PRIV_SUB_A}" "${PRIV_SUB_B}"; do
    aws ec2 delete-subnet --subnet-id "${SUB}" --region "${REGION}" 2>/dev/null || true
done

# Delete route table associations and tables
for RT in $(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --region "${REGION}" --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' --output text 2>/dev/null); do
    for ASSOC in $(aws ec2 describe-route-tables --route-table-ids "${RT}" --region "${REGION}" --query 'RouteTables[0].Associations[?!Main].RouteTableAssociationId' --output text 2>/dev/null); do
        aws ec2 disassociate-route-table --association-id "${ASSOC}" --region "${REGION}" 2>/dev/null || true
    done
    aws ec2 delete-route-table --route-table-id "${RT}" --region "${REGION}" 2>/dev/null || true
done

echo ""
echo "=== Deleting Internet Gateway ==="
aws ec2 detach-internet-gateway --internet-gateway-id "${IGW_ID}" --vpc-id "${VPC_ID}" --region "${REGION}" 2>/dev/null || true
aws ec2 delete-internet-gateway --internet-gateway-id "${IGW_ID}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting VPC ==="
aws ec2 delete-vpc --vpc-id "${VPC_ID}" --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting IAM Roles ==="
for ROLE in "${PROJECT}-exec-role" "${PROJECT}-task-role" "${PROJECT}-neo4j-task-role" "${PROJECT}-efs-loader-role"; do
    # Delete inline policies first
    for POLICY in $(aws iam list-role-policies --role-name "${ROLE}" --query 'PolicyNames[*]' --output text 2>/dev/null); do
        aws iam delete-role-policy --role-name "${ROLE}" --policy-name "${POLICY}" 2>/dev/null || true
    done
    # Detach managed policies
    for ARN in $(aws iam list-attached-role-policies --role-name "${ROLE}" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null); do
        aws iam detach-role-policy --role-name "${ROLE}" --policy-arn "${ARN}" 2>/dev/null || true
    done
    aws iam delete-role --role-name "${ROLE}" 2>/dev/null || true
done

echo ""
echo "=== Deleting ECR Repository ==="
aws ecr delete-repository --repository-name "${PROJECT}" --force --region "${REGION}" 2>/dev/null || true

echo ""
echo "=== Deleting Log Groups ==="
aws logs delete-log-group --log-group-name "/ecs/${PROJECT}/app" --region "${REGION}" 2>/dev/null || true
aws logs delete-log-group --log-group-name "/ecs/${PROJECT}/neo4j" --region "${REGION}" 2>/dev/null || true

echo ""
echo "============================================"
echo "  TEARDOWN COMPLETE"
echo "============================================"
echo ""
echo "NOTE: CloudFront distribution ${CF_DIST_ID} is disabled but not yet deleted."
echo "Wait ~15min for it to fully disable, then delete with:"
echo "  aws cloudfront delete-distribution --id ${CF_DIST_ID} --if-match <etag>"
echo ""
echo "S3 staging bucket (if created) not deleted: django-bench-data-staging-${ACCOUNT_ID}"
echo "Delete manually with: aws s3 rb s3://django-bench-data-staging-${ACCOUNT_ID} --force --region ${REGION}"
