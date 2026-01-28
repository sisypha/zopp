# Zopp Cloud Infrastructure

Terraform configuration for deploying zopp as a SaaS offering on AWS.

## Architecture

- **VPC**: Multi-AZ VPC with public, private, and database subnets
- **EKS**: Managed Kubernetes cluster for running zopp workloads
- **RDS**: PostgreSQL database for persistent storage
- **ECR**: Container registry for zopp images
- **Secrets Manager**: Secure storage for database credentials
- **Route53**: DNS management (optional)
- **ACM**: SSL/TLS certificates (optional)

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Terraform >= 1.5
3. kubectl (for EKS management)
4. Helm 3 (for deploying zopp chart)

## Quick Start

### 1. Initialize Terraform

```bash
cd infra/terraform
terraform init
```

### 2. Deploy Staging Environment

```bash
terraform plan -var-file=environments/staging.tfvars
terraform apply -var-file=environments/staging.tfvars
```

### 3. Configure kubectl

```bash
aws eks update-kubeconfig --region us-east-1 --name zopp-staging
```

### 4. Deploy zopp

```bash
helm upgrade --install zopp ../charts/zopp \
  --namespace zopp --create-namespace \
  --set server.database.type=postgres \
  --set server.database.existingSecret=zopp-db-credentials
```

## State Management

For team collaboration, configure remote state in S3:

```bash
# Create S3 bucket for state
aws s3 mb s3://zopp-terraform-state --region us-east-1

# Create DynamoDB table for locking
aws dynamodb create-table \
  --table-name zopp-terraform-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1

# Initialize with backend
terraform init -backend-config="bucket=zopp-terraform-state" \
  -backend-config="key=staging/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="encrypt=true" \
  -backend-config="dynamodb_table=zopp-terraform-lock"
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `environment` | staging or production | required |
| `aws_region` | AWS region | us-east-1 |
| `vpc_cidr` | VPC CIDR block | 10.0.0.0/16 |
| `eks_cluster_version` | Kubernetes version | 1.29 |
| `eks_node_instance_types` | Node instance types | ["t3.medium"] |
| `db_instance_class` | RDS instance class | db.t3.medium |
| `db_multi_az` | Enable Multi-AZ RDS | false |
| `create_dns` | Create Route53 zone | false |
| `domain_name` | Domain for the app | "" |

## Outputs

After applying, these outputs are available:

- `eks_cluster_name`: Name of the EKS cluster
- `eks_kubeconfig_command`: Command to configure kubectl
- `rds_endpoint`: Database endpoint
- `rds_credentials_secret_arn`: ARN of Secrets Manager secret
- `ecr_*_repository_url`: ECR repository URLs
- `github_actions_role_arn`: IAM role for CI/CD

## Costs

Estimated monthly costs (staging):
- EKS: ~$75 (control plane + 2x t3.medium)
- RDS: ~$25 (db.t3.small, single-AZ)
- VPC NAT Gateway: ~$35
- Total: ~$135/month

Estimated monthly costs (production):
- EKS: ~$250 (control plane + 3x t3.large)
- RDS: ~$100 (db.t3.medium, Multi-AZ)
- VPC NAT Gateways: ~$100 (3x for HA)
- Total: ~$450/month

## Security

- All data is encrypted at rest (EBS, RDS, S3)
- Database credentials stored in Secrets Manager
- IRSA (IAM Roles for Service Accounts) for pod permissions
- Private subnets for workloads
- Security groups restrict traffic flow

## Maintenance

### Updating EKS Version

1. Update `eks_cluster_version` in tfvars
2. Run `terraform apply`
3. EKS will perform a rolling update of the control plane
4. Update managed node groups via Terraform

### Database Backups

RDS automated backups are enabled with configurable retention.
To restore from a snapshot:

```bash
terraform import module.rds.aws_db_instance.this <db-instance-id>
```

## Cleanup

To destroy all resources:

```bash
# Disable deletion protection first (for production)
terraform apply -var-file=environments/production.tfvars \
  -var="db_deletion_protection=false"

# Then destroy
terraform destroy -var-file=environments/production.tfvars
```

**Warning**: This will delete all data. Take backups first!
