# Staging environment configuration

environment = "staging"
aws_region  = "us-east-1"

# VPC
vpc_cidr = "10.0.0.0/16"

# EKS - smaller for staging
eks_cluster_version     = "1.29"
eks_node_instance_types = ["t3.medium"]
eks_node_min_size       = 2
eks_node_max_size       = 4
eks_node_desired_size   = 2
# SECURITY: Configure with your VPN/office/CI runner IP ranges
# Example: ["10.0.0.0/8", "203.0.113.0/24"]
# Using 0.0.0.0/0 for staging - replace with actual CIDRs for real deployment
eks_public_access_cidrs = ["0.0.0.0/0"]

# RDS - smaller for staging
db_instance_class          = "db.t3.small"
db_allocated_storage       = 20
db_max_allocated_storage   = 50
db_multi_az                = false
db_backup_retention_period = 7
db_deletion_protection     = false

# DNS - disabled for staging by default
create_dns  = false
domain_name = ""

# Monitoring
enable_monitoring  = true
log_retention_days = 14
