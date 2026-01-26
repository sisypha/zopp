# Production environment configuration

environment = "production"
aws_region  = "us-east-1"

# VPC
vpc_cidr = "10.1.0.0/16"

# EKS - larger for production
eks_cluster_version     = "1.29"
eks_node_instance_types = ["t3.large", "t3.xlarge"]
eks_node_min_size       = 3
eks_node_max_size       = 10
eks_node_desired_size   = 3
# SECURITY: MUST configure with your VPN/office/CI runner IP ranges before deployment
# Default uses RFC 5737 TEST-NET addresses (routed nowhere) as safe placeholder
# Replace with actual CIDRs, e.g.: ["10.0.0.0/8", "YOUR.VPN.IP/32"]
eks_public_access_cidrs = ["192.0.2.0/24"]  # TEST-NET-1 - replace before deployment

# RDS - production-grade
db_instance_class          = "db.t3.medium"
db_allocated_storage       = 50
db_max_allocated_storage   = 200
db_multi_az                = true
db_backup_retention_period = 30
db_deletion_protection     = true

# DNS - configure your domain
create_dns  = true
domain_name = "zopp.dev"

# Monitoring
enable_monitoring  = true
log_retention_days = 90
