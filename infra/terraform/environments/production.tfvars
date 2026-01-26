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
