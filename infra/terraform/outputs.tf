# Terraform outputs for zopp cloud infrastructure

# VPC Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

# EKS Outputs
output "eks_cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

output "eks_oidc_provider_arn" {
  description = "EKS OIDC provider ARN for IRSA"
  value       = module.eks.oidc_provider_arn
}

output "eks_kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

# RDS Outputs
output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.rds.db_instance_endpoint
}

output "rds_address" {
  description = "RDS instance address"
  value       = module.rds.db_instance_address
}

output "rds_port" {
  description = "RDS instance port"
  value       = module.rds.db_instance_port
}

output "rds_database_name" {
  description = "RDS database name"
  value       = module.rds.db_instance_name
}

output "rds_credentials_secret_arn" {
  description = "ARN of Secrets Manager secret containing database credentials"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

# ECR Outputs
output "ecr_server_repository_url" {
  description = "ECR repository URL for zopp-server"
  value       = aws_ecr_repository.server.repository_url
}

output "ecr_operator_repository_url" {
  description = "ECR repository URL for zopp-operator"
  value       = aws_ecr_repository.operator.repository_url
}

output "ecr_web_repository_url" {
  description = "ECR repository URL for zopp-web"
  value       = aws_ecr_repository.web.repository_url
}

# IAM Outputs
output "zopp_server_role_arn" {
  description = "IAM role ARN for zopp-server pod"
  value       = module.zopp_server_irsa_role.iam_role_arn
}

output "zopp_operator_role_arn" {
  description = "IAM role ARN for zopp-operator pod"
  value       = module.zopp_operator_irsa_role.iam_role_arn
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions CI/CD"
  value       = aws_iam_role.github_actions.arn
}

output "load_balancer_controller_role_arn" {
  description = "IAM role ARN for AWS Load Balancer Controller"
  value       = module.load_balancer_controller_irsa_role.iam_role_arn
}

output "external_dns_role_arn" {
  description = "IAM role ARN for External DNS"
  value       = module.external_dns_irsa_role.iam_role_arn
}

# DNS Outputs (conditional)
output "route53_zone_id" {
  description = "Route53 hosted zone ID"
  value       = var.create_dns && var.domain_name != "" ? aws_route53_zone.main[0].zone_id : null
}

output "route53_nameservers" {
  description = "Route53 nameservers for the hosted zone"
  value       = var.create_dns && var.domain_name != "" ? aws_route53_zone.main[0].name_servers : null
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  value       = var.create_dns && var.domain_name != "" ? aws_acm_certificate.main[0].arn : null
}

# Database URL (for local development reference)
output "database_url_template" {
  description = "Template for DATABASE_URL (retrieve password from Secrets Manager)"
  value       = "postgres://zopp:<password>@${module.rds.db_instance_address}:${module.rds.db_instance_port}/zopp"
  sensitive   = false
}
