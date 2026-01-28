# VPC Configuration for zopp cloud
# Uses AWS VPC module for best practices

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 48)]
  intra_subnets   = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 52)]

  # Database subnets for RDS
  database_subnets                   = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 56)]
  create_database_subnet_group       = true
  create_database_subnet_route_table = true

  # NAT Gateway for private subnet internet access
  enable_nat_gateway     = true
  single_nat_gateway     = var.environment == "staging" ? true : false
  one_nat_gateway_per_az = var.environment == "production" ? true : false

  # DNS settings
  enable_dns_hostnames = true
  enable_dns_support   = true

  # VPC Flow Logs
  enable_flow_log                                 = var.enable_monitoring
  create_flow_log_cloudwatch_log_group           = var.enable_monitoring
  create_flow_log_cloudwatch_iam_role            = var.enable_monitoring
  flow_log_cloudwatch_log_group_retention_in_days = var.log_retention_days
  flow_log_max_aggregation_interval              = 60

  # Tags required for EKS
  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = 1
    "kubernetes.io/cluster/${local.name_prefix}" = "owned"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = 1
    "kubernetes.io/cluster/${local.name_prefix}" = "owned"
  }

  tags = local.common_tags
}
