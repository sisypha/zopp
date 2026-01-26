# RDS PostgreSQL for zopp cloud
# Stores workspace data, user accounts, and audit logs

# Generate random password for database
resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Store database credentials in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "${local.name_prefix}/db-credentials"
  description             = "Database credentials for zopp ${var.environment}"
  recovery_window_in_days = var.environment == "production" ? 30 : 0

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "zopp"
    password = random_password.db_password.result
    engine   = "postgres"
    host     = module.rds.db_instance_address
    port     = module.rds.db_instance_port
    dbname   = "zopp"
  })
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "PostgreSQL from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds"
  })
}

# RDS PostgreSQL Instance
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "${local.name_prefix}-postgres"

  # Engine configuration
  engine               = "postgres"
  engine_version       = "16.3"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.db_instance_class

  # Storage
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  # Database
  db_name  = "zopp"
  username = "zopp"
  password = random_password.db_password.result
  port     = 5432

  # Network
  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  # High availability
  multi_az = var.db_multi_az

  # Backup
  backup_retention_period = var.db_backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # Protection
  deletion_protection = var.db_deletion_protection
  skip_final_snapshot = var.environment != "production"
  final_snapshot_identifier_prefix = var.environment == "production" ? "${local.name_prefix}-final" : null

  # Performance Insights
  performance_insights_enabled          = var.enable_monitoring
  performance_insights_retention_period = var.enable_monitoring ? 7 : 0

  # Enhanced Monitoring
  monitoring_interval                   = var.enable_monitoring ? 60 : 0
  monitoring_role_name                  = var.enable_monitoring ? "${local.name_prefix}-rds-monitoring" : null
  create_monitoring_role                = var.enable_monitoring
  monitoring_role_use_name_prefix       = false

  # CloudWatch Logs
  enabled_cloudwatch_logs_exports = var.enable_monitoring ? ["postgresql", "upgrade"] : []

  # Parameter group
  parameters = [
    {
      name  = "log_statement"
      value = "ddl"
    },
    {
      name  = "log_min_duration_statement"
      value = "1000" # Log queries taking more than 1 second
    }
  ]

  tags = local.common_tags
}
