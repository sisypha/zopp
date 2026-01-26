# IAM Roles and Policies for zopp cloud applications

# IAM Role for zopp-server (for accessing Secrets Manager, etc.)
module "zopp_server_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name = "${local.name_prefix}-server"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["zopp:zopp-server"]
    }
  }

  tags = local.common_tags
}

# Policy for zopp-server to access Secrets Manager
resource "aws_iam_role_policy" "zopp_server_secrets" {
  name = "${local.name_prefix}-server-secrets"
  role = module.zopp_server_irsa_role.iam_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.db_credentials.arn
        ]
      }
    ]
  })
}

# IAM Role for zopp-operator (for Kubernetes operations)
module "zopp_operator_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name = "${local.name_prefix}-operator"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["zopp:zopp-operator"]
    }
  }

  tags = local.common_tags
}

# Policy for zopp-operator to manage secrets (if needed for external secrets)
resource "aws_iam_role_policy" "zopp_operator_secrets" {
  name = "${local.name_prefix}-operator-secrets"
  role = module.zopp_operator_irsa_role.iam_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${local.name_prefix}/*"
        ]
      }
    ]
  })
}

# CI/CD Role for GitHub Actions
# SECURITY: Restricted to trusted refs (main branch, release tags) to prevent
# untrusted branches from gaining deployment permissions
resource "aws_iam_role" "github_actions" {
  name = "${local.name_prefix}-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          # Only allow deployments from main branch and release tags
          # This prevents untrusted feature branches from deploying
          ForAnyValue:StringLike = {
            "token.actions.githubusercontent.com:sub" = [
              "repo:faiscadev/zopp:ref:refs/heads/main",
              "repo:faiscadev/zopp:ref:refs/tags/v*"
            ]
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# Policy for GitHub Actions to push to ECR and update EKS
resource "aws_iam_role_policy" "github_actions" {
  name = "${local.name_prefix}-github-actions"
  role = aws_iam_role.github_actions.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # GetAuthorizationToken requires "*" resource - it's account-level
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      # Scope image operations to zopp repositories only
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:PutImage"
        ]
        Resource = [
          "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${local.name_prefix}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = module.eks.cluster_arn
      }
    ]
  })
}
