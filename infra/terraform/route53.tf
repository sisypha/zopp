# Route53 DNS Configuration for zopp cloud
# Creates hosted zone and records for the application domain

# Hosted zone (only created if domain is provided)
resource "aws_route53_zone" "main" {
  count = var.create_dns && var.domain_name != "" ? 1 : 0

  name    = var.domain_name
  comment = "Hosted zone for zopp ${var.environment}"

  tags = local.common_tags
}

# ACM Certificate for HTTPS
resource "aws_acm_certificate" "main" {
  count = var.create_dns && var.domain_name != "" ? 1 : 0

  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# DNS validation records for ACM certificate
resource "aws_route53_record" "cert_validation" {
  for_each = var.create_dns && var.domain_name != "" ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.main[0].zone_id
}

# Certificate validation
resource "aws_acm_certificate_validation" "main" {
  count = var.create_dns && var.domain_name != "" ? 1 : 0

  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}
