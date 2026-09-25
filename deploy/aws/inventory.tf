# ---- Extra targets for the crypto inventory (make aws-inventory) ----
#
# An internal Application Load Balancer with two HTTPS listeners, one on a legacy security
# policy and one on AWS's post-quantum policy, plus two KMS signing keys (classical ECDSA
# P-256 and ML-DSA-65). The inventory has to find all of them through the AWS APIs and
# classify them correctly. Together they add about 3 cents an hour.
#
# Set create_inventory_targets = false to skip them.

locals {
  inv        = var.create_inventory_targets ? 1 : 0
  alb_domain = "alb.${var.private_domain}"

  alb_legacy_policy = "ELBSecurityPolicy-2016-08"                  # AWS CLI/API default: TLS 1.0-1.2, no PQ
  alb_pq_policy     = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09" # console default since 2025: hybrid ML-KEM
}

# The listeners need a certificate. A self-signed one imported into ACM is free; a private CA
# would cost $400 a month. The private key ends up in the Terraform state (fine for a lab).
resource "tls_private_key" "alb" {
  count       = local.inv
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "alb" {
  count           = local.inv
  private_key_pem = tls_private_key.alb[0].private_key_pem

  subject {
    common_name  = local.alb_domain
    organization = "PQC TLS Lab"
  }
  dns_names             = [local.alb_domain]
  validity_period_hours = 24 * 90
  allowed_uses          = ["digital_signature", "server_auth"]
}

resource "aws_acm_certificate" "alb" {
  count            = local.inv
  private_key      = tls_private_key.alb[0].private_key_pem
  certificate_body = tls_self_signed_cert.alb[0].cert_pem
  tags             = { Name = "${var.name}-alb" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "alb" {
  count       = local.inv
  name        = "${var.name}-alb"
  description = "PQC TLS lab ALB: HTTPS listeners from inside the VPC only"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.name}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each          = var.create_inventory_targets ? toset(["443", "8443"]) : toset([])
  security_group_id = aws_security_group.alb[0].id
  description       = "HTTPS listener ${each.value} from the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

resource "aws_lb" "lab" {
  count                      = local.inv
  name                       = "${var.name}-alb"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb[0].id]
  subnets                    = aws_subnet.public[*].id # two AZs; internal, so private IPs only
  drop_invalid_header_fields = true
  tags                       = { Name = "${var.name}-alb" }
}

# The listeners answer directly (fixed response), so there are no targets to keep healthy.
# Only the TLS handshake matters to the inventory.
resource "aws_lb_listener" "legacy" {
  count             = local.inv
  load_balancer_arn = aws_lb.lab[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.alb_legacy_policy
  certificate_arn   = aws_acm_certificate.alb[0].arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "listener=legacy policy=${local.alb_legacy_policy}\n"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener" "pq" {
  count             = local.inv
  load_balancer_arn = aws_lb.lab[0].arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = local.alb_pq_policy
  certificate_arn   = aws_acm_certificate.alb[0].arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "listener=pq policy=${local.alb_pq_policy}\n"
      status_code  = "200"
    }
  }
}

resource "aws_route53_record" "alb" {
  count   = local.inv
  zone_id = aws_route53_zone.lab.zone_id
  name    = local.alb_domain
  type    = "A"

  alias {
    name                   = aws_lb.lab[0].dns_name
    zone_id                = aws_lb.lab[0].zone_id
    evaluate_target_health = false
  }
}

# ---- KMS signing keys: one classical, one post-quantum (FIPS 204 ML-DSA) ----
# $1 a month each, billed hourly. Keys scheduled for deletion are not billed, and
# `make aws-down` schedules them with the shortest window AWS allows (7 days).

resource "aws_kms_key" "sign_classical" {
  count                    = local.inv
  description              = "${var.name}: classical signing key (ECDSA P-256)"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "sign_classical" {
  count         = local.inv
  name          = "alias/${var.name}-sign-ecdsa"
  target_key_id = aws_kms_key.sign_classical[0].key_id
}

resource "aws_kms_key" "sign_pq" {
  count                    = local.inv
  description              = "${var.name}: post-quantum signing key (ML-DSA-65)"
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "sign_pq" {
  count         = local.inv
  name          = "alias/${var.name}-sign-mldsa"
  target_key_id = aws_kms_key.sign_pq[0].key_id
}
