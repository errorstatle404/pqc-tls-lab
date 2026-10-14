# Extra AWS-managed crypto for the inventory to find. Both are optional (see variables).
#
#   Internal ALB with two HTTPS listeners in front of the lab server:
#     :443   ELBSecurityPolicy-2016-08            the policy AWS applies when an API/CLI/Terraform
#                                                  listener names none: TLS 1.0-1.2, no TLS 1.3, no PQ
#     :9443  ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09   hybrid ML-KEM key exchange
#   The certificate is a self-signed ECDSA P-256 cert imported into ACM (no domain validation needed).
#
#   Two KMS signing keys: RSA_3072 (quantum-vulnerable) and ML_DSA_65 (post-quantum).

locals {
  alb_fqdn = "alb.${var.private_domain}"
}

# ---------------- certificate ----------------
resource "tls_private_key" "alb" {
  count       = var.create_load_balancer ? 1 : 0
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "alb" {
  count           = var.create_load_balancer ? 1 : 0
  private_key_pem = tls_private_key.alb[0].private_key_pem
  subject {
    common_name  = local.alb_fqdn
    organization = "PQC TLS Lab"
  }
  dns_names             = [local.alb_fqdn]
  validity_period_hours = 24 * 90
  allowed_uses          = ["digital_signature", "server_auth"]
}

resource "aws_acm_certificate" "alb" {
  count            = var.create_load_balancer ? 1 : 0
  private_key      = tls_private_key.alb[0].private_key_pem
  certificate_body = tls_self_signed_cert.alb[0].cert_pem
  tags             = { Name = "${var.name}-alb" }

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------- load balancer ----------------
resource "aws_security_group" "alb" {
  count       = var.create_load_balancer ? 1 : 0
  name        = "${var.name}-alb"
  description = "PQC TLS lab ALB: HTTPS 443 and 9443 from inside the VPC"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.name}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb" {
  for_each          = var.create_load_balancer ? toset(["443", "9443"]) : toset([])
  security_group_id = aws_security_group.alb[0].id
  description       = "HTTPS listener ${each.key} from the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
}

resource "aws_vpc_security_group_egress_rule" "alb_to_server" {
  count                        = var.create_load_balancer ? 1 : 0
  security_group_id            = aws_security_group.alb[0].id
  description                  = "To the lab server's classical endpoint"
  referenced_security_group_id = aws_security_group.server.id
  ip_protocol                  = "tcp"
  from_port                    = 8444
  to_port                      = 8444
}

resource "aws_lb" "lab" {
  count                      = var.create_load_balancer ? 1 : 0
  name                       = "${var.name}-alb"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb[0].id]
  subnets                    = local.instance_subnets
  drop_invalid_header_fields = true
  tags                       = { Name = "${var.name}-alb" }
}

resource "aws_lb_target_group" "server" {
  count       = var.create_load_balancer ? 1 : 0
  name        = "${var.name}-server"
  port        = 8444
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.lab.id
  target_type = "instance"

  health_check {
    protocol = "HTTPS"
    path     = "/"
    matcher  = "200"
  }
}

resource "aws_lb_target_group_attachment" "server" {
  count            = var.create_load_balancer ? 1 : 0
  target_group_arn = aws_lb_target_group.server[0].arn
  target_id        = aws_instance.server.id
  port             = 8444
}

resource "aws_lb_listener" "legacy" {
  count             = var.create_load_balancer ? 1 : 0
  load_balancer_arn = aws_lb.lab[0].arn
  port              = 443
  protocol          = "HTTPS"
  # Deliberately the API default, to show what an unconfigured listener looks like.
  ssl_policy      = "ELBSecurityPolicy-2016-08"
  certificate_arn = aws_acm_certificate.alb[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server[0].arn
  }
}

resource "aws_lb_listener" "pq" {
  count             = var.create_load_balancer ? 1 : 0
  load_balancer_arn = aws_lb.lab[0].arn
  port              = 9443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  certificate_arn   = aws_acm_certificate.alb[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server[0].arn
  }
}

resource "aws_route53_record" "alb" {
  count   = var.create_load_balancer ? 1 : 0
  zone_id = aws_route53_zone.lab.zone_id
  name    = local.alb_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.lab[0].dns_name
    zone_id                = aws_lb.lab[0].zone_id
    evaluate_target_health = false
  }
}

# ---------------- KMS signing keys ----------------
resource "aws_kms_key" "classical_signing" {
  count                    = var.create_kms_keys ? 1 : 0
  description              = "${var.name}: classical RSA-3072 signing key (quantum-vulnerable)"
  customer_master_key_spec = "RSA_3072"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "classical_signing" {
  count         = var.create_kms_keys ? 1 : 0
  name          = "alias/${var.name}-rsa-signing"
  target_key_id = aws_kms_key.classical_signing[0].key_id
}

resource "aws_kms_key" "pq_signing" {
  count                    = var.create_kms_keys ? 1 : 0
  description              = "${var.name}: ML-DSA-65 signing key (post-quantum, FIPS 204)"
  customer_master_key_spec = "ML_DSA_65"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 7
}

resource "aws_kms_alias" "pq_signing" {
  count         = var.create_kms_keys ? 1 : 0
  name          = "alias/${var.name}-mldsa-signing"
  target_key_id = aws_kms_key.pq_signing[0].key_id
}
