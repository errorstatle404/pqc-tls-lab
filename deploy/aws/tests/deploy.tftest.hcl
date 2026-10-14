# Offline tests: the AWS provider is mocked, so these need no credentials and create nothing.
#   terraform test      (or: tofu test)

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a", "us-east-1b", "us-east-1c"] }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "ami-0123456789abcdef0", value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { id = "pqc-tls-lab-test", arn = "arn:aws:s3:::pqc-tls-lab-test" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/pqc-tls-lab/nginx" }
  }
  mock_resource "aws_instance" {
    defaults = { private_ip = "10.42.0.10" }
  }
  mock_resource "aws_lb_target_group" {
    defaults = { arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/pqc-tls-lab-server/abc" }
  }
  mock_resource "aws_acm_certificate" {
    defaults = { arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_lb" {
    defaults = { dns_name = "internal-pqc-tls-lab-alb-123.us-east-1.elb.amazonaws.com", arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/pqc-tls-lab-alb/abc" }
  }
}

run "default_is_cheap_and_closed" {
  command = apply

  assert {
    condition     = length(aws_nat_gateway.lab) == 0
    error_message = "No NAT gateway by default."
  }
  assert {
    condition     = aws_instance.server.subnet_id == aws_subnet.public[0].id && aws_instance.server.associate_public_ip_address
    error_message = "Without NAT the server must be in a public subnet with a public IP for egress."
  }
  assert {
    condition     = aws_instance.scanner[0].subnet_id == aws_subnet.public[1].id
    error_message = "Scanner must be in the second AZ."
  }
  assert {
    condition     = aws_subnet.public[0].availability_zone != aws_subnet.public[1].availability_zone
    error_message = "Public subnets must be in different AZs."
  }
  assert {
    condition     = aws_instance.server.instance_type == "t4g.small"
    error_message = "arm64 default should pick t4g.small."
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.server_tls_extra) == 0
    error_message = "No internet ingress unless allowed_cidrs is set."
  }
  assert {
    condition = (
      aws_vpc_security_group_ingress_rule.server_tls_vpc.cidr_ipv4 == "10.42.0.0/16" &&
      aws_vpc_security_group_ingress_rule.server_tls_vpc.from_port == 8443 &&
      aws_vpc_security_group_ingress_rule.server_tls_vpc.to_port == 8446
    )
    error_message = "Server ingress must be 8443-8446 from the VPC CIDR only."
  }
  assert {
    condition     = aws_instance.server.metadata_options[0].http_tokens == "required" && aws_instance.server.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 required, hop limit 1."
  }
  assert {
    condition     = aws_instance.server.root_block_device[0].encrypted && aws_instance.scanner[0].root_block_device[0].encrypted
    error_message = "Root volumes must be encrypted."
  }
  assert {
    condition     = strcontains(aws_instance.server.user_data, "LAB_CN=\"pqc-server.lab.internal\"")
    error_message = "Server certificates must be issued for the private DNS name."
  }
  assert {
    condition     = strcontains(aws_instance.scanner[0].user_data, "SERVER=\"pqc-server.lab.internal\"")
    error_message = "Scanner must target the private DNS name."
  }
  assert {
    condition     = !strcontains(aws_instance.scanner[0].user_data, "$$$${")
    error_message = "Template escaping left an escaped $$$${ in the scanner script."
  }
  assert {
    condition     = aws_route53_record.server.records == toset(["10.42.0.10"])
    error_message = "DNS record must point at the server's private IP."
  }
  assert {
    condition     = startswith(aws_s3_object.bundle.key, "bundle/pqc-tls-lab-")
    error_message = "Bundle key must be content-addressed."
  }
  assert {
    condition     = length(output.inventory_ground_truth.endpoints) == 6
    error_message = "Ground truth should list 4 server endpoints + 2 ALB listeners."
  }
  assert {
    condition     = aws_lb.lab[0].internal && aws_lb_listener.legacy[0].ssl_policy == "ELBSecurityPolicy-2016-08" && aws_lb_listener.pq[0].ssl_policy == "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
    error_message = "Internal ALB with one legacy-policy listener and one PQ-policy listener expected."
  }
  assert {
    condition     = aws_kms_key.pq_signing[0].customer_master_key_spec == "ML_DSA_65" && aws_kms_key.classical_signing[0].customer_master_key_spec == "RSA_3072"
    error_message = "One ML-DSA-65 and one RSA-3072 KMS signing key expected."
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.alb_to_server[0].from_port == 8444 && aws_vpc_security_group_egress_rule.alb_to_server[0].to_port == 8444
    error_message = "ALB may only talk to the server's classical endpoint."
  }
}

run "nat_moves_instances_private" {
  command = apply

  variables {
    use_nat_gateway = true
    architecture    = "x86_64"
    allowed_cidrs   = ["203.0.113.7/32"]
  }

  assert {
    condition     = length(aws_nat_gateway.lab) == 1 && length(aws_route.private_default) == 1
    error_message = "NAT gateway and private default route expected."
  }
  assert {
    condition     = aws_instance.server.subnet_id == aws_subnet.private[0].id && !aws_instance.server.associate_public_ip_address
    error_message = "With NAT the server must be private with no public IP."
  }
  assert {
    condition     = aws_instance.server.instance_type == "t3.small"
    error_message = "x86_64 should pick t3.small."
  }
  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.server_tls_extra) == 1
    error_message = "allowed_cidrs should create one extra ingress rule."
  }
}

run "no_scanner" {
  command = apply
  variables { create_scanner = false }

  assert {
    condition     = length(aws_instance.scanner) == 0 && length(aws_iam_role.scanner) == 0
    error_message = "create_scanner = false must skip the scanner and its role."
  }
}

run "minimal_no_alb_no_kms" {
  command = apply
  variables {
    create_load_balancer = false
    create_kms_keys      = false
  }

  assert {
    condition     = length(aws_lb.lab) == 0 && length(aws_acm_certificate.alb) == 0 && length(aws_kms_key.pq_signing) == 0
    error_message = "Optional ALB and KMS keys must be skippable."
  }
  assert {
    condition     = length(output.inventory_ground_truth.endpoints) == 4
    error_message = "Without the ALB the ground truth has only the 4 server endpoints."
  }
}

run "rejects_open_internet" {
  command = plan
  variables { allowed_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.allowed_cidrs]
}
