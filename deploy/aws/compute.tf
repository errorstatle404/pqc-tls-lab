data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${var.architecture}"
}

locals {
  instance_type = coalesce(var.instance_type, var.architecture == "arm64" ? "t4g.small" : "t3.small")
  server_fqdn   = "pqc-server.${var.private_domain}"

  common_template_vars = {
    region     = var.region
    bucket     = aws_s3_bucket.lab.id
    bundle_key = aws_s3_object.bundle.key
  }
}

resource "aws_instance" "server" {
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = local.instance_type
  subnet_id                   = local.instance_subnets[0]
  vpc_security_group_ids      = [aws_security_group.server.id]
  iam_instance_profile        = aws_iam_instance_profile.server.name
  associate_public_ip_address = !var.use_nat_gateway

  user_data = templatefile("${path.module}/templates/server-user-data.sh.tftpl", merge(local.common_template_vars, {
    lab_cn    = local.server_fqdn
    log_group = aws_cloudwatch_log_group.nginx.name
  }))
  user_data_replace_on_change = true

  metadata_options {
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1          # containers cannot reach instance credentials
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
  }

  tags = { Name = "${var.name}-server", Role = "pqc-tls-server" }

  lifecycle {
    ignore_changes = [ami] # a new AL2023 release should not rebuild the lab
  }

  # The instance needs these before its first boot script runs.
  depends_on = [
    aws_iam_role_policy.server,
    aws_iam_role_policy_attachment.server_ssm,
    aws_s3_bucket_policy.lab,
    aws_route.public_default,
    aws_route.private_default,
    aws_vpc_endpoint.s3,
  ]
}

resource "aws_instance" "scanner" {
  count                       = var.create_scanner ? 1 : 0
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = local.instance_type
  subnet_id                   = local.instance_subnets[1] # other AZ from the server
  vpc_security_group_ids      = [aws_security_group.scanner.id]
  iam_instance_profile        = aws_iam_instance_profile.scanner[0].name
  associate_public_ip_address = !var.use_nat_gateway

  user_data = templatefile("${path.module}/templates/scanner-user-data.sh.tftpl", merge(local.common_template_vars, {
    server_fqdn = local.server_fqdn
  }))
  user_data_replace_on_change = true

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 16
    encrypted   = true
  }

  tags = { Name = "${var.name}-scanner", Role = "pqc-tls-scanner" }

  lifecycle {
    ignore_changes = [ami]
  }

  depends_on = [
    aws_iam_role_policy.scanner,
    aws_iam_role_policy_attachment.scanner_ssm,
    aws_s3_bucket_policy.lab,
    aws_route.public_default,
    aws_route.private_default,
    aws_vpc_endpoint.s3,
  ]
}
