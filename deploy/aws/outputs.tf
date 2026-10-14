output "region" {
  value = var.region
}

output "vpc_id" {
  value = aws_vpc.lab.id
}

output "server_instance_id" {
  value = aws_instance.server.id
}

output "server_private_ip" {
  value = aws_instance.server.private_ip
}

output "server_fqdn" {
  description = "Private DNS name of the lab server (resolvable inside the VPC only)."
  value       = aws_route53_record.server.fqdn
}

output "server_public_ip" {
  description = "Only set when use_nat_gateway = false. Reachable only from allowed_cidrs."
  value       = aws_instance.server.public_ip
}

output "scanner_instance_id" {
  value = try(aws_instance.scanner[0].id, null)
}

output "bucket" {
  value = aws_s3_bucket.lab.id
}

output "nginx_log_group" {
  value = aws_cloudwatch_log_group.nginx.name
}

output "how_to" {
  description = "Copy-paste commands for the next steps."
  value = {
    watch_bootstrap = "aws ssm start-session --region ${var.region} --target ${try(aws_instance.scanner[0].id, aws_instance.server.id)}   # then: sudo tail -f /var/log/pqc-lab-bootstrap.log"
    run_bench       = "make aws-bench   (or in a session on the scanner: sudo pqc-lab bench && sudo pqc-lab upload)"
    fetch_results   = "aws s3 sync s3://${aws_s3_bucket.lab.id}/results ./results/aws --region ${var.region}"
    negotiated      = "CloudWatch > Logs Insights > saved query '${aws_cloudwatch_query_definition.groups.name}'"
    tail_nginx_log  = "aws logs tail ${aws_cloudwatch_log_group.nginx.name} --follow --region ${var.region}"
    teardown        = "make aws-down"
  }
}

# What a correct crypto inventory should report for this lab. `make aws-inventory` scores the
# inventory against it: anything reported differently is either a finding or a bug.
output "inventory_ground_truth" {
  value = {
    description = "Known answers for the PQC TLS lab in AWS"
    endpoints = concat(
      [
        { host = local.server_fqdn, port = 8444, name = "server: classical",
        expected_posture = ["none"], expected_default_group = ["x25519"] },
        { host = local.server_fqdn, port = 8443, name = "server: hybrid (preferred)",
        expected_posture = ["not-enforced"], expected_default_group = ["X25519MLKEM768"] },
        { host = local.server_fqdn, port = 8446, name = "server: hybrid (strict, HelloRetryRequest)",
        expected_posture = ["enforced"], expected_default_group = ["X25519MLKEM768"] },
        { host = local.server_fqdn, port = 8445, name = "server: pure post-quantum (ML-DSA-65 certs)",
        expected_posture = ["pq-only"], expected_default_group = ["handshake_failure"] },
      ],
      [for e in [
        { host = try(aws_lb.lab[0].dns_name, ""), port = 443, name = "ALB: ELBSecurityPolicy-2016-08 (API default)",
        expected_posture = ["no-tls13"], expected_default_group = ["handshake_failure"] },
        # AWS documents hybrid support for this policy; whether it *enforces* hybrid is what the probe finds out.
        { host = try(aws_lb.lab[0].dns_name, ""), port = 9443, name = "ALB: ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
        expected_posture = ["enforced", "not-enforced"], expected_default_group = ["X25519MLKEM768"] },
      ] : e if var.create_load_balancer]
    )
  }
}

output "alb_dns_name" {
  value = try(aws_lb.lab[0].dns_name, null)
}
