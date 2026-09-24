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

# What a correct crypto inventory should report for this server. Use it later to score
# the inventory tool: anything it reports differently is either a finding or a bug.
output "inventory_ground_truth" {
  value = {
    host = aws_route53_record.server.fqdn
    ip   = aws_instance.server.private_ip
    endpoints = {
      "8444" = {
        name                    = "classical"
        groups_offered          = ["x25519", "secp256r1"]
        cert_chain              = "ECDSA P-256 (lab root CA)"
        pq_key_exchange         = "never"
        expected_default_client = "x25519"
      }
      "8443" = {
        name                    = "hybrid (preferred)"
        groups_offered          = ["X25519MLKEM768", "x25519", "secp256r1"]
        cert_chain              = "ECDSA P-256 (lab root CA)"
        pq_key_exchange         = "only if the client sends an X25519MLKEM768 key share first"
        expected_default_client = "X25519MLKEM768"
      }
      "8446" = {
        name                    = "hybrid (strict, HelloRetryRequest)"
        groups_offered          = ["X25519MLKEM768", "x25519", "secp256r1"]
        cert_chain              = "ECDSA P-256 (lab root CA)"
        pq_key_exchange         = "whenever the client supports X25519MLKEM768"
        expected_default_client = "X25519MLKEM768"
      }
      "8445" = {
        name                    = "pure post-quantum"
        groups_offered          = ["MLKEM1024"]
        cert_chain              = "ML-DSA-65 (lab root CA)"
        pq_key_exchange         = "always; classical-only and default clients fail"
        expected_default_client = "handshake_failure"
      }
    }
  }
}
