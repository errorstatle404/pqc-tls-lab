# ---- S3: lab source bundle in, CA certs across, benchmark results out ----

resource "aws_s3_bucket" "lab" {
  bucket_prefix = "${var.name}-"
  force_destroy = true # lab bucket: `terraform destroy` also empties it
  tags          = { Name = "${var.name}-artifacts" }
}

resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# Refuse any request that is not over TLS 1.2+ (fitting, for a TLS lab).
resource "aws_s3_bucket_policy" "lab" {
  bucket = aws_s3_bucket.lab.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.lab.arn, "${aws_s3_bucket.lab.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyOldTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.lab.arn, "${aws_s3_bucket.lab.arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.lab]
}

locals {
  lab_source_dir = coalesce(var.lab_source_dir, "${path.module}/../..")
}

# Zip the lab repo (minus Terraform state, build output and results) and upload it.
# The object key contains the zip's hash, so changing the lab replaces the instances.
data "archive_file" "lab" {
  type        = "zip"
  source_dir  = local.lab_source_dir
  output_path = "${path.module}/.build/pqc-tls-lab.zip"
  excludes = [
    ".git/**",
    "deploy/**",
    "results/**",
    "**/*.pcap",
    "**/.DS_Store",
    ".venv/**", # the inventory tool's Python env (make inventory-setup) stays on your laptop
    "**/__pycache__/**",
    "**/.pytest_cache/**",
  ]
}

resource "aws_s3_object" "bundle" {
  bucket = aws_s3_bucket.lab.id
  key    = "bundle/pqc-tls-lab-${data.archive_file.lab.output_md5}.zip"
  source = data.archive_file.lab.output_path
  etag   = data.archive_file.lab.output_md5
}

# ---- CloudWatch: nginx access log with the negotiated group of every request ----

resource "aws_cloudwatch_log_group" "nginx" {
  name              = "/${var.name}/nginx"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_query_definition" "groups" {
  name            = "${var.name}/negotiated-groups-by-port"
  log_group_names = [aws_cloudwatch_log_group.nginx.name]
  query_string    = <<-EOT
    fields @timestamp, @message
    | filter @message like /group=/
    | parse @message "port=* " as port
    | parse @message "group=*" as grp
    | stats count(*) as handshakes by port, grp
    | sort port asc, handshakes desc
  EOT
}

# ---- Route 53 private DNS: pqc-server.<private_domain> ----

resource "aws_route53_zone" "lab" {
  name          = var.private_domain
  comment       = "${var.name} private zone"
  force_destroy = true

  vpc {
    vpc_id = aws_vpc.lab.id
  }
}

resource "aws_route53_record" "server" {
  zone_id = aws_route53_zone.lab.zone_id
  name    = "pqc-server.${var.private_domain}"
  type    = "A"
  ttl     = 60
  records = [aws_instance.server.private_ip]
}
