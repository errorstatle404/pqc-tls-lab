# One role per instance, least privilege. Both get SSM Session Manager (no SSH keys, no port 22).

locals {
  ec2_assume_role = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_partition" "current" {}

# ---------------- server ----------------
resource "aws_iam_role" "server" {
  name_prefix        = "${var.name}-server-"
  assume_role_policy = local.ec2_assume_role
}

resource "aws_iam_role_policy_attachment" "server_ssm" {
  role       = aws_iam_role.server.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "server" {
  name = "lab-access"
  role = aws_iam_role.server.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadBundle"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.lab.arn}/bundle/*"
      },
      {
        Sid      = "PublishCACerts"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.lab.arn}/ca/*"
      },
      {
        Sid      = "ShipNginxLog"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.nginx.arn}:*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "server" {
  name_prefix = "${var.name}-server-"
  role        = aws_iam_role.server.name
}

# ---------------- scanner ----------------
resource "aws_iam_role" "scanner" {
  count              = var.create_scanner ? 1 : 0
  name_prefix        = "${var.name}-scanner-"
  assume_role_policy = local.ec2_assume_role
}

resource "aws_iam_role_policy_attachment" "scanner_ssm" {
  count      = var.create_scanner ? 1 : 0
  role       = aws_iam_role.scanner[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "scanner" {
  count = var.create_scanner ? 1 : 0
  name  = "lab-access"
  role  = aws_iam_role.scanner[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadBundleAndCA"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = ["${aws_s3_bucket.lab.arn}/bundle/*", "${aws_s3_bucket.lab.arn}/ca/*"]
      },
      {
        # Without ListBucket, a missing object returns 403 instead of 404, which makes
        # "wait for the server to publish its CA" indistinguishable from a permissions bug.
        Sid       = "ListCA"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.lab.arn
        Condition = { StringLike = { "s3:prefix" = ["ca/*"] } }
      },
      {
        Sid      = "UploadResults"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.lab.arn}/results/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "scanner" {
  count       = var.create_scanner ? 1 : 0
  name_prefix = "${var.name}-scanner-"
  role        = aws_iam_role.scanner[0].name
}
