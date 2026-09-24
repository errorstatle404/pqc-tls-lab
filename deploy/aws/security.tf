# No SSH anywhere: shell access is through SSM Session Manager.

resource "aws_security_group" "server" {
  name        = "${var.name}-server"
  description = "PQC TLS lab server: TLS endpoints 8443-8446 from inside the VPC only"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.name}-server" }
}

resource "aws_vpc_security_group_ingress_rule" "server_tls_vpc" {
  security_group_id = aws_security_group.server.id
  description       = "TLS lab endpoints from the VPC (scanner, future inventory tooling)"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 8443
  to_port           = 8446
}

resource "aws_vpc_security_group_ingress_rule" "server_tls_extra" {
  for_each          = toset(var.allowed_cidrs)
  security_group_id = aws_security_group.server.id
  description       = "TLS lab endpoints from an operator-supplied CIDR"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 8443
  to_port           = 8446
}

resource "aws_vpc_security_group_egress_rule" "server_all" {
  security_group_id = aws_security_group.server.id
  description       = "Outbound for package installs, image build, SSM, S3 and CloudWatch"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "scanner" {
  name        = "${var.name}-scanner"
  description = "PQC TLS lab scanner: no inbound, outbound only"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.name}-scanner" }
}

resource "aws_vpc_security_group_egress_rule" "scanner_all" {
  security_group_id = aws_security_group.scanner.id
  description       = "Outbound for scanning, image build, SSM, S3"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
