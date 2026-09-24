variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix for every resource."
  type        = string
  default     = "pqc-tls-lab"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.name))
    error_message = "name must be 3-24 characters of lowercase letters, digits and hyphens (it is used in the S3 bucket name)."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the lab VPC. Two public and two private /24s are carved out of it."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && tonumber(split("/", var.vpc_cidr)[1]) <= 20
    error_message = "vpc_cidr must be a valid IPv4 CIDR of /20 or larger."
  }
}

variable "use_nat_gateway" {
  description = <<-EOT
    false (default, cheapest): the instances run in public subnets with a public IP for outbound
    traffic only. The security groups allow no inbound traffic from the internet unless you add
    allowed_cidrs.
    true: the instances run in private subnets behind a NAT gateway (more realistic, about
    $33/month extra while it exists).
  EOT
  type        = bool
  default     = false
}

variable "architecture" {
  description = "CPU architecture of the instances: arm64 (Graviton, cheaper) or x86_64."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be arm64 or x86_64."
  }
}

variable "instance_type" {
  description = "EC2 instance type. Leave null for t4g.small (arm64) or t3.small (x86_64). It must match architecture."
  type        = string
  default     = null
}

variable "create_scanner" {
  description = "Create a second instance, in another Availability Zone, that runs the benchmark client and is the vantage point for the crypto inventory."
  type        = bool
  default     = true
}

variable "allowed_cidrs" {
  description = <<-EOT
    Extra IPv4 CIDRs allowed to reach the TLS endpoints (ports 8443-8446), for example your own
    IP as ["203.0.113.7/32"]. Only useful when use_nat_gateway = false, because only then does
    the server have a public IP. Leave empty to keep the server reachable only from inside the VPC.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.allowed_cidrs : can(cidrnetmask(c)) && c != "0.0.0.0/0"])
    error_message = "Each allowed_cidrs entry must be a valid IPv4 CIDR, and 0.0.0.0/0 is not allowed."
  }
}

variable "private_domain" {
  description = "Route 53 private hosted zone for the lab. The server is registered as pqc-server.<private_domain>, and that name goes into its certificates."
  type        = string
  default     = "lab.internal"
}

variable "log_retention_days" {
  description = "How long CloudWatch keeps the nginx access log (which records the negotiated group of every handshake)."
  type        = number
  default     = 14
}

variable "lab_source_dir" {
  description = "Path to the lab repository root that gets bundled and uploaded. Defaults to the repo this module lives in."
  type        = string
  default     = null
}
