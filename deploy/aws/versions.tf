terraform {
  # Works with Terraform >= 1.7 and OpenTofu >= 1.7 (mock providers in tests/ need 1.7).
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0" # 6.x: KMS ML_DSA key specs
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.name
      ManagedBy = "terraform"
      Purpose   = "pqc-tls-lab"
    }
  }
}
