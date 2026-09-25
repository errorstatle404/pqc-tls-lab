terraform {
  # Works with Terraform >= 1.7 and OpenTofu >= 1.7 (mock providers in tests/ need 1.7).
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # 6.2 added ML_DSA_65 as a KMS key spec.
      version = ">= 6.2, < 7.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
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
