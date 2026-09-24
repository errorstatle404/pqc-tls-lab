terraform {
  # Works with Terraform >= 1.7 and OpenTofu >= 1.7 (mock providers in tests/ need 1.7).
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0"
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
