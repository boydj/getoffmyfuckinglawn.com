terraform {
  required_version = ">= 1.8.0"

  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.27"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # State is local (infra/terraform.tfstate) and gitignored; see SPEC.md s15.
}

# Authenticates with the VULTR_API_KEY environment variable. Nothing secret
# lives in this directory.
provider "vultr" {}
