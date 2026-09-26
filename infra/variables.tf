# Required operator inputs (set them in terraform.tfvars):
#   ssh_public_key_path, admin_cidrs
# plus VULTR_API_KEY in the environment.

variable "ssh_public_key_path" {
  description = "Path to the SSH public key installed for root on the instance (e.g. ~/.ssh/id_ed25519.pub)."
  type        = string

  validation {
    condition     = fileexists(pathexpand(var.ssh_public_key_path))
    error_message = "ssh_public_key_path must point to an existing public key file."
  }
}

variable "admin_cidrs" {
  description = "CIDRs (IPv4 and/or IPv6) allowed to reach SSH (22/tcp). Everything else only gets 80/443."
  type        = list(string)

  validation {
    condition     = length(var.admin_cidrs) > 0 && alltrue([for c in var.admin_cidrs : can(cidrhost(c, 0))])
    error_message = "admin_cidrs must be a non-empty list of valid CIDRs, e.g. [\"203.0.113.7/32\", \"2001:db8::/64\"]."
  }

  validation {
    condition     = alltrue([for c in var.admin_cidrs : tonumber(split("/", c)[1]) > 0])
    error_message = "admin_cidrs must not contain /0: this box attracts hostile traffic, so SSH stays restricted."
  }
}

variable "domain" {
  description = "Apex domain served by the site. Its DNS zone is created in Vultr DNS; www redirects to it."
  type        = string
  default     = "getoffmyfuckinglawn.com"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", var.domain))
    error_message = "domain must be a lower-case DNS name such as example.com."
  }
}

variable "region" {
  description = "Vultr region id."
  type        = string
  default     = "ewr"
}

variable "plan" {
  description = "Vultr plan id. vc2-2c-2gb is Regular Cloud Compute, 2 vCPU / 2 GB (SPEC.md s15)."
  type        = string
  default     = "vc2-2c-2gb"
}

variable "os_name" {
  description = "Exact Vultr OS image name, resolved to an os_id with the vultr_os data source. Ignored when os_id is set."
  type        = string
  default     = "Debian 12 x64 (bookworm)"
}

variable "os_id" {
  description = "Explicit Vultr os_id; overrides os_name. List ids with: curl -s https://api.vultr.com/v2/os"
  type        = number
  default     = null
}

variable "hostname" {
  description = "Instance hostname. Changing it replaces the instance."
  type        = string
  default     = "lawn"
}

variable "dns_ttl" {
  description = "TTL in seconds for the A/AAAA records."
  type        = number
  default     = 300
}

variable "tags" {
  description = "Tags applied to the instance."
  type        = list(string)
  default     = ["lawn", "tarpit"]
}
