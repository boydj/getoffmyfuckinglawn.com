locals {
  deploy_dir = "${path.module}/../deploy"

  # --- firewall ------------------------------------------------------------
  # IPv4 CIDRs have a netmask; IPv6 ones make cidrnetmask() fail.
  admin_rules = {
    for c in var.admin_cidrs : c => {
      ip_type     = can(cidrnetmask(c)) ? "v4" : "v6"
      subnet      = cidrhost(c, 0)
      subnet_size = tonumber(split("/", c)[1])
    }
  }

  anywhere = {
    v4 = { subnet = "0.0.0.0", subnet_size = 0 }
    v6 = { subnet = "::", subnet_size = 0 }
  }

  # Public services, open to everyone. The original TCP web ports keep their
  # "v4-80"-style keys so upgrading adds rules instead of replacing them.
  public_ports = [
    { key = "80", protocol = "tcp", port = "80" },       # HTTP (logged, then mostly redirected)
    { key = "443", protocol = "tcp", port = "443" },     # HTTPS
    { key = "udp-443", protocol = "udp", port = "443" }, # HTTP/3 (QUIC)
    { key = "70", protocol = "tcp", port = "70" },       # Gopher
    { key = "1965", protocol = "tcp", port = "1965" },   # Gemini
  ]
  web_rules = {
    for pair in setproduct(keys(local.anywhere), local.public_ports) : "${pair[0]}-${pair[1].key}" => {
      ip_type     = pair[0]
      protocol    = pair[1].protocol
      port        = pair[1].port
      subnet      = local.anywhere[pair[0]].subnet
      subnet_size = local.anywhere[pair[0]].subnet_size
    }
  }

  # --- image ---------------------------------------------------------------
  os_id = var.os_id != null ? var.os_id : tonumber(one(data.vultr_os.debian[*].id))

  # --- cloud-init ----------------------------------------------------------
  # The same files deploy/install.sh installs, so a fresh box and a deployed
  # box converge on identical units, scripts and Caddyfile.
  cloud_init_files = [
    for f in [
      { src = "lawn.service", dest = "/etc/systemd/system/lawn.service", mode = "0644" },
      { src = "lawn-asn-refresh.service", dest = "/etc/systemd/system/lawn-asn-refresh.service", mode = "0644" },
      { src = "lawn-asn-refresh.timer", dest = "/etc/systemd/system/lawn-asn-refresh.timer", mode = "0644" },
      { src = "lawn-verify-refresh.service", dest = "/etc/systemd/system/lawn-verify-refresh.service", mode = "0644" },
      { src = "lawn-verify-refresh.timer", dest = "/etc/systemd/system/lawn-verify-refresh.timer", mode = "0644" },
      { src = "lawn-backup.service", dest = "/etc/systemd/system/lawn-backup.service", mode = "0644" },
      { src = "lawn-backup.timer", dest = "/etc/systemd/system/lawn-backup.timer", mode = "0644" },
      { src = "lawn-reboot-check.service", dest = "/etc/systemd/system/lawn-reboot-check.service", mode = "0644" },
      { src = "lawn-reboot-check.timer", dest = "/etc/systemd/system/lawn-reboot-check.timer", mode = "0644" },
      { src = "host-setup.sh", dest = "/usr/local/lib/lawn/host-setup.sh", mode = "0755" },
      { src = "asn-refresh.sh", dest = "/usr/local/lib/lawn/asn-refresh.sh", mode = "0755" },
      { src = "backup.sh", dest = "/usr/local/lib/lawn/backup.sh", mode = "0755" },
      { src = "reboot-check.sh", dest = "/usr/local/lib/lawn/reboot-check.sh", mode = "0755" },
      { src = "Caddyfile", dest = "/usr/local/lib/lawn/Caddyfile", mode = "0644" },
      { src = "torrc", dest = "/usr/local/lib/lawn/torrc", mode = "0644" },
      ] : {
      path    = f.dest
      mode    = f.mode
      content = file("${local.deploy_dir}/${f.src}")
    }
  ]

  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    domain      = var.domain
    lawn_secret = random_password.lawn_secret.result
    files       = local.cloud_init_files
  })

  dns_names = { apex = "", www = "www" }
}

data "vultr_os" "debian" {
  count = var.os_id == null ? 1 : 0

  filter {
    name   = "name"
    values = [var.os_name]
  }
}

# LAWN_SECRET: HMAC key that seeds the maze. Generated once, kept in local
# state, delivered to /etc/lawn/env by cloud-init. Never in the repo.
resource "random_password" "lawn_secret" {
  length  = 48
  special = false
}

resource "vultr_ssh_key" "admin" {
  name    = "lawn-${var.domain}"
  ssh_key = trimspace(file(pathexpand(var.ssh_public_key_path)))
}

resource "vultr_firewall_group" "lawn" {
  description = "lawn ${var.domain}: ssh from admin CIDRs, web from anywhere"
}

resource "vultr_firewall_rule" "ssh" {
  for_each = local.admin_rules

  firewall_group_id = vultr_firewall_group.lawn.id
  protocol          = "tcp"
  ip_type           = each.value.ip_type
  subnet            = each.value.subnet
  subnet_size       = each.value.subnet_size
  port              = "22"
  notes             = "ssh admin ${each.key}"
}

resource "vultr_firewall_rule" "web" {
  for_each = local.web_rules

  firewall_group_id = vultr_firewall_group.lawn.id
  protocol          = each.value.protocol
  ip_type           = each.value.ip_type
  subnet            = each.value.subnet
  subnet_size       = each.value.subnet_size
  port              = each.value.port
  notes             = "web ${each.key}"
}

# ICMP (ping, and ICMPv6 for path-MTU discovery) from anywhere.
resource "vultr_firewall_rule" "icmp" {
  for_each = local.anywhere

  firewall_group_id = vultr_firewall_group.lawn.id
  protocol          = "icmp"
  ip_type           = each.key
  subnet            = each.value.subnet
  subnet_size       = each.value.subnet_size
  notes             = "icmp ${each.key}"
}

resource "vultr_instance" "lawn" {
  region            = var.region
  plan              = var.plan
  os_id             = local.os_id
  label             = "lawn-${var.domain}"
  hostname          = var.hostname
  tags              = var.tags
  enable_ipv6       = true
  backups           = "disabled"
  ddos_protection   = false
  activation_email  = false
  firewall_group_id = vultr_firewall_group.lawn.id
  ssh_key_ids       = [vultr_ssh_key.admin.id]
  user_data         = local.user_data

  # Boot with the firewall already populated.
  depends_on = [
    vultr_firewall_rule.ssh,
    vultr_firewall_rule.web,
    vultr_firewall_rule.icmp,
  ]

  lifecycle {
    # cloud-init only runs on first boot; after that `make deploy` owns the
    # host's files. Edits under deploy/ change the rendered user-data and a
    # re-resolved os_id could drift, and neither should rebuild the box.
    ignore_changes = [user_data, os_id]
  }
}

# The zone is created without `ip`, which (per the provider docs) creates no
# default records, so the records below are the only A/AAAA records.
resource "vultr_dns_domain" "lawn" {
  domain = var.domain
}

resource "vultr_dns_record" "a" {
  for_each = local.dns_names

  domain = vultr_dns_domain.lawn.id
  name   = each.value
  type   = "A"
  data   = vultr_instance.lawn.main_ip
  ttl    = var.dns_ttl
}

resource "vultr_dns_record" "aaaa" {
  for_each = local.dns_names

  domain = vultr_dns_domain.lawn.id
  name   = each.value
  type   = "AAAA"
  data   = vultr_instance.lawn.v6_main_ip
  ttl    = var.dns_ttl
}
