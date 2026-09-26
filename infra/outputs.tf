output "ipv4" {
  description = "Public IPv4 address of the instance."
  value       = vultr_instance.lawn.main_ip
}

output "ipv6" {
  description = "Public IPv6 address of the instance."
  value       = vultr_instance.lawn.v6_main_ip
}

output "domain" {
  description = "Site domain (read by make deploy)."
  value       = var.domain
}

output "instance_id" {
  description = "Vultr instance id."
  value       = vultr_instance.lawn.id
}

output "nameservers" {
  description = "Set these as the domain's nameservers at your registrar; Vultr DNS then serves the A/AAAA records."
  value       = ["ns1.vultr.com", "ns2.vultr.com"]
}

output "ssh" {
  description = "SSH into the box (from an admin CIDR)."
  value       = "ssh root@${vultr_instance.lawn.main_ip}"
}
