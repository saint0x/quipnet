output "regional_topology" {
  description = "Milestone-one topology manifest for bootstrap, observer, and relay placement."
  value = {
    for region, topology in local.topology : region => topology
  }
}

