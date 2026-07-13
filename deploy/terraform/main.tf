provider "aws" {
  region = var.regions[0]
}

locals {
  topology = {
    for region in var.regions : region => {
      bootstrap = contains(var.node_roles, "bootstrap")
      observer  = contains(var.node_roles, "observer")
      relay     = contains(var.node_roles, "relay")
    }
  }
}

resource "terraform_data" "regional_topology" {
  for_each = local.topology

  input = {
    project     = var.project
    environment = var.environment
    region      = each.key
    roles       = each.value
  }
}

