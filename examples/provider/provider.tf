terraform {
  required_providers {
    ldap = {
      source  = "l-with/ldap"
      version = ">= 0.0.2"
    }
  }
}

variable "ldap_bind_user" {}
variable "ldap_bind_password" {}

provider "ldap" {
  host          = "example.com"
  port          = 636
  tls           = true

  bind_user     = var.ldap_bind_user
  bind_password = var.ldap_bind_password
}

data "ldap_entry" "user" {
  ou          = "ou=People,dc=example,dc=com"
  filter      = "mail=user@example.com"
}

locals {
  user_data = jsondecode(data.ldap_entry.user.data_json)
}

