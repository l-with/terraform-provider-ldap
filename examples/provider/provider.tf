terraform {
  required_providers {
    ldap = {
      source  = "l-with/ldap"
      version = ">= 0.4"
    }
  }
}

variable "ldap_bind_user" {}
variable "ldap_bind_password" {}

provider "ldap" {
  host = "example.com"
  port = 636
  tls  = true

  bind_user     = var.ldap_bind_user
  bind_password = var.ldap_bind_password
}

data "ldap_entry" "user" {
  ou     = "ou=People,dc=example,dc=com"
  filter = "mail=user@example.com"
}

resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "user_jim_mit" {
  dn = "uid=jimmit01,${ldap_entry.users_example_com.dn}"
  data_json = jsonencode({
    objectClass = ["inetOrgPerson"]
    ou          = ["users"]
    givenName   = ["Jim"]
    sn          = ["Mit"]
    cn          = ["Jim Mit"]
  })
}

data "ldap_entry" "user_jim_mit" {
  depends_on = [ldap_entry.user_jim_mit]

  dn = "uid=jimmit01,${ldap_entry.users_example_com.dn}"
}

locals {
  user_data         = jsondecode(data.ldap_entry.user.data_json)
  user_jim_mit_data = jsondecode(data.ldap_entry.user_jim_mit.data_json)
}

