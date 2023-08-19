data "ldap_entry" "user" {
  ou     = "ou=People,dc=example,dc=com"
  filter = "mail=user@example.com"
}

data "ldap_entry" "user_jim_mit" {
  dn = "uid=jimmit01,ou=People,dc=example,dc=com"
}
