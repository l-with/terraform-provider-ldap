data "ldap_entry" "user" {
  ou     = "ou=People,dc=example,dc=com"
  filter = "mail=user@example.com"
}
