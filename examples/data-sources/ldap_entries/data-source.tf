data "ldap_entries" "does" {
  ou     = "ou=People,dc=example,dc=com"
  filter = "sn=Doe"
}
