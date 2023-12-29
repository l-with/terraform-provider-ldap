package ldap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/l-with/terraform-provider-ldap/client"
	"strconv"
	"testing"
)

func TestAccDataSourceLdapEntry(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceEntry(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ldap_entry.user_jimmit", "dn", "uid=jimmit01,ou=users,dc=example,dc=com"),
					resource.TestCheckResourceAttrWith(
						"data.ldap_entry.user_jimmit",
						"data_json",
						func(value string) error {
							var ldapEntry client.LdapEntry
							err := json.Unmarshal([]byte(value), &ldapEntry.Entry)
							if err != nil {
								return err
							}
							if ldapEntry.Entry["cn"][0] != "Jim Mit" {
								return errors.New("cn: expected 'Jim Mit', got '" + ldapEntry.Entry["cn"][0] + "'")
							}
							if ldapEntry.Entry["ou"][0] != "users" {
								return errors.New("ou: expected 'users', got '" + ldapEntry.Entry["ou"][0] + "'")
							}
							_, mailInEntry := ldapEntry.Entry["mail"]
							if mailInEntry {
								return errors.New("mail: expected to be ignored, got '" + ldapEntry.Entry["mail"][0] + "'")
							}
							snBytes, err := base64.StdEncoding.DecodeString(ldapEntry.Entry["sn"][0])
							if err != nil {
								return err
							}
							sn := string(snBytes[:])
							if err != nil {
								return err
							}
							if sn != "Mit" {
								return errors.New("sn: expected 'Mit', got '" + sn + "'")
							}
							givenNameBytes, err := base64.StdEncoding.DecodeString(ldapEntry.Entry["givenName"][0])
							if err != nil {
								return err
							}
							givenName := string(givenNameBytes[:])
							if err != nil {
								return err
							}
							if givenName != "Jim" {
								return errors.New("givenName: expected 'Jim', got '" + givenName + "'")
							}
							return nil
						},
					),
					resource.TestCheckResourceAttrWith(
						"data.ldap_entry.user_jimmit_mail",
						"data_json",
						func(value string) error {
							var ldapEntry client.LdapEntry
							err := json.Unmarshal([]byte(value), &ldapEntry.Entry)
							if err != nil {
								return err
							}
							if len(ldapEntry.Entry) > 1 {
								return errors.New("expected 1 Entry, got '" + strconv.Itoa(len(ldapEntry.Entry)) + "'")
							}
							_, ok := ldapEntry.Entry["cn"]
							if ok {
								return errors.New("cn: expected null, got values")
							}
							return nil
						},
					),
				),
			},
		},
	})
}

func testAccDataSourceEntry() string {
	return fmt.Sprintf(`
locals {
 dn = "ou=users,dc=example,dc=com"
}

resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "user_jimmit" {
  depends_on = [ldap_entry.users_example_com]

  dn = "uid=jimmit01,${local.dn}"
  data_json = jsonencode({
    objectClass = ["inetOrgPerson"]
    ou          = ["users"]
    givenName   = ["Jim"]
    sn          = ["Mit"]
    cn          = ["Jim Mit"]
    mail        = ["jim.mit@example.com"]
  })
}

data "ldap_entry" "user_jimmit" {
  depends_on = [ldap_entry.user_jimmit]
  ou          = local.dn
  filter      = "cn=Jim Mit"
  ignore_attributes = [
    "mail"
  ]
  base64encode_attributes = [
    "sn"
  ]
  base64encode_attribute_patterns = [
    "^g.*"
  ]
}

data "ldap_entry" "user_jimmit_mail" {
  depends_on = [ldap_entry.user_jimmit]
  ou          = local.dn
  filter      = "cn=Jim Mit"
  restrict_attributes = [
    "mail"
  ]
}
`)
}
