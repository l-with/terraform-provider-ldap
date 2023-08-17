package ldap

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/l-with/terraform-provider-ldap/client"
	"testing"
)

func TestAccResourceLdapEntry(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceEntry(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ldap_entry.users_example_com", "dn", "ou=users,dc=example,dc=com"),
					resource.TestCheckResourceAttr("ldap_entry.user_jimmit", "dn", "uid=jimmit01,ou=users,dc=example,dc=com"),
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
							return nil
						},
					),
					resource.TestCheckResourceAttr(
						"data.ldap_entries.search",
						"entries.#",
						"3",
					),
				),
			},
		},
	})
}

func testAccResourceEntry() string {
	return fmt.Sprintf(`
resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "user_jimmit" {
  dn = "uid=jimmit01,${ldap_entry.users_example_com.dn}"
  data_json = jsonencode({
    objectClass = ["inetOrgPerson"]
    ou          = ["users"]
    givenName   = ["Jim"]
    sn          = ["Mit"]
    cn          = ["Jim Mit"]
  })
}

data "ldap_entry" "user_jimmit" {
  depends_on = [ldap_entry.user_jimmit]
  ou          = ldap_entry.users_example_com.dn
  filter      = "cn=Jim Mit"
}
data "ldap_entries" "search" {
  depends_on = [ldap_entry.user_jimmit]
  ou         = "dc=example,dc=com"
  filter     = "objectClass=*"
}
`)
}
