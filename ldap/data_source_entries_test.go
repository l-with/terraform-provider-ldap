package ldap

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/l-with/terraform-provider-ldap/client"
	"strconv"
	"testing"
)

func TestAccDataSourceLdapEntries(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceEntries(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.ldap_entries.mits",
						"entries.#",
						"2",
					),
					testAccCheckLdapEntriesDataJson(
						"data.ldap_entries.mits",
						"Jim Mit",
						func(ldapEntry client.LdapEntry) error {
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
						"data.ldap_entries.mits_mail",
						"entries.0.data_json",
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

// testAccCheckLdapEntriesDataJson applies check to the data_json of the entry
// with the given cn in the entries of a ldap_entries data source. The order
// of the entries depends on the LDAP server, so they are matched by cn.
func testAccCheckLdapEntriesDataJson(name string, cn string, check func(ldapEntry client.LdapEntry) error) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s: not found in state", name)
		}
		count, err := strconv.Atoi(rs.Primary.Attributes["entries.#"])
		if err != nil {
			return fmt.Errorf("%s: entries.#: %w", name, err)
		}
		for i := 0; i < count; i++ {
			var ldapEntry client.LdapEntry
			if err := json.Unmarshal([]byte(rs.Primary.Attributes[fmt.Sprintf("entries.%d.data_json", i)]), &ldapEntry.Entry); err != nil {
				return err
			}
			if len(ldapEntry.Entry["cn"]) > 0 && ldapEntry.Entry["cn"][0] == cn {
				return check(ldapEntry)
			}
		}
		return fmt.Errorf("%s: no entry with cn '%s' found", name, cn)
	}
}

func testAccDataSourceEntries() string {
	return testAccConfig(`
locals {
 dn = "ou=users,dc=example,dc=com"
}

resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  %IGNORE_OPERATIONAL_ATTRIBUTES%
  data_json = jsonencode({
    objectClass = %OU_OBJECT_CLASSES%
  })
}

resource "ldap_entry" "user_jimmit" {
  depends_on = [ldap_entry.users_example_com]

  dn = "%RDN(jimmit01,Jim Mit)%,${local.dn}"
  %IGNORE_OPERATIONAL_ATTRIBUTES%
  data_json = jsonencode({
    objectClass = %PERSON_OBJECT_CLASSES%
    ou          = ["users"]
    givenName   = ["Jim"]
    sn          = ["Mit"]
    %CN(Jim Mit)%
    mail        = ["jim.mit@example.com"]
  })
}

resource "ldap_entry" "user_larrymit" {
  depends_on = [ldap_entry.users_example_com]

  dn = "%RDN(larrymit02,Larry Mit)%,${local.dn}"
  %IGNORE_OPERATIONAL_ATTRIBUTES%
  data_json = jsonencode({
    objectClass = %PERSON_OBJECT_CLASSES%
    ou          = ["users"]
    givenName   = ["Larry"]
    sn          = ["Mit"]
    %CN(Larry Mit)%
    mail        = ["larry.mit@example.com"]
  })
}

data "ldap_entries" "mits" {
  depends_on = [
    ldap_entry.user_jimmit,
    ldap_entry.user_larrymit,
  ]
  ou          = local.dn
  filter      = "sn=Mit"
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

data "ldap_entries" "mits_mail" {
  depends_on = [
    ldap_entry.user_jimmit,
    ldap_entry.user_larrymit,
  ]
  ou          = local.dn
  filter      = "sn=Mit"
  restrict_attributes = [
    "mail"
  ]
}
`)
}
