package ldap

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/l-with/terraform-provider-ldap/client"
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
						"ldap_entry.user_jimmit",
						"data_json",
						func(value string) error {
							var ldapEntry client.LdapEntry
							err := json.Unmarshal([]byte(value), &ldapEntry.Entry)
							if err != nil {
								return err
							}
							_, uidInEntry := ldapEntry.Entry["uid"]
							if uidInEntry {
								return errors.New("uid: expected to be ignored, got '" + ldapEntry.Entry["uid"][0] + "'")
							}
							return nil
						},
					),
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
							if ldapEntry.Entry["street"][0] != "Street" {
								return errors.New("street: expected 'Street', got '" + ldapEntry.Entry["street"][0] + "'")
							}
							if ldapEntry.Entry["userPassword"][0] != "userPassword" {
								return errors.New("userPassword: expected 'userPassword', got '" + ldapEntry.Entry["userPassword"][0] + "'")
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
			{
				Config: testAccResourceEntryIgnoreAttributes(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ldap_entry.users_example_com", "dn", "ou=users,dc=example,dc=com"),
					//resource.TestCheckResourceAttr("ldap_entry.user_jimmit2", "dn", "uid=jimmit02,ou=users,dc=example,dc=com"),
					resource.TestCheckResourceAttrWith(
						"ldap_entry.user_jimmit",
						"data_json",
						func(value string) error {
							var ldapEntry client.LdapEntry
							err := json.Unmarshal([]byte(value), &ldapEntry.Entry)
							if err != nil {
								return err
							}
							_, userPasswordInEntry := ldapEntry.Entry["userPassword"]
							if userPasswordInEntry {
								return errors.New("userPassword: expected to be ignored, got '" + ldapEntry.Entry["userPassword"][0] + "'")
							}
							return nil
						},
					),
				),
			},
			{
				Config:      testAccResourceEntryRestrictAttributes(),
				ExpectError: regexp.MustCompile(".*ldap_entry.user_jimmit will be updated in-place.*"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ldap_entry.user_bobmit", "restrict_attributes.#", "2"),
					resource.TestCheckResourceAttrWith(
						"ldap_entry.user_bobmit",
						"data_json",
						func(value string) error {
							var ldapEntry client.LdapEntry
							err := json.Unmarshal([]byte(value), &ldapEntry.Entry)
							if err != nil {
								return err
							}
							entryGroups, memberOfInEntry := ldapEntry.Entry["memberOf"]
							if !memberOfInEntry {
								return errors.New("memberOf: it is expected to be present in the resource, but it is not")
							}
							if !(entryGroups[0] == "cn=all,ou=groups,dc=example,dc=com") {
								return errors.New("memberOf: expected 'cn=all,ou=groups,dc=example,dc=com', got '" + entryGroups[0] + "'")
							}
							return nil
						},
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
    objectClass  = ["inetOrgPerson"]
    ou           = ["users"]
    givenName    = ["Jim"]
    sn           = [ldap_entry.users_example_com.id]
    cn           = ["Jim Mit"]
	userPassword = ["userPassword"]
    street       = ["Street"]
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

func testAccResourceEntryIgnoreAttributes() string {
	return fmt.Sprintf(`
resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "user_jimmit" {
  dn = "uid=jimmit01,${ldap_entry.users_example_com.dn}"
  ignore_attributes = [
 	"userPassword"
  ]
  data_json = jsonencode({
    objectClass = ["inetOrgPerson"]
    ou          = ["users"]
    givenName   = ["Jim"]
    sn          = [ldap_entry.users_example_com.id]
    cn          = ["Jim Mit"]
    street      = ["Street"]
  })
}
`)
}

func TestAccResourceLdapEntryCreateDefaults(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceEntryCreateDefaults("Street"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(
						"ldap_entry.user_defaults",
						"data_json_create_defaults",
						func(value string) error {
							decoded := map[string][]string{}
							if err := json.Unmarshal([]byte(value), &decoded); err != nil {
								return err
							}
							vals, present := decoded["userPassword"]
							if !present || len(vals) == 0 || vals[0] != "{SSHA}creation-dummy" {
								return fmt.Errorf("data_json_create_defaults: expected userPassword=[\"{SSHA}creation-dummy\"], got %v", decoded)
							}
							return nil
						},
					),
					resource.TestCheckResourceAttrWith(
						"ldap_entry.user_defaults",
						"data_json",
						func(value string) error {
							var e client.LdapEntry
							if err := json.Unmarshal([]byte(value), &e.Entry); err != nil {
								return err
							}
							if _, present := e.Entry["userPassword"]; present {
								return errors.New("userPassword: expected to be stripped from resource data_json via data_json_create_defaults, got '" + e.Entry["userPassword"][0] + "'")
							}
							return nil
						},
					),
					resource.TestCheckResourceAttrWith(
						"data.ldap_entry.user_defaults",
						"data_json",
						func(value string) error {
							var e client.LdapEntry
							if err := json.Unmarshal([]byte(value), &e.Entry); err != nil {
								return err
							}
							vals, present := e.Entry["userPassword"]
							if !present {
								return errors.New("userPassword: expected to be present on the LDAP server (injected by data_json_create_defaults), but data.ldap_entry did not return it")
							}
							if len(vals) == 0 || vals[0] != "{SSHA}creation-dummy" {
								return fmt.Errorf("userPassword: expected '{SSHA}creation-dummy' on server, got %v", vals)
							}
							return nil
						},
					),
				),
			},
			{
				Config: testAccResourceEntryCreateDefaults("NewStreet"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrWith(
						"ldap_entry.user_defaults",
						"data_json",
						func(value string) error {
							var e client.LdapEntry
							if err := json.Unmarshal([]byte(value), &e.Entry); err != nil {
								return err
							}
							if len(e.Entry["street"]) == 0 || e.Entry["street"][0] != "NewStreet" {
								return fmt.Errorf("street: expected 'NewStreet' after update, got %v", e.Entry["street"])
							}
							if _, present := e.Entry["userPassword"]; present {
								return errors.New("userPassword: leaked into resource data_json after unrelated-attribute update")
							}
							return nil
						},
					),
				),
			},
		},
	})
}

func testAccResourceEntryCreateDefaults(street string) string {
	return fmt.Sprintf(`
resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "user_defaults" {
  dn = "uid=defaults01,${ldap_entry.users_example_com.dn}"
  data_json_create_defaults = jsonencode({
    userPassword = ["{SSHA}creation-dummy"]
  })
  data_json = jsonencode({
    objectClass = ["inetOrgPerson"]
    ou          = ["users"]
    givenName   = ["Default"]
    sn          = [ldap_entry.users_example_com.id]
    cn          = ["Default User"]
    street      = ["%s"]
  })
}

data "ldap_entry" "user_defaults" {
  depends_on = [ldap_entry.user_defaults]
  dn         = ldap_entry.user_defaults.dn
}
`, street)
}

func testAccResourceEntryRestrictAttributes() string {
	return fmt.Sprintf(`
resource "ldap_entry" "users_example_com" {
  dn = "ou=users,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "groups_example_com" {
  dn = "ou=groups,dc=example,dc=com"
  data_json = jsonencode({
    objectClass = ["organizationalUnit"]
  })
}

resource "ldap_entry" "group_all" {
  dn = "cn=all,${ldap_entry.groups_example_com.dn}"
  data_json = jsonencode({
    objectClass = ["groupOfNames"]
	member = [
	  "cn=placeholder,${ldap_entry.users_example_com.dn}",
	]
  })
}

resource "ldap_entry" "user_jimmit" {
  dn = "uid=jimmit01,${ldap_entry.users_example_com.dn}"
  data_json = jsonencode({
    objectClass  = ["inetOrgPerson"]
    ou           = ["users"]
    givenName    = ["Jim"]
    sn           = [ldap_entry.users_example_com.id]
    cn           = ["Jim Mit"]
	userPassword = ["userPassword"]
    street       = ["Street"]
	memberOf     = ["${ldap_entry.group_all.dn}"]
  })
}

resource "ldap_entry" "user_bobmit" {
  dn = "uid=bobmit01,${ldap_entry.users_example_com.dn}"
  restrict_attributes = [
    "*",
    "memberOf"
  ]
  data_json = jsonencode({
    objectClass  = ["inetOrgPerson"]
    ou           = ["users"]
    givenName    = ["Bob"]
    sn           = [ldap_entry.users_example_com.id]
    cn           = ["Bob Mit"]
	userPassword = ["userPassword"]
    street       = ["Street"]
	memberOf     = ["${ldap_entry.group_all.dn}"]
  })
}
`)
}
