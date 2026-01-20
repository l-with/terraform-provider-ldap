package ldap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/l-with/terraform-provider-ldap/client"
)

// isSambaAD returns true if LDAP_SAMBA environment variable is set to "true".
// This indicates tests are running against Samba AD which supports the
// Tree Delete Control (OID 1.2.840.113556.1.4.805).
func isSambaAD() bool {
	return os.Getenv("LDAP_SAMBA") == "true"
}

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

// TestAccResourceLdapEntryRecursiveDelete tests the recursive_delete attribute
// with nested entries. This requires an AD-compatible server (Samba AD) that supports
// the Tree Delete Control (OID 1.2.840.113556.1.4.805).
//
// The test creates a 3-level hierarchy (parent OU -> child OU -> grandchild entry)
// with recursive_delete=true on the parent. When Terraform destroys the parent,
// all children are deleted atomically using the Tree Delete Control.
//
// To run this test:
//
//	export LDAP_SAMBA=true
//	# ... set other LDAP_* variables for Samba AD ...
//	go test -v ./ldap -run TestAccResourceLdapEntryRecursiveDelete
func TestAccResourceLdapEntryRecursiveDelete(t *testing.T) {
	if !isSambaAD() {
		t.Skip("Skipping recursive delete test: requires Samba AD (LDAP_SAMBA=true)")
	}

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceEntryRecursiveDeleteWithChildren(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ldap_entry.parent_ou", "dn", "ou=recursive_test,dc=example,dc=com"),
					resource.TestCheckResourceAttr("ldap_entry.parent_ou", "recursive_delete", "true"),
					resource.TestCheckResourceAttr("ldap_entry.child_ou", "dn", "ou=child,ou=recursive_test,dc=example,dc=com"),
					resource.TestCheckResourceAttr("ldap_entry.grandchild_entry", "dn", "cn=grandchild,ou=child,ou=recursive_test,dc=example,dc=com"),
				),
			},
		},
	})
}

// testAccResourceEntryRecursiveDeleteWithChildren creates a 3-level hierarchy
// to test the Tree Delete Control. The parent OU has recursive_delete=true,
// so when Terraform destroys it, all children are deleted atomically.
//
// Note: ignore_attribute_patterns is required because Samba AD returns many
// operational attributes (distinguishedName, objectGUID, whenCreated, etc.)
// that are not in the configuration and would cause perpetual plan drift.
func testAccResourceEntryRecursiveDeleteWithChildren() string {
	return `
resource "ldap_entry" "parent_ou" {
  dn = "ou=recursive_test,dc=example,dc=com"
  recursive_delete = true
  ignore_attribute_patterns = [
    "^distinguishedName$",
    "^instanceType$",
    "^name$",
    "^objectCategory$",
    "^objectGUID$",
    "^uSNChanged$",
    "^uSNCreated$",
    "^whenChanged$",
    "^whenCreated$",
    "^showInAdvancedViewOnly$",
  ]
  data_json = jsonencode({
    objectClass = ["top", "organizationalUnit"]
  })
}

resource "ldap_entry" "child_ou" {
  dn = "ou=child,${ldap_entry.parent_ou.dn}"
  ignore_attribute_patterns = [
    "^distinguishedName$",
    "^instanceType$",
    "^name$",
    "^objectCategory$",
    "^objectGUID$",
    "^uSNChanged$",
    "^uSNCreated$",
    "^whenChanged$",
    "^whenCreated$",
    "^showInAdvancedViewOnly$",
  ]
  data_json = jsonencode({
    objectClass = ["top", "organizationalUnit"]
  })
}

resource "ldap_entry" "grandchild_entry" {
  dn = "cn=grandchild,${ldap_entry.child_ou.dn}"
  ignore_attribute_patterns = [
    "^distinguishedName$",
    "^instanceType$",
    "^name$",
    "^objectCategory$",
    "^objectGUID$",
    "^uSNChanged$",
    "^uSNCreated$",
    "^whenChanged$",
    "^whenCreated$",
    "^showInAdvancedViewOnly$",
  ]
  data_json = jsonencode({
    objectClass = ["top", "container"]
  })
}
`
}
