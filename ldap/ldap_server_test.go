package ldap

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// LDAP server types the acceptance tests can run against, selected by the
// LDAP_SERVER environment variable (s. test/README.md).
const (
	ldapServerOpenLDAP = "openldap"
	ldapServerSamba    = "samba"
)

// testLdapServer returns the type of the LDAP server the acceptance tests run
// against. It defaults to OpenLDAP if LDAP_SERVER is not set.
func testLdapServer() string {
	if server := os.Getenv("LDAP_SERVER"); server != "" {
		return server
	}
	return ldapServerOpenLDAP
}

// testAccSkipUnlessLdapServer skips the test unless it runs against one of the
// given LDAP server types.
func testAccSkipUnlessLdapServer(t *testing.T, servers ...string) {
	t.Helper()
	server := testLdapServer()
	for _, s := range servers {
		if s == server {
			return
		}
	}
	t.Skipf("skipping test for LDAP_SERVER=%s, requires one of %v", server, servers)
}

// testAccSkipOnLdapServer returns a TestStep.SkipFunc skipping the step when
// running against one of the given LDAP server types.
func testAccSkipOnLdapServer(servers ...string) func() (bool, error) {
	return func() (bool, error) {
		server := testLdapServer()
		for _, s := range servers {
			if s == server {
				return true, nil
			}
		}
		return false, nil
	}
}

// sambaOperationalAttributes are attributes Samba AD maintains itself. They
// are returned for "*" (all user attributes) and have to be ignored by
// ldap_entry resources to avoid a perpetual diff.
var sambaOperationalAttributes = []string{
	"accountExpires",
	"badPasswordTime",
	"badPwdCount",
	"codePage",
	"countryCode",
	"distinguishedName",
	"groupType",
	"instanceType",
	"lastLogoff",
	"lastLogon",
	"logonCount",
	"memberOf",
	"name",
	"objectCategory",
	"objectGUID",
	"objectSid",
	"primaryGroupID",
	"pwdLastSet",
	"sAMAccountName",
	"sAMAccountType",
	"uSNChanged",
	"uSNCreated",
	"userAccountControl",
	"whenChanged",
	"whenCreated",
}

var testAccConfigRDNRegexp = regexp.MustCompile(`%RDN\(([^,)]+),([^)]+)\)%`)
var testAccConfigCNRegexp = regexp.MustCompile(`%CN\(([^)]+)\)%`)

// testAccConfig adapts an acceptance test configuration to the LDAP server
// the tests run against by replacing these placeholders:
//
//   - %OU_OBJECT_CLASSES%: object classes of an organizational unit
//   - %PERSON_OBJECT_CLASSES%: object classes of an inetOrgPerson
//   - %IGNORE_OPERATIONAL_ATTRIBUTES%: ignore_attribute_patterns for the
//     attributes the server maintains itself (empty for OpenLDAP)
//   - %RDN(uid,cn)%: RDN of a person, "uid=<uid>" for OpenLDAP and
//     "cn=<cn>" for Samba, where inetOrgPerson must be named by cn
//   - %CN(cn)%: the cn attribute of a person for data_json, empty for Samba
//     since the cn is given by the RDN there
func testAccConfig(config string) string {
	ouObjectClasses := `["organizationalUnit"]`
	personObjectClasses := `["inetOrgPerson"]`
	ignoreOperationalAttributes := ""
	rdn := "uid=$1"
	cn := `cn = ["$1"]`
	if testLdapServer() == ldapServerSamba {
		ouObjectClasses = `["top", "organizationalUnit"]`
		personObjectClasses = `["top", "person", "organizationalPerson", "user", "inetOrgPerson"]`
		ignoreOperationalAttributes = fmt.Sprintf(`ignore_attribute_patterns = ["^(%s)$"]`, strings.Join(sambaOperationalAttributes, "|"))
		rdn = "cn=$2"
		cn = ""
	}
	config = strings.NewReplacer(
		"%OU_OBJECT_CLASSES%", ouObjectClasses,
		"%PERSON_OBJECT_CLASSES%", personObjectClasses,
		"%IGNORE_OPERATIONAL_ATTRIBUTES%", ignoreOperationalAttributes,
	).Replace(config)
	config = testAccConfigRDNRegexp.ReplaceAllString(config, rdn)
	return testAccConfigCNRegexp.ReplaceAllString(config, cn)
}

// testAccPersonRDN returns the RDN of a person like %RDN(uid,cn)% in
// testAccConfig.
func testAccPersonRDN(uid, cn string) string {
	if testLdapServer() == ldapServerSamba {
		return "cn=" + cn
	}
	return "uid=" + uid
}

// testAccCheckResourceAttrEqualFold checks an attribute case-insensitively,
// e.g. a DN, which Samba returns with upper case attribute types.
func testAccCheckResourceAttrEqualFold(name, key, expected string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(name, key, func(value string) error {
		if !strings.EqualFold(value, expected) {
			return fmt.Errorf("%s: expected '%s' (case-insensitive), got '%s'", key, expected, value)
		}
		return nil
	})
}
