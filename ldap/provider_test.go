package ldap

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"os"
	"testing"
)

// providerFactories are used to instantiate a provider during acceptance testing.
// The factory function will be invoked for every Terraform CLI command executed
// to create a provider server to which the CLI can reattach.
var providerFactories = map[string]func() (*schema.Provider, error){
	"ldap": func() (*schema.Provider, error) {
		return Provider(), nil
	},
}

func testAccPreCheck(t *testing.T) {
	testEnvIsSet("LDAP_HOST", t)
	testEnvIsSet("LDAP_PORT", t)
	testEnvIsSet("LDAP_BIND_USER", t)
	testEnvIsSet("LDAP_BIND_PASSWORD", t)
}

func testEnvIsSet(k string, t *testing.T) {
	if v := os.Getenv(k); v == "" {
		t.Fatalf("%[1]s must be set for acceptance tests", k)
	}
}
