package ldap

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	client2 "github.com/l-with/terraform-provider-ldap/client"
)

const attributeNameHost = "host"
const ldapHostEnvVarName = "LDAP_HOST"
const attributeNamePort = "port"
const ldapPortEnvVarName = "LDAP_PORT"
const attributeNameBindUser = "bind_user"
const ldapBindUserEnvVarName = "LDAP_BIND_USER"
const attributeNameBindPassword = "bind_password"
const ldapBindPasswordEnvVarName = "LDAP_BIND_PASSWORD"
const attributeNameTls = "tls"
const attributeNameTlsInsecure = "tls_insecure"

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			attributeNameHost: {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(ldapHostEnvVarName, nil),
				Description: "LDAP host, can optionally be passed as `" + ldapHostEnvVarName + "`environment variable",
			},
			attributeNamePort: {
				Type:        schema.TypeInt,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(ldapPortEnvVarName, nil),
				Description: "LDAP port, can optionally be passed as `" + ldapPortEnvVarName + "`environment variable",
			},
			attributeNameBindUser: {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc(ldapBindUserEnvVarName, nil),
				Description: "LDAP username, can optionally be passed as `" + ldapBindUserEnvVarName + "`environment variable",
			},
			attributeNameBindPassword: {
				Type:        schema.TypeString,
				DefaultFunc: schema.EnvDefaultFunc(ldapBindPasswordEnvVarName, nil),
				Required:    true,
				Description: "LDAP password, can optionally be passed as `" + ldapBindPasswordEnvVarName + "`environment variable",
			},
			attributeNameTls: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Enable the TLS encryption for LDAP (LDAPS). Default, is `false`.",
			},
			attributeNameTlsInsecure: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Don't verify the server TLS certificate. Default is `false`.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"ldap_entry": resourceLDAPEntry(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"ldap_entry":   dataSourceLDAPEntry(),
			"ldap_entries": dataSourceLDAPEntries(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	client := &client2.Client{
		Host:         d.Get(attributeNameHost).(string),
		Port:         d.Get(attributeNamePort).(int),
		BindUser:     d.Get(attributeNameBindUser).(string),
		BindPassword: d.Get(attributeNameBindPassword).(string),
		TLS:          d.Get(attributeNameTls).(bool),
		TLSInsecure:  d.Get(attributeNameTlsInsecure).(bool),
	}

	err := client.Connect()
	if err != nil {
		return nil, diag.FromErr(err)
	}

	return client, nil
}
