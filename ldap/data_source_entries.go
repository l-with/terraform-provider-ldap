package ldap

import (
	"context"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/l-with/terraform-provider-ldap/client"
)

func dataSourceLDAPEntries() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceLDAPEntriesRead,
		Schema: map[string]*schema.Schema{
			"entries": {
				Description: "list of entries",
				Type:        schema.TypeList,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"dn": {
							Description: "DN of the LDAP entry",
							Type:        schema.TypeString,
							Computed:    true,
						},
						"data_json": {
							Description: "JSON-encoded string that is read as the values of the attributes of the entry (s. https://pkg.go.dev/github.com/go-ldap/ldap/v3#EntryAttribute)",
							Type:        schema.TypeString,
							Computed:    true,
						},
					},
				},
			},
			"ou": {
				Description: "OU where LDAP entry will be searched",
				Type:        schema.TypeString,
				Required:    true,
			},
			"filter": {
				Description: "filter for selecting the LDAP entry",
				Type:        schema.TypeString,
				Required:    true,
			},
		},
	}
}

func dataSourceLDAPEntriesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return resourceLDAPEntriesRead(context.WithValue(ctx, CallerTypeKey, DatasourceCaller), d, m)
}

func resourceLDAPEntriesRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	ou := d.Get("ou").(string)
	filter := d.Get("filter").(string)

	ldapEntries, err := cl.ReadEntriesByFilter(ou, "("+filter+")")

	if err != nil {
		if err.(*ldap.Error).ResultCode == ldap.LDAPResultNoSuchObject {
			// Object doesn't exist

			// If Read is called from a datasource, return an error
			if ctx.Value(CallerTypeKey) == DatasourceCaller {
				return diag.FromErr(err)
			}

			// If not a call from datasource, remove the resource from the state
			// and cleanly return
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}

	id := "(" + filter + "," + ou + ")"
	d.SetId(id)

	entriesList := []interface{}{}
	for _, ldapEntry := range *ldapEntries {
		jsonData, err := json.Marshal(ldapEntry.Entry)
		if err != nil {
			return diag.Errorf("error marshaling JSON for %q: %s", id, err)
		}
		values := map[string]interface{}{
			"dn":        ldapEntry.Dn,
			"data_json": string(jsonData),
		}
		entriesList = append(entriesList, values)
	}

	if err := d.Set("entries", entriesList); err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(err)
}
