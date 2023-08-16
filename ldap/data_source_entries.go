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
			"ignore_attributes": {
				Description: "list of attributes to ignore",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ignore_attribute_patterns": {
				Description: "list of attribute patterns to ignore",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"base64encode_attributes": {
				Description: "list of attributes to be encoded to base64",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"base64encode_attribute_patterns": {
				Description: "list of attribute patterns to be encoded to base64",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceLDAPEntriesRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)
	ou := d.Get("ou").(string)
	filter := d.Get("filter").(string)
	var ignore_attributes []string
	for _, ignore_attribute := range d.Get("ignore_attributes").([]interface{}) {
		ignore_attributes = append(ignore_attributes, ignore_attribute.(string))
	}
	var ignore_attribute_patterns []string
	for _, ignore_attribute_pattern := range d.Get("ignore_attribute_patterns").([]interface{}) {
		ignore_attribute_patterns = append(ignore_attribute_patterns, ignore_attribute_pattern.(string))
	}
	var base64encode_attributes []string
	for _, base64encode_attribute := range d.Get("base64encode_attributes").([]interface{}) {
		base64encode_attributes = append(base64encode_attributes, base64encode_attribute.(string))
	}
	var base64encode_attribute_patterns []string
	for _, base64encode_attribute_pattern := range d.Get("base64encode_attribute_patterns").([]interface{}) {
		base64encode_attribute_patterns = append(base64encode_attribute_patterns, base64encode_attribute_pattern.(string))
	}
	ldapEntries, err := cl.ReadEntriesByFilter(ou, "("+filter+")", ignore_attributes, ignore_attribute_patterns, base64encode_attributes, base64encode_attribute_patterns)

	if err != nil {
		if err.(*ldap.Error).ResultCode != ldap.LDAPResultNoSuchObject {
			return diag.FromErr(err)
		}
		err = nil
	}

	id := "(" + filter + "," + ou + ")"
	d.SetId(id)

	entriesList := []interface{}{}
	if ldapEntries != nil {
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
	}

	if err := d.Set("entries", entriesList); err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(err)
}
