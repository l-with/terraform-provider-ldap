package ldap

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/l-with/terraform-provider-ldap/client"
)

const attributeNameOu = "ou"
const attributeNameFilter = "filter"
const attributeNameIgnoreAttributes = "ignore_attributes"
const attributeNameIgnoreAttributePatterns = "ignore_attribute_patterns"
const attributeNameBase64EncodeAttributes = "base64encode_attributes"
const attributeNameBase64EncodeAttributePatterns = "base64encode_attribute_patterns"

func dataSourceLDAPEntry() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceLDAPEntryRead,
		Schema: map[string]*schema.Schema{
			attributeNameDn: {
				Description: "DN of the LDAP entry",
				Type:        schema.TypeString,
				Computed:    true,
			},
			attributeNameOu: {
				Description: "OU where LDAP entry will be searched",
				Type:        schema.TypeString,
				Required:    true,
			},
			attributeNameFilter: {
				Description: "filter for selecting the LDAP entry",
				Type:        schema.TypeString,
				Required:    true,
			},
			attributeNameDataJson: {
				Description: "JSON-encoded string that is read as the values of the attributes of the entry (s. https://pkg.go.dev/github.com/go-ldap/ldap/v3#EntryAttribute)",
				Type:        schema.TypeString,
				Computed:    true,
			},
			attributeNameIgnoreAttributes: {
				Description: "list of attributes to ignore",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			attributeNameIgnoreAttributePatterns: {
				Description: "list of attribute patterns to ignore",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			attributeNameBase64EncodeAttributes: {
				Description: "list of attributes to be encoded to base64",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			attributeNameBase64EncodeAttributePatterns: {
				Description: "list of attribute patterns to be encoded to base64",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func dataSourceLDAPEntryRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	ou := d.Get(attributeNameOu).(string)
	filter := d.Get(attributeNameFilter).(string)
	var ignore_attributes []string
	for _, ignore_attribute := range d.Get(attributeNameIgnoreAttributes).([]interface{}) {
		ignore_attributes = append(ignore_attributes, ignore_attribute.(string))
	}
	var ignore_attribute_patterns []string
	for _, ignore_attribute_pattern := range d.Get(attributeNameIgnoreAttributePatterns).([]interface{}) {
		ignore_attribute_patterns = append(ignore_attribute_patterns, ignore_attribute_pattern.(string))
	}
	var base64encode_attributes []string
	for _, base64encode_attribute := range d.Get(attributeNameBase64EncodeAttributes).([]interface{}) {
		base64encode_attributes = append(base64encode_attributes, base64encode_attribute.(string))
	}
	var base64encode_attribute_patterns []string
	for _, base64encode_attribute_pattern := range d.Get(attributeNameBase64EncodeAttributePatterns).([]interface{}) {
		base64encode_attribute_patterns = append(base64encode_attribute_patterns, base64encode_attribute_pattern.(string))
	}

	ldapEntry, err := cl.ReadEntryByFilter(ou, "("+filter+")", ignore_attributes, ignore_attribute_patterns, base64encode_attributes, base64encode_attribute_patterns)

	if err != nil {
		return diag.FromErr(err)
	}

	id := ldapEntry.Dn
	d.SetId(id)

	err = d.Set(attributeNameDn, id)
	if err != nil {
		return diag.FromErr(err)
	}

	jsonData, err := json.Marshal(ldapEntry.Entry)
	if err != nil {
		return diag.Errorf("error marshaling JSON for %q: %s", id, err)
	}

	if err := d.Set(attributeNameDataJson, string(jsonData)); err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(err)
}
