package ldap

import (
	"context"
	"encoding/json"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/l-with/terraform-provider-ldap/client"
)

func dataSourceLDAPEntry() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceLDAPEntryRead,
		Schema: map[string]*schema.Schema{
			attributeNameDn: {
				Description:  "DN of the LDAP entry",
				Type:         schema.TypeString,
				Optional:     true,
				Required:     false,
				ExactlyOneOf: []string{attributeNameDn, attributeNameOu},
			},
			attributeNameOu: {
				Description:  "OU where LDAP entry will be searched",
				Type:         schema.TypeString,
				Optional:     true,
				Required:     false,
				ExactlyOneOf: []string{attributeNameDn, attributeNameOu},
			},
			attributeNameFilter: {
				Description:  "filter for selecting the LDAP entry, ignored if '" + attributeNameDn + "' is used",
				Type:         schema.TypeString,
				Optional:     true,
				Required:     false,
				Default:      dummyFilter,
				AtLeastOneOf: []string{attributeNameDn, attributeNameOu, attributeNameFilter},
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
			attributeNameRestrictAttributes: {
				Description: "list of attributes to which reading is restricted",
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

	var ok bool

	var baseDn string

	_, ok = d.GetOk(attributeNameDn)
	if ok {
		baseDn = d.Get(attributeNameDn).(string)
	}
	_, ok = d.GetOk(attributeNameOu)
	if ok {
		baseDn = d.Get(attributeNameOu).(string)
	}
	filter := d.Get(attributeNameFilter).(string)

	restrictAttributes := &[]string{"*"}
	_, ok = d.GetOk(attributeNameRestrictAttributes)
	if ok {
		restrictAttributes = getAttributeListFromAttribute(d, attributeNameRestrictAttributes)
	}

	ldapEntry, err := cl.ReadEntryByFilter(baseDn, "("+filter+")", restrictAttributes)

	ignoreAndBase64Encode := getIgnoreAndBase64encode(d)
	client.IgnoreAndBase64encodeAttributes(ldapEntry, ignoreAndBase64Encode)

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
