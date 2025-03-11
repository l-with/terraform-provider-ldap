package ldap

import (
	"context"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/l-with/terraform-provider-ldap/client"
)

const attributeNameEntries = "entries"

func dataSourceLDAPEntries() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceLDAPEntriesRead,
		Schema: map[string]*schema.Schema{
			attributeNameEntries: {
				Description: "list of entries",
				Type:        schema.TypeList,
				Computed:    true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						attributeNameDn: {
							Description: "DN of the LDAP entry",
							Type:        schema.TypeString,
							Computed:    true,
						},
						attributeNameDataJson: {
							Description: "JSON-encoded string that is read as the values of the attributes of the entry (s. https://pkg.go.dev/github.com/go-ldap/ldap/v3#EntryAttribute)",
							Type:        schema.TypeString,
							Computed:    true,
						},
					},
				},
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
				Description: "list of attributes to which reading from the LDAP server is restricted",
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
			attributeNamePagingSize: {
				Description: "Desired page size for the search request. Use 0 to retrieve all results without pagination, or a value greater than 0 to enable paginated queries. Defaults to 0.",
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     0,
				ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(0)),
			},
		},
	}
}

func dataSourceLDAPEntriesRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	ou := d.Get(attributeNameOu).(string)
	filter := d.Get(attributeNameFilter).(string)
	pagingSize := d.Get(attributeNamePagingSize).(int)

	var ok bool
	restrictAttributes := &[]string{"*"}
	_, ok = d.GetOk(attributeNameRestrictAttributes)
	if ok {
		restrictAttributes = getAttributeListFromAttribute(d, attributeNameRestrictAttributes)
	}

	restrictAttributes = getAttributeListFromAttribute(d, attributeNameRestrictAttributes)

	ldapEntries, err := cl.ReadEntriesByFilter(ou, "("+filter+")", restrictAttributes, pagingSize)
	if err != nil {
		if err.(*ldap.Error).ResultCode != ldap.LDAPResultNoSuchObject {
			return diag.FromErr(err)
		}
		err = nil
	}

	id := "(" + filter + "," + ou + ")"
	d.SetId(id)

	ignoreAndBase64Encode := getIgnoreAndBase64encode(d)
	entriesList := []interface{}{}
	if ldapEntries != nil {
		for _, ldapEntry := range *ldapEntries {
			client.IgnoreAndBase64encodeAttributes(&ldapEntry, ignoreAndBase64Encode)
			jsonData, err := json.Marshal(ldapEntry.Entry)
			if err != nil {
				return diag.Errorf("error marshaling JSON for %q: %s", id, err)
			}
			values := map[string]interface{}{
				attributeNameDn:       ldapEntry.Dn,
				attributeNameDataJson: string(jsonData),
			}
			entriesList = append(entriesList, values)
		}
	}

	if err := d.Set(attributeNameEntries, entriesList); err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(err)
}
