package ldap

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/l-with/terraform-provider-ldap/client"
)

func resourceLDAPEntry() *schema.Resource {
	return &schema.Resource{
		ReadContext:   resourceLDAPEntryRead,
		CreateContext: resourceLDAPEntryCreate,
		UpdateContext: resourceLDAPEntryUpdate,
		DeleteContext: resourceLDAPEntryDelete,

		Importer: &schema.ResourceImporter{
			StateContext: resourceLDAPEntryImport,
		},

		Schema: map[string]*schema.Schema{
			attributeNameDn: {
				Description: "DN of the LDAP entry",
				Type:        schema.TypeString,
				ForceNew:    true,
				Required:    true,
			},
			attributeNameDataJson: {
				Description: "JSON-encoded string with the values of the attributes of the entry (s. https://pkg.go.dev/github.com/go-ldap/ldap/v3#EntryAttribute)",
				Type:        schema.TypeString,
				Required:    true,
				ValidateFunc: func(value interface{}, k string) (ws []string, errs []error) {
					decoded := make(map[string][]string)
					err := json.Unmarshal([]byte(value.(string)), &decoded)
					if err != nil {
						errs = append(errs, err)
					}
					return nil, errs
				},
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
				Description: "list of base64 encoded attributes",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			attributeNameBase64EncodeAttributePatterns: {
				Description: "list of attribute patterns for base64 encoded attributes",
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceLDAPEntryImport(_ context.Context, d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	return []*schema.ResourceData{d}, nil
}

func resourceLDAPEntryRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	id := d.Id()

	ldapEntry, err := cl.ReadEntryByDN(id, "("+dummyFilter+")")
	if err != nil {
		if err.(*ldap.Error).ResultCode == ldap.LDAPResultNoSuchObject {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	ignoreAndBase64Encode := getIgnoreAndBase64encode(d)
	ignoreRDNAttributes := client.GetRDNAttributes(ldapEntry, id)
	if ignoreRDNAttributes != nil {
		*ignoreAndBase64Encode.IgnoreAttributes = append(*ignoreAndBase64Encode.IgnoreAttributes, *ignoreRDNAttributes...)
	}
	client.IgnoreAndBase64encodeAttributes(ldapEntry, ignoreAndBase64Encode)

	err = d.Set(attributeNameDn, id)
	if err != nil {
		return diag.FromErr(err)
	}

	jsonData, err := json.Marshal(ldapEntry.Entry)
	if err != nil {
		return diag.Errorf("error marshaling JSON for %q: %s", id, err)
	}

	err = d.Set(attributeNameDataJson, string(jsonData))
	if err != nil {
		return diag.FromErr(err)
	}

	return diag.FromErr(err)
}

func resourceLDAPEntryCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	dn := d.Get(attributeNameDn).(string)

	dataJson := d.Get(attributeNameDataJson)

	var ldapEntry client.LdapEntry

	ignoreAndBase64Encode := getIgnoreAndBase64encode(d)
	err := json.Unmarshal([]byte(dataJson.(string)), &ldapEntry.Entry)
	if err != nil {
		return diag.FromErr(err)
	}
	client.IgnoreAndBase64decodeAttributes(&ldapEntry, ignoreAndBase64Encode)
	ldapEntry.Dn = dn

	err = cl.CreateEntry(&ldapEntry)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(dn)

	return resourceLDAPEntryRead(ctx, d, m)
}

func resourceLDAPEntryUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	dn := d.Get(attributeNameDn).(string)

	newIgnoreAndBase64Encode := getIgnoreAndBase64encode(d)
	oldIgnoreAndBas64Encode := getOldIgnoreAndBase64encode(d)
	var err error
	if d.HasChanges(attributeNameDataJson) {
		oldDataJson, newDataJson := d.GetChange(attributeNameDataJson)
		var ldapEntryOld client.LdapEntry
		var ldapEntryNew client.LdapEntry
		err = json.Unmarshal([]byte(oldDataJson.(string)), &ldapEntryOld.Entry)
		if err != nil {
			return diag.FromErr(err)
		}
		err = json.Unmarshal([]byte(newDataJson.(string)), &ldapEntryNew.Entry)
		if err != nil {
			return diag.FromErr(err)
		}
		err = client.IgnoreAndBase64decodeAttributes(&ldapEntryOld, oldIgnoreAndBas64Encode)
		if err != nil {
			return diag.FromErr(err)
		}
		err = client.IgnoreAndBase64decodeAttributes(&ldapEntryNew, newIgnoreAndBase64Encode)
		if err != nil {
			return diag.FromErr(err)
		}
		ldapEntryOld.Dn = dn
		ldapEntryNew.Dn = dn

		var oldAttributeNames []interface{}
		for oldAttributeName := range ldapEntryOld.Entry {
			oldAttributeNames = append(oldAttributeNames, oldAttributeName)
		}
		oldAttributeNameSet := schema.NewSet(schema.HashString, oldAttributeNames)
		var newAttributeNames []interface{}
		for newAttributeName := range ldapEntryNew.Entry {
			newAttributeNames = append(newAttributeNames, newAttributeName)
		}
		newAttributeNameSet := schema.NewSet(schema.HashString, newAttributeNames)

		deletedAttributeNameSet := oldAttributeNameSet.Difference(newAttributeNameSet)
		addedAttributeNameSet := newAttributeNameSet.Difference(oldAttributeNameSet)
		commonAttributeNameSet := oldAttributeNameSet.Intersection(newAttributeNameSet)

		changedAttributeNameSet := schema.NewSet(schema.HashString, []interface{}{})
		for _, attributeName := range commonAttributeNameSet.List() {
			oldValuesJson, err := json.Marshal(ldapEntryOld.Entry[attributeName.(string)])
			if err != nil {
				return diag.FromErr(err)
			}
			newValuesJson, err := json.Marshal(ldapEntryNew.Entry[attributeName.(string)])
			if err != nil {
				return diag.FromErr(err)
			}
			if fmt.Sprint(oldValuesJson) != fmt.Sprint(newValuesJson) {
				changedAttributeNameSet.Add(attributeName)
			}
		}
		err = cl.UpdateEntry(&ldapEntryNew, deletedAttributeNameSet, addedAttributeNameSet, changedAttributeNameSet)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return resourceLDAPEntryRead(ctx, d, m)
}

func resourceLDAPEntryDelete(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	cl := m.(*client.Client)

	dn := d.Get(attributeNameDn).(string)

	err := cl.DeleteEntry(dn)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}
