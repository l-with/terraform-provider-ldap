package client

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

type LdapEntry struct {
	Entry map[string][]string
	Dn    string
}

func (c *Client) ReadEntryByFilter(
	ou string, filter string,
	ignoreAttributes *[]string,
	ignoreAttributePatterns *[]string,
	base64encodeAttributes *[]string,
	base64encodeAttributePatterns *[]string,
) (ldapEntry *LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		ou,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"*"},
		[]ldap.Control{},
	)

	searchResult, err := c.Conn.Search(req)

	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("The filter '%s' doesn't match any entry in the OU: %s", filter, ou))
	}

	if len(searchResult.Entries) > 1 {
		return nil, ldap.NewError(ldap.LDAPResultOther, fmt.Errorf("The filter '%s' match more than one entry in the OU: %s", filter, ou))
	}

	ldapEntry = new(LdapEntry)
	ldapEntry.Entry = make(map[string][]string)

	setAttributesIgnoringAndBase64encodingAttributes(
		ldapEntry,
		searchResult.Entries[0],
		ignoreAttributes,
		ignoreAttributePatterns,
		base64encodeAttributes,
		base64encodeAttributePatterns,
	)

	ldapEntry.Dn = searchResult.Entries[0].DN

	return ldapEntry, nil
}

func (c *Client) ReadEntriesByFilter(
	baseDn string,
	filter string,
	ignoreAttributes *[]string,
	ignoreAttributePatterns *[]string,
	base64encodeAttributes *[]string,
	base64encodeAttributePatterns *[]string,
) (ldapEntries *[]LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"*"},
		[]ldap.Control{},
	)

	searchResult, err := c.Conn.Search(req)
	if err != nil {
		return nil, err
	}

	ldapEntries = new([]LdapEntry)

	for _, entry := range searchResult.Entries {
		var ldapEntry LdapEntry
		ldapEntry.Entry = make(map[string][]string)
		setAttributesIgnoringAndBase64encodingAttributes(
			&ldapEntry,
			entry,
			ignoreAttributes,
			ignoreAttributePatterns,
			base64encodeAttributes,
			base64encodeAttributePatterns,
		)
		ldapEntry.Dn = entry.DN
		*ldapEntries = append(*ldapEntries, ldapEntry)
	}

	return ldapEntries, nil
}

func (c *Client) ReadEntryByDN(
	dn string,
	filter string,
	ignoreAttributes *[]string,
	ignoreAttributePatterns *[]string,
	base64encodeAttributes *[]string,
	base64encodeAttributePatterns *[]string,
) (ldapEntry *LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"*"},
		[]ldap.Control{},
	)

	searchResult, err := c.Conn.Search(req)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("The dn '%s' doesn't match any entry", dn))
	}

	if len(searchResult.Entries) > 1 {
		return nil, ldap.NewError(ldap.LDAPResultOther, fmt.Errorf("The dn '%s' matches more than one entry", dn))
	}

	ldapEntry = new(LdapEntry)
	ldapEntry.Entry = make(map[string][]string)

	ignoreAttributesIncludingRDNAttribute := getRDNAttributes(&searchResult.Entries[0].Attributes, dn)
	if ignoreAttributes != nil {
		*ignoreAttributesIncludingRDNAttribute = append(*ignoreAttributesIncludingRDNAttribute, *ignoreAttributes...)
	}
	setAttributesIgnoringAndBase64encodingAttributes(
		ldapEntry,
		searchResult.Entries[0],
		ignoreAttributesIncludingRDNAttribute,
		ignoreAttributePatterns,
		base64encodeAttributes,
		base64encodeAttributePatterns,
	)

	ldapEntry.Dn = searchResult.Entries[0].DN

	return ldapEntry, nil
}

func (c *Client) CreateEntry(ldapEntry *LdapEntry) error {
	addRequest := ldap.NewAddRequest(ldapEntry.Dn, []ldap.Control{})

	for attrName, attrValues := range ldapEntry.Entry {
		addRequest.Attribute(attrName, attrValues)
	}

	err := c.Conn.Add(addRequest)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) UpdateEntry(
	ldapEntry *LdapEntry,
	deletedAttributeNameSet, addedAttributeNameSet, changedAttributeNameSet *schema.Set,
) error {
	modifyRequest := ldap.NewModifyRequest(ldapEntry.Dn, []ldap.Control{})

	for _, attributeName := range deletedAttributeNameSet.List() {
		modifyRequest.Changes = append(modifyRequest.Changes, ldap.Change{
			Operation: ldap.DeleteAttribute,
			Modification: ldap.PartialAttribute{
				Type: attributeName.(string),
				Vals: []string{},
			},
		})
	}
	for _, attributeName := range addedAttributeNameSet.List() {
		modifyRequest.Changes = append(modifyRequest.Changes, ldap.Change{
			Operation: ldap.AddAttribute,
			Modification: ldap.PartialAttribute{
				Type: attributeName.(string),
				Vals: ldapEntry.Entry[attributeName.(string)],
			},
		})
	}
	for _, attributeName := range changedAttributeNameSet.List() {
		modifyRequest.Changes = append(modifyRequest.Changes, ldap.Change{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: attributeName.(string),
				Vals: ldapEntry.Entry[attributeName.(string)],
			},
		})
	}

	err := c.Conn.Modify(modifyRequest)
	if err != nil {
		log.Printf("[ERROR] UpdateEntry - error modifying LDAP object '%q' with values %v", ldapEntry.Dn, err)
		return err
	}

	return nil
}

func (c *Client) DeleteEntry(dn string) error {
	deleteRequest := ldap.NewDelRequest(dn, []ldap.Control{})
	err := c.Conn.Del(deleteRequest)
	if err != nil {
		return err
	}
	return nil
}
