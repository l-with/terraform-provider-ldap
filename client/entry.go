package client

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
)

func (c *Client) ReadEntryByFilter(
	baseDn string,
	filter string,
	attributes *[]string,
) (ldapEntry *LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		*attributes,
		[]ldap.Control{},
	)

	searchResult, err := c.Conn.Search(req)

	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("the filter '%s' doesn't match any entry in the OU: %s", filter, baseDn))
	}

	if len(searchResult.Entries) > 1 {
		return nil, ldap.NewError(ldap.LDAPResultOther, fmt.Errorf("the filter '%s' match more than one entry in the OU: %s", filter, baseDn))
	}

	ldapEntry = new(LdapEntry)
	ldapEntry.Entry = make(map[string][]string)

	for _, attr := range searchResult.Entries[0].Attributes {
		ldapEntry.Entry[attr.Name] = attr.Values
	}

	ldapEntry.Dn = searchResult.Entries[0].DN

	return ldapEntry, nil
}

func (c *Client) ReadEntriesByFilter(
	baseDn string,
	filter string,
	attributes *[]string,
	pagingSize int,
) (ldapEntries *[]LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		baseDn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		*attributes,
		[]ldap.Control{},
	)

	var searchResult *ldap.SearchResult
	if pagingSize == 0 {
		// Use Search for no limit paging size
		searchResult, err = c.Conn.Search(req)
		if err != nil {
			return nil, err
		}

	} else if pagingSize > 0 {
		// Use SearchWithPaging with positive paging size
		searchResult, err = c.Conn.SearchWithPaging(req, uint32(pagingSize))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ldap.NewError(ldap.LDAPResultOther, fmt.Errorf("paging size must be equal or greater than 0, got: %d", pagingSize))
	}

	ldapEntries = new([]LdapEntry)

	for _, entry := range searchResult.Entries {
		var ldapEntry LdapEntry
		ldapEntry.Entry = make(map[string][]string)
		for _, attr := range entry.Attributes {
			ldapEntry.Entry[attr.Name] = attr.Values
		}
		ldapEntry.Dn = entry.DN
		*ldapEntries = append(*ldapEntries, ldapEntry)
	}

	return ldapEntries, nil
}

func (c *Client) ReadEntryByDN(
	dn string,
	filter string,
	attributes *[]string,
) (ldapEntry *LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		*attributes,
		[]ldap.Control{},
	)

	log.Printf("[INFO] attributes %v", *attributes)
	searchResult, err := c.Conn.Search(req)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, fmt.Errorf("the dn '%s' doesn't match any entry", dn))
	}

	if len(searchResult.Entries) > 1 {
		return nil, ldap.NewError(ldap.LDAPResultOther, fmt.Errorf("the dn '%s' matches more than one entry", dn))
	}

	ldapEntry = new(LdapEntry)
	ldapEntry.Entry = make(map[string][]string)

	for _, attr := range searchResult.Entries[0].Attributes {
		ldapEntry.Entry[attr.Name] = attr.Values
	}
	ldapEntry.Dn = searchResult.Entries[0].DN

	return ldapEntry, nil
}

func (c *Client) CreateEntry(
	ldapEntry *LdapEntry,
) error {
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
