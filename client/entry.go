package client

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/exp/slices"
	"log"
)

type LdapEntry struct {
	Entry map[string][]string
	Dn    string
}

func (c *Client) ReadEntryByFilter(ou string, filter string, ignore_attributes []string) (ldapEntry *LdapEntry, err error) {
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

	var le LdapEntry
	le.Entry = make(map[string][]string)

	for _, attr := range searchResult.Entries[0].Attributes {
		if slices.Contains(ignore_attributes, attr.Name) {
			continue
		}
		le.Entry[attr.Name] = attr.Values
	}

	le.Dn = searchResult.Entries[0].DN

	return &le, nil
}

func (c *Client) ReadEntriesByFilter(ou string, filter string, ignore_attributes []string) (ldapEntries *[]LdapEntry, err error) {
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

	var les []LdapEntry

	log.Printf("Found %d entries", len(searchResult.Entries))

	for _, entry := range searchResult.Entries {
		var ldapEntry LdapEntry
		ldapEntry.Entry = make(map[string][]string)
		for _, attr := range entry.Attributes {
			if slices.Contains(ignore_attributes, attr.Name) {
				continue
			}
			ldapEntry.Entry[attr.Name] = attr.Values
		}
		ldapEntry.Dn = entry.DN
		les = append(les, ldapEntry)
	}

	return &les, nil
}
