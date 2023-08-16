package client

import (
	"encoding/base64"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/exp/slices"
	"log"
	"regexp"
	"strings"
)

type LdapEntry struct {
	Entry map[string][]string
	Dn    string
}

func (c *Client) ReadEntryByFilter(ou string, filter string, ignore_attributes []string, ignore_attribute_patterns []string, base64encode_attributes []string, base64encode_attributes_patterns []string) (ldapEntry *LdapEntry, err error) {
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
		ignore := false
		for _, pattern := range ignore_attribute_patterns {
			r := regexp.MustCompile(pattern)
			if r.MatchString(attr.Name) {
				ignore = true
			}
		}
		if ignore {
			continue
		}
		values := attr.Values
		if slices.Contains(base64encode_attributes, attr.Name) {
			for i, value := range values {
				values[i] = base64.StdEncoding.EncodeToString([]byte(value))
			}
		}
		base64encode := false
		for _, pattern := range base64encode_attributes_patterns {
			r := regexp.MustCompile(pattern)
			if r.MatchString(attr.Name) {
				base64encode = true
			}
		}
		if base64encode {
			for i, value := range values {
				values[i] = base64.StdEncoding.EncodeToString([]byte(value))
			}
		}
		le.Entry[attr.Name] = values
	}

	le.Dn = searchResult.Entries[0].DN

	return &le, nil
}

func (c *Client) ReadEntriesByFilter(ou string, filter string, ignore_attributes []string, ignore_attribute_patterns []string, base64encode_attributes []string, base64encode_attributes_patterns []string) (ldapEntries *[]LdapEntry, err error) {
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
			ignore := false
			for _, pattern := range ignore_attribute_patterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attr.Name) {
					ignore = true
				}
			}
			if ignore {
				continue
			}
			values := attr.Values
			if slices.Contains(base64encode_attributes, attr.Name) {
				for i, value := range values {
					values[i] = base64.StdEncoding.EncodeToString([]byte(value))
				}
			}
			base64encode := false
			for _, pattern := range base64encode_attributes_patterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attr.Name) {
					base64encode = true
				}
			}
			if base64encode {
				for i, value := range values {
					values[i] = base64.StdEncoding.EncodeToString([]byte(value))
				}
			}
			ldapEntry.Entry[attr.Name] = values
		}
		ldapEntry.Dn = entry.DN
		les = append(les, ldapEntry)
	}

	return &les, nil
}

func (c *Client) ReadEntryByDN(dn string) (ldapEntry *LdapEntry, err error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
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

	var le LdapEntry
	le.Entry = make(map[string][]string)

	for _, attr := range searchResult.Entries[0].Attributes {
		if len(attr.Values) == 1 {
			a := fmt.Sprintf("%s=%s", attr.Name, attr.Values[0])
			if strings.HasPrefix(dn, a) {
				continue
			}
		}
		le.Entry[attr.Name] = attr.Values
	}

	le.Dn = searchResult.Entries[0].DN

	return &le, nil
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
