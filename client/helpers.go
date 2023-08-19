package client

import (
	"encoding/base64"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/exp/slices"
	"regexp"
	"strings"
)

func setAttributesIgnoringAndBase64encodingAttributes(
	ldapEntry *LdapEntry,
	searchResult *ldap.SearchResult,
	ignoreAttributes *[]string,
	ignoreAttributePatterns *[]string,
	base64encodeAttributes *[]string,
	base64encodeAttributePatterns *[]string,
) {
	for _, attr := range searchResult.Entries[0].Attributes {
		if ignoreAttributes != nil {
			if slices.Contains(*ignoreAttributes, attr.Name) {
				continue
			}
		}
		if ignoreAttributePatterns != nil {
			ignore := false
			for _, pattern := range *ignoreAttributePatterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attr.Name) {
					ignore = true
				}
			}
			if ignore {
				continue
			}
		}
		values := attr.Values
		if base64encodeAttributes != nil {
			if slices.Contains(*base64encodeAttributes, attr.Name) {
				for i, value := range values {
					values[i] = base64.StdEncoding.EncodeToString([]byte(value))
				}
			}
		}
		if base64encodeAttributePatterns != nil {
			base64encode := false
			for _, pattern := range *base64encodeAttributePatterns {
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
		}
		ldapEntry.Entry[attr.Name] = values
	}
}

func getRDNAttributes(attributes *[]*ldap.EntryAttribute, dn string) (ignoreRDNAttributes *[]string) {
	for _, attr := range *attributes {
		if len(attr.Values) == 1 {
			a := fmt.Sprintf("%s=%s,", attr.Name, attr.Values[0])
			if strings.HasPrefix(dn, a) {
				if ignoreRDNAttributes == nil {
					ignoreRDNAttributes = new([]string)
				}
				*ignoreRDNAttributes = append(*ignoreRDNAttributes, attr.Name)
			}
		}
	}
	return ignoreRDNAttributes
}
