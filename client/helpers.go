package client

import (
	"encoding/base64"
	"fmt"
	"golang.org/x/exp/slices"
	"regexp"
	"strings"
)

func GetRDNAttributes(ldapEntry *LdapEntry, dn string) (ignoreRDNAttributes *[]string) {
	for attributeName, attributeValues := range ldapEntry.Entry {
		if len(attributeValues) == 1 {
			attributeValueString := fmt.Sprintf("%s=%s,", attributeName, attributeValues[0])
			if strings.HasPrefix(dn, attributeValueString) {
				if ignoreRDNAttributes == nil {
					ignoreRDNAttributes = new([]string)
				}
				*ignoreRDNAttributes = append(*ignoreRDNAttributes, attributeName)
			}
		}
	}
	return ignoreRDNAttributes
}

func IgnoreAndBase64encodeAttributes(ldapEntry *LdapEntry, ignoreAndBase64Encode *IgnoreAndBase64Encode) {
	IgnoreAttributes(ldapEntry, ignoreAndBase64Encode)
	for attributeName, attributeValues := range ldapEntry.Entry {
		values := attributeValues
		if ignoreAndBase64Encode.Base64encodeAttributes != nil {
			if slices.Contains(*ignoreAndBase64Encode.Base64encodeAttributes, attributeName) {
				for i, value := range values {
					values[i] = base64.StdEncoding.EncodeToString([]byte(value))
				}
			}
		}
		if ignoreAndBase64Encode.Base64encodeAttributePatterns != nil {
			base64encode := false
			for _, pattern := range *ignoreAndBase64Encode.Base64encodeAttributePatterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attributeName) {
					base64encode = true
				}
			}
			if base64encode {
				for i, value := range values {
					values[i] = base64.StdEncoding.EncodeToString([]byte(value))
				}
			}
		}
		ldapEntry.Entry[attributeName] = values
	}
}

func IgnoreAndBase64decodeAttributes(ldapEntry *LdapEntry, ignoreAndBase64Encode *IgnoreAndBase64Encode) (err error) {
	IgnoreAttributes(ldapEntry, ignoreAndBase64Encode)
	for attributeName, attributeValues := range ldapEntry.Entry {
		values := attributeValues
		if ignoreAndBase64Encode.Base64encodeAttributes != nil {
			if slices.Contains(*ignoreAndBase64Encode.Base64encodeAttributes, attributeName) {
				for i, value := range values {
					bytes, err := base64.StdEncoding.DecodeString(value)
					if err != nil {
						return err
					}
					values[i] = string(bytes)
				}
			}
		}
		if ignoreAndBase64Encode.Base64encodeAttributePatterns != nil {
			base64encode := false
			for _, pattern := range *ignoreAndBase64Encode.Base64encodeAttributePatterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attributeName) {
					base64encode = true
				}
			}
			if base64encode {
				for i, value := range values {
					bytes, err := base64.StdEncoding.DecodeString(value)
					if err != nil {
						return err
					}
					values[i] = string(bytes)
				}
			}
		}
		ldapEntry.Entry[attributeName] = values
	}
	return nil
}

func IgnoreAttributes(ldapEntry *LdapEntry, ignoreAndBase64Encode *IgnoreAndBase64Encode) {
	for attributeName, _ := range ldapEntry.Entry {
		if ignoreAndBase64Encode.IgnoreAttributes != nil {
			if slices.Contains(*ignoreAndBase64Encode.IgnoreAttributes, attributeName) {
				delete(ldapEntry.Entry, attributeName)
				continue // do not check base64encode
			}
		}
		if ignoreAndBase64Encode.IgnoreAttributePatterns != nil {
			ignore := false
			for _, pattern := range *ignoreAndBase64Encode.IgnoreAttributePatterns {
				r := regexp.MustCompile(pattern)
				if r.MatchString(attributeName) {
					ignore = true
				}
			}
			if ignore {
				delete(ldapEntry.Entry, attributeName)
				continue // do not check base64encode
			}
		}
	}
}
