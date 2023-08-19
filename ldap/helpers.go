package ldap

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func getIgnoreAndBase64encode(
	d *schema.ResourceData,
	ignoreAttributes *[]string,
	ignoreAttributePatterns *[]string,
	base64encodeAttributes *[]string,
	base64encodeAttributePatterns *[]string,
) {
	for _, ignoreAttribute := range d.Get(attributeNameIgnoreAttributes).([]interface{}) {
		*ignoreAttributes = append(*ignoreAttributes, ignoreAttribute.(string))
	}
	for _, ignoreAttributePattern := range d.Get(attributeNameIgnoreAttributePatterns).([]interface{}) {
		*ignoreAttributePatterns = append(*ignoreAttributePatterns, ignoreAttributePattern.(string))
	}
	for _, base64encodeAttribute := range d.Get(attributeNameBase64EncodeAttributes).([]interface{}) {
		*base64encodeAttributes = append(*base64encodeAttributes, base64encodeAttribute.(string))
	}
	for _, base64encodeAttributePattern := range d.Get(attributeNameBase64EncodeAttributePatterns).([]interface{}) {
		*base64encodeAttributePatterns = append(*base64encodeAttributePatterns, base64encodeAttributePattern.(string))
	}
}
