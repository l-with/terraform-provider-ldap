package ldap

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/l-with/terraform-provider-ldap/client"
)

func getIgnoreAndBase64encode(d *schema.ResourceData) (ignoreAndBas64Encode *client.IgnoreAndBase64Encode) {
	ignoreAndBas64Encode = client.NewIgnoreAndBase64Encode()
	ignoreAndBas64Encode.IgnoreAttributes = getAttributeListFromAttribute(d, attributeNameIgnoreAttributes)
	ignoreAndBas64Encode.IgnoreAttributePatterns = getAttributeListFromAttribute(d, attributeNameIgnoreAttributePatterns)
	ignoreAndBas64Encode.Base64encodeAttributes = getAttributeListFromAttribute(d, attributeNameBase64EncodeAttributes)
	ignoreAndBas64Encode.Base64encodeAttributePatterns = getAttributeListFromAttribute(d, attributeNameBase64EncodeAttributePatterns)
	return ignoreAndBas64Encode
}

func getAttributeListFromAttribute(d *schema.ResourceData, attributeName string) (attributeList *[]string) {
	attributeList = new([]string)
	for _, attributeListValue := range d.Get(attributeName).([]interface{}) {
		*attributeList = append(*attributeList, attributeListValue.(string))
	}
	return attributeList
}

func getOldIgnoreAndBase64encode(d *schema.ResourceData) (oldIgnoreAndBas64Encode *client.IgnoreAndBase64Encode) {
	oldIgnoreAndBas64Encode = client.NewIgnoreAndBase64Encode()
	oldIgnoreAndBas64Encode.IgnoreAttributes = getOldAttributeListFromAttribute(d, attributeNameIgnoreAttributes)
	oldIgnoreAndBas64Encode.IgnoreAttributePatterns = getOldAttributeListFromAttribute(d, attributeNameIgnoreAttributePatterns)
	oldIgnoreAndBas64Encode.Base64encodeAttributes = getOldAttributeListFromAttribute(d, attributeNameBase64EncodeAttributes)
	oldIgnoreAndBas64Encode.Base64encodeAttributePatterns = getOldAttributeListFromAttribute(d, attributeNameBase64EncodeAttributePatterns)
	return oldIgnoreAndBas64Encode
}

func getOldAttributeListFromAttribute(d *schema.ResourceData, attributeName string) (oldAttributeList *[]string) {
	oldAttributeList = new([]string)
	var oldAttributeValue interface{}
	if d.HasChange(attributeName) {
		oldAttributeValue, _ = d.GetChange(attributeNameIgnoreAttributes)
	} else {
		oldAttributeValue = d.Get(attributeName)
	}
	for _, attributeListValue := range oldAttributeValue.([]interface{}) {
		*oldAttributeList = append(*oldAttributeList, attributeListValue.(string))
	}
	return oldAttributeList
}
