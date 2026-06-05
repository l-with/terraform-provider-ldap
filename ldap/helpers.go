package ldap

import (
	"encoding/json"

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

// parseCreateDefaults decodes the data_json_create_defaults JSON string
// (same shape as data_json: attribute name -> list of values). An empty
// or unparseable value yields an empty map — validation of the string is
// handled by the schema ValidateFunc, so callers stay total.
func parseCreateDefaults(raw interface{}) map[string][]string {
	result := map[string][]string{}
	s, ok := raw.(string)
	if !ok || s == "" {
		return result
	}
	decoded := map[string][]string{}
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		return result
	}
	for k, v := range decoded {
		result[k] = v
	}
	return result
}

// getCreateDefaults returns the data_json_create_defaults values
// (attribute name -> values to inject on Create if absent from data_json).
func getCreateDefaults(d *schema.ResourceData) map[string][]string {
	return parseCreateDefaults(d.Get(attributeNameDataJsonCreateDefaults))
}

// appendCreateDefaultKeysToIgnore extends the ignore list so that
// Read/Update paths treat data_json_create_defaults keys identically to
// ignore_attributes. The Create path must NOT call this — if it did,
// the injected defaults would be stripped back out before the LDAP Add.
func appendCreateDefaultKeysToIgnore(ig *client.IgnoreAndBase64Encode, d *schema.ResourceData) {
	for k := range getCreateDefaults(d) {
		*ig.IgnoreAttributes = append(*ig.IgnoreAttributes, k)
	}
}

// appendOldCreateDefaultKeysToIgnore mirrors appendCreateDefaultKeysToIgnore
// against the pre-apply value of data_json_create_defaults so that keys
// removed from it in the current plan are still stripped from the OLD
// data_json before the add/delete/change-set diff is computed.
func appendOldCreateDefaultKeysToIgnore(ig *client.IgnoreAndBase64Encode, d *schema.ResourceData) {
	var raw interface{}
	if d.HasChange(attributeNameDataJsonCreateDefaults) {
		raw, _ = d.GetChange(attributeNameDataJsonCreateDefaults)
	} else {
		raw = d.Get(attributeNameDataJsonCreateDefaults)
	}
	for k := range parseCreateDefaults(raw) {
		*ig.IgnoreAttributes = append(*ig.IgnoreAttributes, k)
	}
}
