package client

type LdapEntry struct {
	Entry map[string][]string
	Dn    string
}

type IgnoreAndBase64Encode struct {
	IgnoreAttributes              *[]string
	IgnoreAttributePatterns       *[]string
	Base64encodeAttributes        *[]string
	Base64encodeAttributePatterns *[]string
}

func NewIgnoreAndBase64Encode() *IgnoreAndBase64Encode {
	return &IgnoreAndBase64Encode{
		new([]string),
		new([]string),
		new([]string),
		new([]string),
	}
}
