package ldap

import (
	"encoding/json"
	"testing"
)

func TestIsIgnoredAttribute(t *testing.T) {
	tests := []struct {
		name     string
		attr     string
		ignore   []string
		patterns []string
		want     bool
	}{
		{
			name:   "exact match",
			attr:   "olcArgsFile",
			ignore: []string{"olcArgsFile", "olcPidFile"},
			want:   true,
		},
		{
			name:   "case insensitive match",
			attr:   "olcArgsFile",
			ignore: []string{"olcargsfile"},
			want:   true,
		},
		{
			name:   "no match",
			attr:   "olcLogLevel",
			ignore: []string{"olcArgsFile", "olcPidFile"},
			want:   false,
		},
		{
			name:     "pattern match",
			attr:     "olcTLSCertificateFile",
			patterns: []string{"^olcTLS.*"},
			want:     true,
		},
		{
			name:     "pattern no match",
			attr:     "olcLogLevel",
			patterns: []string{"^olcTLS.*"},
			want:     false,
		},
		{
			name:     "combined exact and pattern",
			attr:     "olcServerID",
			ignore:   []string{"olcServerID"},
			patterns: []string{"^olcTLS.*"},
			want:     true,
		},
		{
			name: "empty lists",
			attr: "olcLogLevel",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIgnoredAttribute(tt.attr, tt.ignore, tt.patterns)
			if got != tt.want {
				t.Errorf("isIgnoredAttribute(%q) = %v, want %v", tt.attr, got, tt.want)
			}
		})
	}
}

func TestCustomizeDiffIgnoreAttributes(t *testing.T) {
	tests := []struct {
		name           string
		oldDataJson    string
		newDataJson    string
		ignoreAttrs    []string
		ignorePatterns []string
		wantChanged    bool
		wantAttrs      []string // attributes expected in result
		wantMissing    []string // attributes expected NOT in result
	}{
		{
			name: "ignored attributes carried over from old",
			oldDataJson: toJSON(map[string][]string{
				"objectClass":   {"olcGlobal"},
				"olcLogLevel":   {"none"},
				"olcArgsFile":   {"/var/run/slapd/slapd.args"},
				"olcPidFile":    {"/var/run/slapd/slapd.pid"},
				"olcServerID":   {"1 ldaps://host1"},
				"cn":            {"config"},
			}),
			newDataJson: toJSON(map[string][]string{
				"objectClass":  {"olcGlobal"},
				"olcDisallows": {"bind_anon"},
				"olcLogLevel":  {"256 16384"},
			}),
			ignoreAttrs: []string{"olcArgsFile", "olcPidFile", "olcServerID", "cn"},
			wantChanged: true,
			wantAttrs:   []string{"objectClass", "olcDisallows", "olcLogLevel", "olcArgsFile", "olcPidFile", "olcServerID", "cn"},
		},
		{
			name: "pattern-based ignore carried over",
			oldDataJson: toJSON(map[string][]string{
				"objectClass":              {"olcGlobal"},
				"olcTLSCertificateFile":    {"/etc/ldap/cert.pem"},
				"olcTLSCertificateKeyFile": {"/etc/ldap/key.pem"},
				"olcLogLevel":              {"none"},
			}),
			newDataJson: toJSON(map[string][]string{
				"objectClass": {"olcGlobal"},
				"olcLogLevel": {"256"},
			}),
			ignorePatterns: []string{"^olcTLS.*"},
			wantChanged:    true,
			wantAttrs:      []string{"objectClass", "olcLogLevel", "olcTLSCertificateFile", "olcTLSCertificateKeyFile"},
		},
		{
			name: "no ignored attributes in old - no change",
			oldDataJson: toJSON(map[string][]string{
				"objectClass": {"olcGlobal"},
				"olcLogLevel": {"none"},
			}),
			newDataJson: toJSON(map[string][]string{
				"objectClass":  {"olcGlobal"},
				"olcDisallows": {"bind_anon"},
				"olcLogLevel":  {"256"},
			}),
			ignoreAttrs: []string{"olcArgsFile", "olcPidFile"},
			wantChanged: false,
		},
		{
			name: "attribute in both old and new is not duplicated",
			oldDataJson: toJSON(map[string][]string{
				"objectClass": {"olcGlobal"},
				"olcLogLevel": {"none"},
				"olcArgsFile": {"/var/run/slapd/slapd.args"},
			}),
			newDataJson: toJSON(map[string][]string{
				"objectClass": {"olcGlobal"},
				"olcLogLevel": {"256"},
				"olcArgsFile": {"/new/path"},
			}),
			ignoreAttrs: []string{"olcArgsFile"},
			wantChanged: false, // olcArgsFile exists in new already, no copy needed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyIgnoreAttributesLogic(
				tt.oldDataJson,
				tt.newDataJson,
				tt.ignoreAttrs,
				tt.ignorePatterns,
			)

			if tt.wantChanged && result == "" {
				t.Fatal("expected data_json to be modified, but got no change")
			}
			if !tt.wantChanged && result != "" {
				t.Fatalf("expected no change, but got: %s", result)
			}

			if tt.wantChanged {
				var entry map[string][]string
				if err := json.Unmarshal([]byte(result), &entry); err != nil {
					t.Fatalf("failed to parse result JSON: %v", err)
				}
				for _, attr := range tt.wantAttrs {
					if _, ok := entry[attr]; !ok {
						t.Errorf("expected attribute %q in result, but not found", attr)
					}
				}
				for _, attr := range tt.wantMissing {
					if _, ok := entry[attr]; ok {
						t.Errorf("expected attribute %q NOT in result, but found", attr)
					}
				}
			}
		})
	}
}

// applyIgnoreAttributesLogic is the extracted core logic of
// customizeDiffIgnoreAttributes, testable without a full ResourceDiff.
// Returns the modified newDataJson or "" if no change was needed.
func applyIgnoreAttributesLogic(oldDataJson, newDataJson string, ignoreAttrs, ignorePatterns []string) string {
	if len(ignoreAttrs) == 0 && len(ignorePatterns) == 0 {
		return ""
	}
	if oldDataJson == "" || newDataJson == "" {
		return ""
	}

	var oldEntry map[string][]string
	if err := json.Unmarshal([]byte(oldDataJson), &oldEntry); err != nil {
		return ""
	}
	var newEntry map[string][]string
	if err := json.Unmarshal([]byte(newDataJson), &newEntry); err != nil {
		return ""
	}

	changed := false
	for attr, val := range oldEntry {
		if _, exists := newEntry[attr]; exists {
			continue
		}
		if isIgnoredAttribute(attr, ignoreAttrs, ignorePatterns) {
			newEntry[attr] = val
			changed = true
		}
	}

	if !changed {
		return ""
	}

	newJson, err := json.Marshal(newEntry)
	if err != nil {
		return ""
	}
	return string(newJson)
}

func toJSON(m map[string][]string) string {
	b, _ := json.Marshal(m)
	return string(b)
}
