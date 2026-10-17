package ldap

import (
	"slices"
	"testing"
)

func TestPerValueChanges(t *testing.T) {
	tests := []struct {
		name        string
		oldValues   []string
		newValues   []string
		wantDeleted []string
		wantAdded   []string
	}{
		{
			name:        "value removed",
			oldValues:   []string{"cn=one", "cn=two"},
			newValues:   []string{"cn=one"},
			wantDeleted: []string{"cn=two"},
		},
		{
			name:      "value added",
			oldValues: []string{"cn=one"},
			newValues: []string{"cn=one", "cn=two"},
			wantAdded: []string{"cn=two"},
		},
		{
			name:        "value replaced",
			oldValues:   []string{"cn=one", "cn=two"},
			newValues:   []string{"cn=one", "cn=three"},
			wantDeleted: []string{"cn=two"},
			wantAdded:   []string{"cn=three"},
		},
		{
			name:      "order changed only",
			oldValues: []string{"cn=one", "cn=two"},
			newValues: []string{"cn=two", "cn=one"},
		},
		{
			name:      "attribute added",
			newValues: []string{"cn=one", "cn=two"},
			wantAdded: []string{"cn=one", "cn=two"},
		},
		{
			name:        "attribute deleted",
			oldValues:   []string{"cn=one", "cn=two"},
			wantDeleted: []string{"cn=one", "cn=two"},
		},
		{
			// the LDAP server compares e.g. DNs case-insensitively, so a
			// value differing only in case is the same value
			name:      "case changed only",
			oldValues: []string{"cn=one,ou=groups,dc=example,dc=com"},
			newValues: []string{"CN=one,OU=groups,DC=example,DC=com"},
		},
		{
			name:        "case changed and value replaced",
			oldValues:   []string{"cn=one", "cn=two"},
			newValues:   []string{"CN=one", "CN=three"},
			wantDeleted: []string{"cn=two"},
			wantAdded:   []string{"CN=three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := perValueChanges(tt.oldValues, tt.newValues)
			if !slices.Equal(got.Deleted, tt.wantDeleted) {
				t.Errorf("Deleted = %v, want %v", got.Deleted, tt.wantDeleted)
			}
			if !slices.Equal(got.Added, tt.wantAdded) {
				t.Errorf("Added = %v, want %v", got.Added, tt.wantAdded)
			}
		})
	}
}
