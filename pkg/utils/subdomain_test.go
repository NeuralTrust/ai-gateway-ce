package utils

import "testing"

func TestExtractTenantFromSubdomain(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		baseDomain string
		want       string
	}{
		{
			name:       "valid tenant subdomain",
			host:       "tenant1.example.com",
			baseDomain: "example.com",
			want:       "tenant1",
		},
		{
			name:       "invalid tenant subdomain",
			host:       "invalid@.example.com",
			baseDomain: "example.com",
			want:       "",
		},
		{
			name:       "no tenant subdomain",
			host:       "example.com",
			baseDomain: "example.com",
			want:       "",
		},
		{
			name:       "with port number",
			host:       "tenant1.example.com:8080",
			baseDomain: "example.com",
			want:       "tenant1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractTenantFromSubdomain(tt.host, tt.baseDomain)
			if got != tt.want {
				t.Errorf("ExtractTenantFromSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
} 