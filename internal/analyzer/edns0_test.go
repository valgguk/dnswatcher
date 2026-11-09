package analyzer

import "testing"

func TestValidateEDNS0(t *testing.T) {
	supported := true
	unsupported := false

	tests := []struct {
		name         string
		results      []EDNS0CheckResult
		expected     bool
		nonEDNSCount int
	}{
		{
			name: "all servers support EDNS0",
			results: []EDNS0CheckResult{
				{Server: "ns1.example", EDNS0Supported: &supported},
				{Server: "ns2.example", EDNS0Supported: &supported},
			},
			expected: true,
		},
		{
			name: "one server does not support EDNS0",
			results: []EDNS0CheckResult{
				{Server: "ns1.example", EDNS0Supported: &supported},
				{Server: "ns2.example", EDNS0Supported: &unsupported},
			},
			nonEDNSCount: 1,
		},
		{
			name: "no verifiable server",
			results: []EDNS0CheckResult{
				{Server: "ns1.example", Error: "ns_unverifiable_error"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnosis := ValidateEDNS0(test.results)
			if diagnosis.EDNS0Validation != test.expected {
				t.Fatalf("validation = %v, want %v", diagnosis.EDNS0Validation, test.expected)
			}
			if len(diagnosis.NonEDNS0Servers) != test.nonEDNSCount {
				t.Fatalf("non-EDNS0 servers = %d, want %d", len(diagnosis.NonEDNS0Servers), test.nonEDNSCount)
			}
		})
	}
}
