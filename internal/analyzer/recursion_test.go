package analyzer

import "testing"

func TestValidateOpenRecursion(t *testing.T) {
	isTrue := true
	isFalse := false

	tests := []struct {
		name         string
		result       RecursionCheckResult
		expectedRisk bool
		vulnerable   int
	}{
		{
			name: "authoritative server without recursion",
			result: RecursionCheckResult{
				Server:             "ns1.example",
				Authoritative:      &isTrue,
				RecursionAvailable: &isFalse,
			},
		},
		{
			name: "authoritative server with recursion",
			result: RecursionCheckResult{
				Server:             "ns2.example",
				Authoritative:      &isTrue,
				RecursionAvailable: &isTrue,
			},
			expectedRisk: true,
			vulnerable:   1,
		},
		{
			name: "network error",
			result: RecursionCheckResult{
				Server: "ns3.example",
				Error:  "ns_unverifiable_error",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnosis := ValidateOpenRecursion([]RecursionCheckResult{test.result})
			if diagnosis.OpenRecursionRisk != test.expectedRisk {
				t.Fatalf("risk = %v, want %v", diagnosis.OpenRecursionRisk, test.expectedRisk)
			}
			if len(diagnosis.VulnerableRecursionServers) != test.vulnerable {
				t.Fatalf("vulnerable servers = %d, want %d", len(diagnosis.VulnerableRecursionServers), test.vulnerable)
			}
		})
	}
}
