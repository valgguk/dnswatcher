package analyzer

import "testing"

func TestValidateTCPSupport(t *testing.T) {
	supported := true
	unsupported := false

	tests := []struct {
		name        string
		results     []TCPCheckResult
		expected    bool
		nonTCPCount int
	}{
		{
			name: "all servers support TCP",
			results: []TCPCheckResult{
				{Server: "ns1.example", TCPSupported: &supported},
				{Server: "ns2.example", TCPSupported: &supported},
			},
			expected: true,
		},
		{
			name: "one server does not support TCP",
			results: []TCPCheckResult{
				{Server: "ns1.example", TCPSupported: &supported},
				{Server: "ns2.example", TCPSupported: &unsupported, Error: "tcp_connection_failed"},
			},
			nonTCPCount: 1,
		},
		{
			name: "no verifiable server",
			results: []TCPCheckResult{
				{Server: "ns1.example", Error: "tcp_timeout"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			diagnosis := ValidateTCPSupport(test.results)
			if diagnosis.TCPSupportValidation != test.expected {
				t.Fatalf("validation = %v, want %v", diagnosis.TCPSupportValidation, test.expected)
			}
			if len(diagnosis.NonTCPServers) != test.nonTCPCount {
				t.Fatalf("non-TCP servers = %d, want %d", len(diagnosis.NonTCPServers), test.nonTCPCount)
			}
		})
	}
}
