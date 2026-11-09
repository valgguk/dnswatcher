package analyzer

// EDNS0CheckResult stores EDNS0 support observed from one server.
// A nil EDNS0Supported means that the result could not be verified.
type EDNS0CheckResult struct {
	Server         string `json:"server"`
	EDNS0Supported *bool  `json:"edns0_supported,omitempty"`
	Error          string `json:"error,omitempty"`
}

// EDNS0Diagnosis stores the domain-level EDNS0 diagnosis.
type EDNS0Diagnosis struct {
	EDNS0Validation bool               `json:"edns0_validation"`
	NonEDNS0Servers []EDNS0CheckResult `json:"non_edns0_servers"`
}

// ValidateEDNS0 verifies that every reachable server returned an OPT record.
func ValidateEDNS0(results []EDNS0CheckResult) EDNS0Diagnosis {
	diagnosis := EDNS0Diagnosis{
		NonEDNS0Servers: []EDNS0CheckResult{},
	}
	validCount := 0
	for _, result := range results {
		if result.EDNS0Supported == nil {
			continue
		}
		validCount++
		if !*result.EDNS0Supported {
			diagnosis.NonEDNS0Servers = append(diagnosis.NonEDNS0Servers, result)
		}
	}
	diagnosis.EDNS0Validation = validCount > 0 && len(diagnosis.NonEDNS0Servers) == 0
	return diagnosis
}
