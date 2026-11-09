package analyzer

// TCPCheckResult stores the result of a TCP/53 SOA query.
// A nil TCPSupported means that the transport could not be evaluated.
type TCPCheckResult struct {
	Server       string `json:"server"`
	TCPSupported *bool  `json:"tcp_supported,omitempty"`
	Error        string `json:"error,omitempty"`
}

// TCPDiagnosis stores the domain-level TCP support diagnosis.
type TCPDiagnosis struct {
	TCPSupportValidation bool             `json:"tcp_support_validation"`
	NonTCPServers        []TCPCheckResult `json:"non_tcp_servers"`
}

// ValidateTCPSupport verifies that every reachable server supports TCP/53.
func ValidateTCPSupport(results []TCPCheckResult) TCPDiagnosis {
	diagnosis := TCPDiagnosis{
		NonTCPServers: []TCPCheckResult{},
	}
	validCount := 0
	for _, result := range results {
		if result.TCPSupported == nil {
			continue
		}
		validCount++
		if !*result.TCPSupported {
			diagnosis.NonTCPServers = append(diagnosis.NonTCPServers, result)
		}
	}
	diagnosis.TCPSupportValidation = validCount > 0 && len(diagnosis.NonTCPServers) == 0
	return diagnosis
}
