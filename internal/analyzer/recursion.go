package analyzer

// RecursionCheckResult stores the AA and RA flags observed from one server.
type RecursionCheckResult struct {
	Server             string `json:"server"`
	Authoritative      *bool  `json:"authoritative,omitempty"`
	RecursionAvailable *bool  `json:"recursion_available,omitempty"`
	Error              string `json:"error,omitempty"`
}

// RecursionDiagnosis stores the domain-level open recursion diagnosis.
type RecursionDiagnosis struct {
	OpenRecursionRisk          bool                   `json:"open_recursion_risk"`
	VulnerableRecursionServers []RecursionCheckResult `json:"vulnerable_recursion_servers"`
}

// ValidateOpenRecursion flags authoritative servers that advertise RA.
func ValidateOpenRecursion(results []RecursionCheckResult) RecursionDiagnosis {
	diagnosis := RecursionDiagnosis{
		VulnerableRecursionServers: []RecursionCheckResult{},
	}
	for _, result := range results {
		if result.Authoritative != nil && *result.Authoritative &&
			result.RecursionAvailable != nil && *result.RecursionAvailable {
			diagnosis.OpenRecursionRisk = true
			diagnosis.VulnerableRecursionServers = append(diagnosis.VulnerableRecursionServers, result)
		}
	}
	return diagnosis
}
