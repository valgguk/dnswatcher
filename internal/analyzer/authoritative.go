package analyzer

// AuthoritativeCheckResult stores the AA flag observed from one server.
// A nil Authoritative means that no response was available to evaluate.
type AuthoritativeCheckResult struct {
	Server        string `json:"server"`
	Authoritative *bool  `json:"authoritative,omitempty"`
	Error         string `json:"error,omitempty"`
}

// AuthoritativeDiagnosis stores the domain-level authority diagnosis.
type AuthoritativeDiagnosis struct {
	AllAuthoritative        bool                       `json:"all_authoritative"`
	NonAuthoritativeServers []AuthoritativeCheckResult `json:"non_authoritative_servers"`
}

// ValidateAuthoritativeFlags evaluates the AA flag for each server response.
func ValidateAuthoritativeFlags(results []AuthoritativeCheckResult) AuthoritativeDiagnosis {
	diagnosis := AuthoritativeDiagnosis{
		NonAuthoritativeServers: []AuthoritativeCheckResult{},
	}
	validCount := 0
	for _, result := range results {
		if result.Authoritative == nil {
			continue
		}
		validCount++
		if !*result.Authoritative {
			diagnosis.NonAuthoritativeServers = append(diagnosis.NonAuthoritativeServers, result)
		}
	}
	diagnosis.AllAuthoritative = validCount > 0 && len(diagnosis.NonAuthoritativeServers) == 0
	return diagnosis
}
