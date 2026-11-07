package analyzer

import (
	"sort"
	"strings"
)

type DelegationDiagnosis struct {
	Status           string   `json:"status"`
	Message          string   `json:"message"`
	MissingInPrimary []string `json:"missing_in_primary,omitempty"`
	MissingInParent  []string `json:"missing_in_parent,omitempty"`
	TLDServers       []string `json:"tld_servers"`
	PrimaryServers   []string `json:"primary_servers"`
}

func CompareNS(primaryNS, parentNS []string) DelegationDiagnosis {
	primary := normalize(primaryNS)
	parent := normalize(parentNS)
	missingInPrimary := difference(parent, primary)
	missingInParent := difference(primary, parent)
	sort.Strings(missingInPrimary)
	sort.Strings(missingInParent)

	result := DelegationDiagnosis{
		Status:           "ok",
		Message:          "delegation_ok",
		MissingInPrimary: missingInPrimary,
		MissingInParent:  missingInParent,
		TLDServers:       values(parent),
		PrimaryServers:   values(primary),
	}
	if len(missingInPrimary) > 0 || len(missingInParent) > 0 {
		result.Status = "warning"
		result.Message = "delegation_warning"
	}
	return result
}

func normalize(servers []string) map[string]struct{} {
	result := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		server = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(server), "."))
		if server != "" {
			result[server] = struct{}{}
		}
	}
	return result
}

func difference(left, right map[string]struct{}) []string {
	result := make([]string, 0)
	for server := range left {
		if _, ok := right[server]; !ok {
			result = append(result, server)
		}
	}
	return result
}

func values(servers map[string]struct{}) []string {
	result := make([]string, 0, len(servers))
	for server := range servers {
		result = append(result, server)
	}
	sort.Strings(result)
	return result
}
