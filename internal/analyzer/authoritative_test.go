package analyzer

import "testing"

func TestValidateAuthoritativeFlags(t *testing.T) {
	authoritative := true
	notAuthoritative := false

	diagnosis := ValidateAuthoritativeFlags([]AuthoritativeCheckResult{
		{Server: "ns1.example", Authoritative: &authoritative},
		{Server: "ns2.example", Authoritative: &notAuthoritative, Error: "ns_unverifiable_noauth_error"},
		{Server: "ns3.example", Error: "ns_unverifiable_error"},
	})

	if diagnosis.AllAuthoritative {
		t.Fatal("expected the diagnosis not to be fully authoritative")
	}
	if len(diagnosis.NonAuthoritativeServers) != 1 || diagnosis.NonAuthoritativeServers[0].Server != "ns2.example" {
		t.Fatalf("non-authoritative servers = %#v", diagnosis.NonAuthoritativeServers)
	}
}

func TestValidateAuthoritativeFlagsRequiresAResponse(t *testing.T) {
	diagnosis := ValidateAuthoritativeFlags([]AuthoritativeCheckResult{
		{Server: "ns1.example", Error: "ns_unverifiable_error"},
	})

	if diagnosis.AllAuthoritative {
		t.Fatal("expected no-response diagnosis not to be authoritative")
	}
}
