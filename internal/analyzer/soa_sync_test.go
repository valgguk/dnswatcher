package analyzer

import "testing"

func TestValidateSerialSyncDeterministic(t *testing.T) {
	majority := uint32(2026110801)
	outdated := uint32(2026110800)

	diagnosis := ValidateSerialSync([]NSSerialResult{
		{Server: "ns1.nic.cl", Serial: &outdated},
		{Server: "ns2.nic.cl", Serial: &majority},
		{Server: "ns3.nic.cl", Serial: &majority},
		{Server: "ns4.nic.cl", Error: "ns_unverifiable_error"},
	})

	if !diagnosis.HasMismatch {
		t.Fatal("expected a serial mismatch")
	}
	if diagnosis.ReferenceSerial == nil || *diagnosis.ReferenceSerial != majority {
		t.Fatalf("reference serial = %v, want %d", diagnosis.ReferenceSerial, majority)
	}
	if len(diagnosis.OutOfSyncServers) != 1 || diagnosis.OutOfSyncServers[0].Server != "ns1.nic.cl" {
		t.Fatalf("out-of-sync servers = %#v", diagnosis.OutOfSyncServers)
	}
	if len(diagnosis.UnverifiableServers) != 1 || diagnosis.UnverifiableServers[0] != "ns4.nic.cl" {
		t.Fatalf("unverifiable servers = %#v", diagnosis.UnverifiableServers)
	}
}

func TestValidateSerialSyncTieUsesFirstValidSerial(t *testing.T) {
	first := uint32(10)
	second := uint32(20)

	diagnosis := ValidateSerialSync([]NSSerialResult{
		{Server: "ns1.example", Serial: &first},
		{Server: "ns2.example", Serial: &second},
	})

	if diagnosis.ReferenceSerial == nil || *diagnosis.ReferenceSerial != first {
		t.Fatalf("reference serial = %v, want %d", diagnosis.ReferenceSerial, first)
	}
}
