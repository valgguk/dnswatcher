package analyzer

import (
	"reflect"
	"testing"
)

func TestCompareNS(t *testing.T) {
	got := CompareNS([]string{"NS1.Example.", "ns2.example"}, []string{"ns1.example", "NS3.Example."})
	if got.Status != "warning" {
		t.Fatalf("status = %q", got.Status)
	}
	if !reflect.DeepEqual(got.MissingInPrimary, []string{"ns3.example"}) {
		t.Fatalf("missing in primary = %#v", got.MissingInPrimary)
	}
	if !reflect.DeepEqual(got.MissingInParent, []string{"ns2.example"}) {
		t.Fatalf("missing in parent = %#v", got.MissingInParent)
	}
}
