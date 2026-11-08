package analyzer

// NSSerialResult stores the SOA serial observed from one authoritative server.
type NSSerialResult struct {
	Server string  `json:"server"`
	Serial *uint32 `json:"serial,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// SOASyncDiagnosis stores the domain-level SOA synchronization diagnosis.
type SOASyncDiagnosis struct {
	IsSynchronized      bool             `json:"is_synchronized"`
	ReferenceSerial     *uint32          `json:"reference_serial,omitempty"`
	HasMismatch         bool             `json:"has_mismatch"`
	OutOfSyncServers    []NSSerialResult `json:"out_of_sync_servers"`
	UnverifiableServers []string         `json:"unverifiable_servers"`
}

// ValidateSerialSync selects the most frequent valid serial as the reference
// and compares all other valid server responses against it.
func ValidateSerialSync(results []NSSerialResult) SOASyncDiagnosis {
	diagnosis := SOASyncDiagnosis{
		OutOfSyncServers:    []NSSerialResult{},
		UnverifiableServers: []string{},
	}
	if len(results) == 0 {
		return diagnosis
	}

	frequency := make(map[uint32]int)
	validSerials := make([]uint32, 0, len(results))
	for _, result := range results {
		if result.Error != "" || result.Serial == nil {
			diagnosis.UnverifiableServers = append(diagnosis.UnverifiableServers, result.Server)
			continue
		}
		frequency[*result.Serial]++
		validSerials = append(validSerials, *result.Serial)
	}

	if len(validSerials) == 0 {
		return diagnosis
	}

	var referenceSerial uint32
	maxFrequency := 0
	for _, serial := range validSerials {
		if frequency[serial] > maxFrequency {
			referenceSerial = serial
			maxFrequency = frequency[serial]
		}
	}
	diagnosis.ReferenceSerial = &referenceSerial

	for _, result := range results {
		if result.Error == "" && result.Serial != nil && *result.Serial != referenceSerial {
			diagnosis.HasMismatch = true
			diagnosis.OutOfSyncServers = append(diagnosis.OutOfSyncServers, result)
		}
	}
	diagnosis.IsSynchronized = !diagnosis.HasMismatch
	return diagnosis
}
