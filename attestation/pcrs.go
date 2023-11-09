package attestation

// prcEqual Checks if 2 PCR strings are not equal.
func pcrNotEqual(p1, p2 string) bool {
	return p1 != "" && p2 != "" && p1 != p2
}

// PCRs struct for attesting a cage connection against.
type PCRs struct {
	PCR0, PCR1, PCR2, PCR8 string
}

// Check if two PCRs are equal to each other.
func (p *PCRs) Equal(pcrs PCRs) bool {
	if pcrNotEqual(p.PCR0, pcrs.PCR0) {
		return false
	}

	if pcrNotEqual(p.PCR1, pcrs.PCR1) {
		return false
	}

	if pcrNotEqual(p.PCR2, pcrs.PCR2) {
		return false
	}

	if pcrNotEqual(p.PCR8, pcrs.PCR8) {
		return false
	}

	return true
}

// IsEmpty checks if all PCRs in the struct are empty.
func (p *PCRs) IsEmpty() bool {
	return p.PCR0 == "" && p.PCR1 == "" && p.PCR2 == "" && p.PCR8 == ""
}
