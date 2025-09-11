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

func (p *PCRs) isMinimalPCRSet() bool {
	return p.PCR0 != "" && p.PCR1 != "" && p.PCR2 != ""
}

// Check if the receivedPCRs meet the expectations of the provided PCRs. 
// The PCRs given as a parameter are expected to be the PCRs received from the remote enclave.
// 
// The `receivedPCRs` are compared against the current PCR object which is assumed to be a
// partial set of expected PCR values. Any set PCR values are expected to be equal to the
// corresponding `receivedPCRs` value.
// 
// If any expected PCR value is not equal, this function returns false.
func (p *PCRs) SatisfiedBy(receivedPCRs PCRs) bool {
	// If the set of receivedPCRs has zero values for any of the minimally expected PCRs, short circuit
	if !receivedPCRs.isMinimalPCRSet() {
		return false
	}

	if p.PCR0 != "" && p.PCR0 != receivedPCRs.PCR0 {
		return false
	}

	if p.PCR1 != "" && p.PCR1 != receivedPCRs.PCR1 {
		return false
	}

	if p.PCR2 != "" && p.PCR2 != receivedPCRs.PCR2 {
		return false
	}

	if p.PCR8 != "" && p.PCR8 != receivedPCRs.PCR8 {
		return false
	}

	return true
}

// IsEmpty checks if all PCRs in the struct are empty.
func (p *PCRs) IsEmpty() bool {
	return p.PCR0 == "" && p.PCR1 == "" && p.PCR2 == "" && p.PCR8 == ""
}

func BuildStaticPcrProvider(pcrs []PCRs) func() ([]PCRs, error) {
	return func() ([]PCRs, error) {
		return pcrs, nil
	}
}
