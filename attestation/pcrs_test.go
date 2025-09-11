package attestation_test

import (
	"testing"

	"github.com/evervault/evervault-go/attestation"
	"github.com/stretchr/testify/assert"
)

// Confirm that a partial set of PCRs provided as expectation will match if their values
// align with the received values
func TestPartialPCRsMatchReceived(t *testing.T) {
	t.Parallel()

	expectedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR8: "8",
	}

	receivedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR1: "1",
		PCR2: "2",
		PCR8: "8",
	}

	assert.True(t, expectedPcrs.SatisfiedBy(receivedPcrs), "Expect partial set of matching PCRs to result in True")
}

// Confirm that the received PCRs are treated as non matching when any single value is unset
func TestFailureOnAnyMismatch(t *testing.T) {
	t.Parallel()

	expectedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR1: "1",
		PCR2: "2",
		PCR8: "1",
	}

	receivedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR1: "1",
		PCR2: "2",
		PCR8: "8",
	}

	assert.False(t, expectedPcrs.SatisfiedBy(receivedPcrs), "Expect mismatch in any PCR value to return False")
}

// Confirm that received PCRs are rejected if they do not contain a PCR value for which we have an expectation
func TestFailureOnAnyExpectedValueNotSet(t *testing.T) {
	t.Parallel()

	expectedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR8: "8",
	}

	receivedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR1: "1",
		PCR2: "2",
	}

	assert.False(t, expectedPcrs.SatisfiedBy(receivedPcrs), "Expect missing PCR in received value to return False")
}

// Confirm that received PCRs must have at least PCRs 0, 1, and 2 set
func TestFailureOnAnyIncompleteReceivedPCRs(t *testing.T) {
	t.Parallel()

	expectedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR2: "2",
		PCR8: "8",
	}

	receivedPcrs := attestation.PCRs {
		PCR0: "0",
		PCR2: "2",
		PCR8: "8",
	}

	assert.False(t, expectedPcrs.SatisfiedBy(receivedPcrs), "Expect incomplete received PCRs to be rejected with False")
}
