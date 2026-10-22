//go:build go1.25

package attestation_test

import (
	"testing"
	"testing/synctest"
)

// runInBubble runs f inside a synctest bubble.
func runInBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	synctest.Test(t, f)
}
