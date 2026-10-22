//go:build !go1.25

package attestation_test

import (
	"testing"
	"testing/synctest"
)

// runInBubble runs f inside a synctest bubble. Go 1.24 only exposes the
// experimental synctest.Run API, which requires GOEXPERIMENT=synctest.
func runInBubble(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	synctest.Run(func() { f(t) })
}
