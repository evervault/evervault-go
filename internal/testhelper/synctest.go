//go:build go1.25

package testhelper

import (
	"testing"
	"testing/synctest"
)

func SyncTest(t *testing.T, fn func(*testing.T)) {
	synctest.Test(t, fn)
}

func Wait() {
	synctest.Wait()
}