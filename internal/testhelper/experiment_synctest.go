//go:build goexperiment.synctest && !go1.25

package testhelper

import (
	"testing"
	"testing/synctest"
)

func SyncTest(t *testing.T, fn func(*testing.T)) {
	synctest.Run(func () {
		fn(t)
	})
}

func Wait() {
	synctest.Wait()
}