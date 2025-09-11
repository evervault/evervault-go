//go:build synctest && !go1.25

package testhelper

import "testing"

func SyncTest(t *testing.T, fn func(*testing.T)) {
	synctest.Run(func () {
		fn(t)
	})
}

func Wait() {
	synctest.Wait()
}