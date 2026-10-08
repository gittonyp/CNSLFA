package main

import (
	"crypto/rand"
	"crypto/subtle"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
