package main

// PhantomQR crypto core: HMAC-SHA256 over a canonical message.
//
// Token proves: "this is enrolled student/device X and this token is fresh."
// It deliberately does NOT contain session/course/room — the professor's
// authenticated scanner session supplies that (direction flip).
//
// Canonical message (deterministic, pipe-joined, no JSON ambiguity):
//     sid|did|ctr|ts|nonce
// mac = hex(HMAC-SHA256(student_secret_key, canonical))

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// CanonicalMessage builds the exact signed bytes. Field order is fixed.
func CanonicalMessage(sid, did string, ctr int64, ts int64, nonce string) string {
	return fmt.Sprintf("%s|%s|%d|%d|%s", sid, did, ctr, ts, nonce)
}

// ComputeMAC returns lowercase hex HMAC-SHA256(key, canonical).
func ComputeMAC(key []byte, canonical string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyMAC uses constant-time comparison so an attacker cannot learn the
// correct MAC byte-by-byte from timing differences (why not ==).
func VerifyMAC(key []byte, canonical, macHex string) bool {
	want := ComputeMAC(key, canonical)
	// subtle.ConstantTimeCompare requires equal length; hex MACs are fixed 64 chars.
	a, b := []byte(want), []byte(macHex)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomHex returns n random bytes as hex (n bytes -> 2n chars).
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// KeyFingerprint shows only a prefix of SHA-256(key) for the debug panel.
// Never expose the full key in UI/logs.
func KeyFingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])[:12]
}
