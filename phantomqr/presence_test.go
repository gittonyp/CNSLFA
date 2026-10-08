package main

import (
	"testing"
	"time"
)

func TestCheckWifiProximitySameSubnet(t *testing.T) {
	ok, _ := CheckWifiProximity("192.168.1.10", "192.168.1.45", 24)
	if !ok {
		t.Fatal("same /24 should be in range")
	}
}

func TestCheckWifiProximityDifferentSubnet(t *testing.T) {
	ok, _ := CheckWifiProximity("192.168.1.10", "192.168.2.45", 24)
	if ok {
		t.Fatal("different /24 should be out of range")
	}
}

func TestCheckWifiProximityWithPorts(t *testing.T) {
	// RemoteAddr form with ports must be tolerated.
	ok, _ := CheckWifiProximity("192.168.1.10:54321", "[192.168.1.99]:8812", 24)
	if !ok {
		t.Fatal("host:port form should still match same subnet")
	}
}

func TestCheckWifiProximityLoopbackDemo(t *testing.T) {
	ok, _ := CheckWifiProximity("127.0.0.1:8812", "127.0.0.1", 24)
	if !ok {
		t.Fatal("loopback demo (same laptop) should pass")
	}
}

func TestCheckWifiProximityInvalid(t *testing.T) {
	if ok, _ := CheckWifiProximity("", "192.168.1.5", 24); ok {
		t.Fatal("missing scanner IP must fail")
	}
	if ok, _ := CheckWifiProximity("192.168.1.5", "not-an-ip", 24); ok {
		t.Fatal("invalid student IP must fail")
	}
	if ok, _ := CheckWifiProximity("192.168.1.5", "2001:db8::1", 24); ok {
		t.Fatal("v4 vs v6 mismatch must fail")
	}
}

func TestCheckWifiProximityIPv6(t *testing.T) {
	ok, _ := CheckWifiProximity("2001:db8:1::10", "2001:db8:1::99", 64)
	if !ok {
		t.Fatal("same /64 should be in range")
	}
	ok, _ = CheckWifiProximity("2001:db8:1::10", "2001:db8:2::99", 64)
	if ok {
		t.Fatal("different /64 should be out of range")
	}
}

func TestPresenceTrackerFreshAndStale(t *testing.T) {
	tr := NewPresenceTracker(90, 24)
	now := time.Now().Unix()
	tr.Heartbeat("S1", "192.168.1.20", "192.168.1.20", now)
	if ok, _ := tr.Verify("S1", "192.168.1.5", now+10); !ok {
		t.Fatal("fresh same-subnet heartbeat should verify")
	}
	if ok, _ := tr.Verify("S1", "10.0.5.5", now+10); ok {
		t.Fatal("different subnet must not verify")
	}
	if ok, _ := tr.Verify("S1", "192.168.1.5", now+1000); ok {
		t.Fatal("stale heartbeat must not verify")
	}
	if ok, _ := tr.Verify("NOBODY", "192.168.1.5", now); ok {
		t.Fatal("missing heartbeat must not verify")
	}
}

func TestVerifyScanProximityEnforced(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	presence.Reset()
	defer presence.Reset()

	// Same-machine demo: scanner on loopback, student heartbeat on loopback.
	presence.Heartbeat("21BT0451", "127.0.0.1", "127.0.0.1", time.Now().Unix())
	good := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-prox-ok-000000000001")
	if code, st, _, _ := verifyScanWithProximity(f.db, ScanReq{Token: good, SessionID: f.sess, StaffSessionTok: f.staffTok}, "127.0.0.1"); code != 200 || st != "ACCEPTED" {
		t.Fatalf("in-range scan should accept, got %d %s", code, st)
	}

	// Remote student: heartbeat from another subnet.
	presence.Heartbeat("21BT0452", "10.9.9.9", "10.9.9.9", time.Now().Unix())
	remote := tok(f.keyB, "21BT0452", "a1b2", 1, time.Now().Unix(), "n-prox-far-00000000001")
	if _, st, _, _ := verifyScanWithProximity(f.db, ScanReq{Token: remote, SessionID: f.sess, StaffSessionTok: f.staffTok}, "192.168.1.5"); st != "PROXIMITY_FAIL" {
		t.Fatalf("out-of-range scan should be PROXIMITY_FAIL, got %s", st)
	}

	// No heartbeat at all -> fail closed on the network path.
	ghost := tok(f.keyB, "21BT0452", "a1b2", 2, time.Now().Unix(), "n-prox-nohb-0000000001")
	presence.Reset()
	if _, st, _, _ := verifyScanWithProximity(f.db, ScanReq{Token: ghost, SessionID: f.sess, StaffSessionTok: f.staffTok}, "192.168.1.5"); st != "PROXIMITY_FAIL" {
		t.Fatalf("missing heartbeat should be PROXIMITY_FAIL, got %s", st)
	}

	// Old unit-test path (no network view) still skips proximity.
	fresh := tok(f.keyB, "21BT0452", "a1b2", 3, time.Now().Unix(), "n-prox-skip-0000000001")
	if _, st, _, _ := verifyScan(f.db, ScanReq{Token: fresh, SessionID: f.sess, StaffSessionTok: f.staffTok}); st != "ACCEPTED" {
		t.Fatalf("legacy verifyScan should skip proximity, got %s", st)
	}
}
