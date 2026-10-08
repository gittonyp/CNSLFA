package main

// Physical-presence check over WiFi (same-network proximity).
//
// Why WiFi and not Bluetooth:
//   - Bluetooth proximity needs BLE hardware on the server/scanner host,
//     root + BlueZ, extra Go BLE deps, HTTPS + WebBluetooth on the client,
//     and physical beacons. Not testable in CI and not demo-friendly.
//   - WiFi same-subnet check is pure stdlib (net/netip), works with the
//     existing HTTP flow, needs no new dependencies or hardware.
//
// Model:
//   - The student page POSTs a lightweight heartbeat every ~15s to
//     /api/presence/heartbeat. The server records the heartbeat's egress IP
//     (RemoteAddr, i.e. how the server sees the student) + an optional
//     WebRTC-derived LAN hint + timestamp, keyed by sid.
//   - At scan time the server compares the scanner's egress IP (RemoteAddr
//     of POST /api/attendance/scan) against the student's last heartbeat
//     egress IP with CheckWifiProximity (same /24 for IPv4, /64 for IPv6).
//   - Same subnet => both devices are behind the same classroom WiFi/NAT,
//     so the student is physically in scanner range. Different subnet /
//     stale / missing heartbeat => the QR may be a remote screenshot relay.
//
// Trust note: IPs are network locators, not cryptographic identity. This
// check is a defense-in-depth signal layered AFTER the HMAC/counter/nonce
// pipeline — it raises the bar for remote screenshot forwarding but does
// not replace the crypto. A VPN on both devices could still spoof it
// (documented limitation, same class as the existing "video relay" limit).

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultProximityPrefixV4 is the subnet size for IPv4 classroom WiFi.
	DefaultProximityPrefixV4 = 24
	// DefaultProximityPrefixV6 is the subnet size for IPv6.
	DefaultProximityPrefixV6 = 64
	// PresenceMaxAgeSec is how fresh the student heartbeat must be at scan time.
	PresenceMaxAgeSec = 90
)

// ClientIPFromRemoteAddr strips the port from r.RemoteAddr ("1.2.3.4:5678"
// -> "1.2.3.4"). Handles bare IPs and zone-scoped IPv6.
func ClientIPFromRemoteAddr(remoteAddr string) string {
	s := strings.TrimSpace(remoteAddr)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	// Strip IPv6 zone ("fe80::1%wlan0" -> "fe80::1").
	if i := strings.LastIndex(s, "%"); i != -1 {
		s = s[:i]
	}
	return strings.Trim(s, "[]")
}

// CheckWifiProximity reports whether scannerIP and studentIP look like they
// sit behind the same classroom WiFi (same subnet).
//
// prefixBits <= 0 selects the default (24 for IPv4, 64 for IPv6).
// Returns (inRange, reason) where reason is a short human-readable note.
func CheckWifiProximity(scannerIP, studentIP string, prefixBits int) (bool, string) {
	aStr := strings.TrimSpace(scannerIP)
	bStr := strings.TrimSpace(studentIP)
	if aStr == "" || bStr == "" {
		return false, "missing IP (need scanner + student heartbeat)"
	}
	a := net.ParseIP(ClientIPFromRemoteAddr(aStr))
	b := net.ParseIP(ClientIPFromRemoteAddr(bStr))
	if a == nil || b == nil {
		return false, "invalid IP"
	}
	a4, b4 := a.To4(), b.To4()
	if (a4 == nil) != (b4 == nil) {
		return false, "IP family mismatch (v4 vs v6)"
	}
	// Loopback demo: server + both browsers on one laptop.
	if a.IsLoopback() && b.IsLoopback() {
		return true, "loopback demo (same machine)"
	}
	bits := prefixBits
	if bits <= 0 {
		if a4 != nil {
			bits = DefaultProximityPrefixV4
		} else {
			bits = DefaultProximityPrefixV6
		}
	}
	total := 32
	if a4 == nil {
		total = 128
	}
	if bits < 0 || bits > total {
		return false, "bad prefix size"
	}
	var mask net.IPMask
	var anet, bnet net.IP
	if a4 != nil {
		mask = net.CIDRMask(bits, 32)
		anet, bnet = a4.Mask(mask), b4.Mask(mask)
	} else {
		mask = net.CIDRMask(bits, 128)
		anet, bnet = a.Mask(mask), b.Mask(mask)
	}
	if anet.Equal(bnet) {
		return true, "same /" + itoa(bits) + " subnet (" + anet.String() + ")"
	}
	return false, "different subnets (" + anet.String() + " vs " + bnet.String() + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ---- Heartbeat tracker ----

// PresenceHeartbeat is the last-seen record for one student device.
type PresenceHeartbeat struct {
	EgressIP string `json:"egress_ip"` // how the server saw the student (RemoteAddr)
	LocalIP  string `json:"local_ip"`  // WebRTC-derived LAN hint (untrusted, informational)
	SeenAt   int64  `json:"seen_at"`
}

// PresenceTracker is an in-memory last-seen map keyed by sid.
type PresenceTracker struct {
	mu         sync.Mutex
	last       map[string]PresenceHeartbeat
	maxAgeSec  int64
	prefixBits int
}

// NewPresenceTracker builds a tracker. maxAgeSec<=0 defaults to
// PresenceMaxAgeSec, prefixBits<=0 defaults per IP family.
func NewPresenceTracker(maxAgeSec int64, prefixBits int) *PresenceTracker {
	if maxAgeSec <= 0 {
		maxAgeSec = PresenceMaxAgeSec
	}
	return &PresenceTracker{last: map[string]PresenceHeartbeat{}, maxAgeSec: maxAgeSec, prefixBits: prefixBits}
}

// Heartbeat records a student sighting. now<=0 uses time.Now().
func (t *PresenceTracker) Heartbeat(sid, egressIP, localIP string, now int64) {
	if now <= 0 {
		now = time.Now().Unix()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last[sid] = PresenceHeartbeat{EgressIP: egressIP, LocalIP: localIP, SeenAt: now}
}

// Lookup returns the last heartbeat for sid.
func (t *PresenceTracker) Lookup(sid string) (PresenceHeartbeat, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	hb, ok := t.last[sid]
	return hb, ok
}

// Reset clears all entries (tests).
func (t *PresenceTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last = map[string]PresenceHeartbeat{}
}

// Verify checks the student was recently on the same WiFi as the scanner.
// Returns (present, reason). Missing/stale heartbeat => not present.
func (t *PresenceTracker) Verify(sid, scannerIP string, now int64) (bool, string) {
	if now <= 0 {
		now = time.Now().Unix()
	}
	t.mu.Lock()
	hb, ok := t.last[sid]
	maxAge, bits := t.maxAgeSec, t.prefixBits
	t.mu.Unlock()
	if !ok {
		return false, "no student heartbeat (student not on classroom WiFi?)"
	}
	if now-hb.SeenAt > maxAge {
		return false, "stale heartbeat (last seen too long ago)"
	}
	if scannerIP == "" {
		return false, "missing scanner IP"
	}
	return CheckWifiProximity(scannerIP, hb.EgressIP, bits)
}

// presence is the process-wide tracker used by the HTTP handlers.
var presence = NewPresenceTracker(PresenceMaxAgeSec, 0)

// CheckPresenceForScan is the one-call helper used by the scan pipeline.
func CheckPresenceForScan(sid, scannerIP string) (bool, string) {
	return presence.Verify(sid, scannerIP, time.Now().Unix())
}

// ---- HTTP ----

func handlePresenceHeartbeat(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_ = db // heartbeat is transport-level; kept in memory, not in sqlite
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var in struct {
		SID     string `json:"sid"`
		LocalIP string `json:"local_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "bad JSON"})
		return
	}
	in.SID = strings.TrimSpace(in.SID)
	if in.SID == "" {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "sid required"})
		return
	}
	egress := ClientIPFromRemoteAddr(r.RemoteAddr)
	presence.Heartbeat(in.SID, egress, strings.TrimSpace(in.LocalIP), time.Now().Unix())
	writeJSON(w, 200, map[string]any{"ok": true, "egress_ip": egress})
}

func handlePresenceCheck(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_ = db
	sid := strings.TrimSpace(r.URL.Query().Get("sid"))
	if sid == "" {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "sid required"})
		return
	}
	scannerIP := ClientIPFromRemoteAddr(r.RemoteAddr)
	if q := strings.TrimSpace(r.URL.Query().Get("scanner_ip")); q != "" {
		scannerIP = q // debug override for the dashboard / attacks lab
	}
	ok, reason := CheckPresenceForScan(sid, scannerIP)
	hb, _ := presence.Lookup(sid)
	writeJSON(w, 200, map[string]any{
		"ok": ok, "reason": reason,
		"scanner_ip": scannerIP, "heartbeat": hb,
	})
}
