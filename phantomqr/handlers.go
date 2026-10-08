package main

// HTTP API + verification pipeline. The scanner is a DUMB CAMERA + RELAY:
// no crypto happens there. Everything below runs on the server.

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Token struct {
	SID   string `json:"sid"`
	DID   string `json:"did"`
	Ctr   int64  `json:"ctr"`
	Ts    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	Mac   string `json:"mac"`
}

type ScanReq struct {
	Token           Token  `json:"token"`
	SessionID       string `json:"session_id"`
	StaffSessionTok string `json:"staff_session_token"`
	ScannedAt       int64  `json:"scanned_at"` // scanner-reported; NOT trusted for validity
}

const (
	tokenValiditySec = 60 // server-time freshness window
	futureSkewSec    = 10 // allow tiny clock skew, reject anything newer
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func staffOf(db *sql.DB, tok string) (staffID, deviceID string, ok bool) {
	if tok == "" {
		return "", "", false
	}
	now := time.Now().Unix()
	err := db.QueryRow(`SELECT staff_id, device_id FROM staff_sessions WHERE token=? AND expires_at>?`, tok, now).Scan(&staffID, &deviceID)
	return staffID, deviceID, err == nil
}

// verifyScan implements STEPS 1-14 in order. Returns (httpStatus, eventType, message, sid).
func verifyScan(db *sql.DB, r ScanReq) (int, string, string, string) {
	t := r.Token
	sid := t.SID

	// STEP 1: staff session.
	staffID, _, ok := staffOf(db, r.StaffSessionTok)
	if !ok {
		logEvent(db, "INVALID_STAFF", sid, r.SessionID, "missing/expired staff session token")
		return 401, "INVALID_STAFF", "REMOTE SUBMISSION BLOCKED — Unauthorized scanner (staff login required)", sid
	}
	_ = staffID

	// STEP 2: session exists.
	var status, course string
	err := db.QueryRow(`SELECT status, course FROM attendance_sessions WHERE session_id=?`, r.SessionID).Scan(&status, &course)
	if err != nil {
		logEvent(db, "INVALID_SESSION", sid, r.SessionID, "unknown session_id")
		return 404, "INVALID_SESSION", "REJECTED: Invalid attendance session", sid
	}
	// STEP 3: session OPEN.
	if status != "OPEN" {
		logEvent(db, "INVALID_SESSION", sid, r.SessionID, "session status="+status)
		return 409, "INVALID_SESSION", "REJECTED: Attendance session closed", sid
	}
	// STEP 4-5: look up student + device.
	var studentExists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM students WHERE sid=?)`, t.SID).Scan(&studentExists); err != nil || !studentExists {
		logEvent(db, "UNKNOWN_STUDENT", sid, r.SessionID, "sid not enrolled")
		return 404, "UNKNOWN_STUDENT", "REJECTED: Unknown student (not enrolled)", sid
	}
	var keyHex string
	var lastCtr int64
	var active int
	var ownerSID string
	err = db.QueryRow(`SELECT secret_key, last_seen_counter, active, sid FROM devices WHERE did=?`, t.DID).Scan(&keyHex, &lastCtr, &active, &ownerSID)
	if err != nil {
		logEvent(db, "UNKNOWN_DEVICE", sid, r.SessionID, "did not enrolled: "+t.DID)
		return 404, "UNKNOWN_DEVICE", "REJECTED: Unknown device", sid
	}
	// STEP 6: sid+did must belong together, device active.
	if ownerSID != t.SID || active != 1 {
		logEvent(db, "UNKNOWN_DEVICE", sid, r.SessionID, "device/student mismatch or revoked")
		return 403, "UNKNOWN_DEVICE", "REJECTED: Device does not belong to this student", sid
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		logEvent(db, "INVALID_MAC", sid, r.SessionID, "server key corrupt")
		return 500, "INVALID_MAC", "Server key error", sid
	}
	// STEPS 7-9: canonical + HMAC + constant-time compare. BEFORE trusting any field.
	canonical := CanonicalMessage(t.SID, t.DID, t.Ctr, t.Ts, t.Nonce)
	if !VerifyMAC(key, canonical, strings.ToLower(t.Mac)) {
		logEvent(db, "INVALID_MAC", sid, r.SessionID, "HMAC mismatch (tampered or forged)")
		return 403, "INVALID_MAC", "REJECTED: Cryptographic verification failed (INVALID_MAC — tampered or forged)", sid
	}
	// STEP 10: timestamp vs SERVER time. Client clock is never trusted.
	now := time.Now().Unix()
	if t.Ts > now+futureSkewSec {
		logEvent(db, "FUTURE_TOKEN", sid, r.SessionID, "token from the future")
		return 403, "FUTURE_TOKEN", "REJECTED: Token from the future (clock skew / forgery)", sid
	}
	if now-t.Ts > tokenValiditySec {
		logEvent(db, "STALE_TOKEN", sid, r.SessionID, "token too old")
		return 403, "STALE_TOKEN", "REJECTED: Stale token (expired — QR rotates every 15s, valid 60s)", sid
	}
	// STEP 11: monotonic counter. ts=freshness, ctr=ordering: an old-but-unexpired
	// token (replayed within 60s) still fails here because its ctr <= last seen.
	if t.Ctr <= lastCtr {
		logEvent(db, "REPLAY_COUNTER", sid, r.SessionID, "stale counter")
		return 409, "REPLAY_COUNTER", "REJECTED: Replay detected (stale counter)", sid
	}
	// STEP 12: nonce once-only (atomic backstop via UNIQUE).
	var nonceUsed bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM nonces WHERE nonce=?)`, t.Nonce).Scan(&nonceUsed); err == nil && nonceUsed {
		logEvent(db, "REPLAY_NONCE", sid, r.SessionID, "nonce already used")
		return 409, "REPLAY_NONCE", "REJECTED: Replay detected (nonce already used — screenshot replay blocked)", sid
	}
	// STEP 13: one attendance per (student, session).
	var dup bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM attendance WHERE sid=? AND session_id=?)`, t.SID, r.SessionID).Scan(&dup); err == nil && dup {
		logEvent(db, "DUPLICATE_ATTENDANCE", sid, r.SessionID, "already present")
		return 409, "DUPLICATE_ATTENDANCE", "REJECTED: Already marked present for this session", sid
	}
	// STEP 14: accept — single transaction so nonce/counter/attendance move together.
	tx, err := db.Begin()
	if err != nil {
		return 500, "ERROR", "Server busy, retry", sid
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO nonces(sid,nonce,used_at) VALUES(?,?,?)`, t.SID, t.Nonce, now); err != nil {
		_ = tx.Rollback()
		logEvent(db, "REPLAY_NONCE", sid, r.SessionID, "nonce race")
		return 409, "REPLAY_NONCE", "REJECTED: Replay detected (nonce already used)", sid
	}
	if _, err := tx.Exec(`INSERT INTO attendance(sid,session_id,scanned_at,counter,nonce) VALUES(?,?,?,?,?)`, t.SID, r.SessionID, now, t.Ctr, t.Nonce); err != nil {
		_ = tx.Rollback()
		logEvent(db, "DUPLICATE_ATTENDANCE", sid, r.SessionID, "attendance race")
		return 409, "DUPLICATE_ATTENDANCE", "REJECTED: Already marked present for this session", sid
	}
	if _, err := tx.Exec(`UPDATE devices SET last_seen_counter=? WHERE did=?`, t.Ctr, t.DID); err != nil {
		return 500, "ERROR", "Server busy, retry", sid
	}
	t0 := time.Now()
	_ = t0
	if err := tx.Commit(); err != nil {
		return 500, "ERROR", "Server busy, retry", sid
	}
	logEvent(db, "ACCEPTED", sid, r.SessionID, "marked present")
	return 200, "ACCEPTED", "ACCEPTED", sid
}

func handleEnroll(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var in struct {
		SID  string `json:"sid"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad JSON"})
		return
	}
	in.SID = strings.TrimSpace(in.SID)
	in.Name = strings.TrimSpace(in.Name)
	if in.SID == "" || in.Name == "" {
		writeJSON(w, 400, map[string]any{"error": "sid and name required"})
		return
	}
	// Per-device secret: 32 cryptographically random bytes. Server stores it,
	// device stores it (prototype: browser localStorage — NOT hardware-backed).
	raw := make([]byte, 32)
	if _, err := randRead(raw); err != nil {
		writeJSON(w, 500, map[string]any{"error": "RNG failure"})
		return
	}
	keyHex := hex.EncodeToString(raw)
	did, _ := RandomHex(2) // 2 bytes -> 4 hex chars like "d7f3"
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO students(sid,name,created_at) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET name=excluded.name`, in.SID, in.Name, now); err != nil {
		writeJSON(w, 500, map[string]any{"error": "db error"})
		return
	}
	// One device per enroll call; re-enroll creates a fresh device (old stays unless revoked).
	if _, err := db.Exec(`INSERT INTO devices(did,sid,secret_key,created_at) VALUES(?,?,?,?)`, did, in.SID, keyHex, now); err != nil {
		writeJSON(w, 500, map[string]any{"error": "db error: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"sid": in.SID, "name": in.Name, "did": did,
		"secret_key": keyHex, // returned ONCE; client stores locally
		"key_fp":     KeyFingerprint(raw),
	})
}

func handleStaffLogin(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	ip := clientIP(r)
	if !loginAllowed(ip) {
		logEvent(db, "INVALID_STAFF", "", "", "rate-limited login from "+ip)
		writeJSON(w, 429, map[string]any{"ok": false, "error": "too many attempts, try again in a minute"})
		return
	}
	var in struct {
		StaffID  string `json:"staff_id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad JSON"})
		return
	}
	var want string
	if err := db.QueryRow(`SELECT password_hash FROM staff WHERE staff_id=?`, strings.TrimSpace(in.StaffID)).Scan(&want); err != nil {
		loginFailed(ip)
		logEvent(db, "INVALID_STAFF", "", "", "bad staff_id")
		writeJSON(w, 401, map[string]any{"ok": false, "error": "invalid credentials"})
		return
	}
	ok, migrate := checkPassword(want, in.Password)
	if !ok {
		loginFailed(ip)
		logEvent(db, "INVALID_STAFF", "", "", "bad password")
		writeJSON(w, 401, map[string]any{"ok": false, "error": "invalid credentials"})
		return
	}
	if migrate {
		// Transparent upgrade: old SHA-256 hash -> bcrypt on successful login.
		if h, err := hashPassword(in.Password); err == nil {
			_, _ = db.Exec(`UPDATE staff SET password_hash=? WHERE staff_id=?`, h, strings.TrimSpace(in.StaffID))
		}
	}
	loginOK(ip)
	tok, _ := RandomHex(32)
	now := time.Now().Unix()
	_, _ = db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?)`,
		tok, strings.TrimSpace(in.StaffID), "staff-device-04", now, now+8*3600)
	writeJSON(w, 200, map[string]any{"ok": true, "staff_session_token": tok, "staff_id": strings.TrimSpace(in.StaffID), "device_id": "staff-device-04", "expires_in": 8 * 3600})
}

func handleStaffLogout(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var in struct {
		Staff string `json:"staff_session_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.Staff == "" {
		in.Staff = r.URL.Query().Get("staff_session_token")
	}
	_, _ = db.Exec(`DELETE FROM staff_sessions WHERE token=?`, in.Staff)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func handleStaffMe(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("staff_session_token")
	staffID, devID, ok := staffOf(db, tok)
	if !ok {
		writeJSON(w, 401, map[string]any{"ok": false})
		return
	}
	var exp int64
	_ = db.QueryRow(`SELECT expires_at FROM staff_sessions WHERE token=?`, tok).Scan(&exp)
	writeJSON(w, 200, map[string]any{"ok": true, "staff_id": staffID, "device_id": devID, "expires_at": exp})
}

// handleAdminReset wipes demo attendance data (staff-only) so each demo run
// starts clean. Students, devices, keys and sessions are kept.
func handleAdminReset(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var in struct {
		Staff string `json:"staff_session_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if _, _, ok := staffOf(db, in.Staff); !ok {
		writeJSON(w, 401, map[string]any{"error": "staff login required"})
		return
	}
	var a, n, e int64
	ra, _ := db.Exec(`DELETE FROM attendance`)
	rn, _ := db.Exec(`DELETE FROM nonces`)
	re, _ := db.Exec(`DELETE FROM security_events`)
	_, _ = db.Exec(`UPDATE devices SET last_seen_counter=0`)
	if ra != nil {
		a, _ = ra.RowsAffected()
	}
	if rn != nil {
		n, _ = rn.RowsAffected()
	}
	if re != nil {
		e, _ = re.RowsAffected()
	}
	logEvent(db, "RESET", "", "", "demo data reset")
	writeJSON(w, 200, map[string]any{"ok": true, "cleared": map[string]int64{"attendance": a, "nonces": n, "events": e}})
}

func handleSessionOpen(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var in struct {
		Course string `json:"course"`
		Room   string `json:"room"`
		Start  string `json:"start"`
		End    string `json:"end"`
		Staff  string `json:"staff_session_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad JSON"})
		return
	}
	staffID, devID, ok := staffOf(db, in.Staff)
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "staff login required"})
		return
	}
	if in.Course == "" || in.Room == "" {
		writeJSON(w, 400, map[string]any{"error": "course and room required"})
		return
	}
	sid, _ := RandomHex(2)
	sessionID := "S-" + strings.ToUpper(sid)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO attendance_sessions(session_id,course,room,staff_id,staff_device_id,start_time,end_time,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		sessionID, in.Course, in.Room, staffID, devID, in.Start, in.End, "OPEN", now); err != nil {
		writeJSON(w, 500, map[string]any{"error": "db error"})
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sessionID, "status": "OPEN"})
}

func handleSessionClose(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionID string `json:"session_id"`
		Staff     string `json:"staff_session_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if _, _, ok := staffOf(db, in.Staff); !ok {
		writeJSON(w, 401, map[string]any{"error": "staff login required"})
		return
	}
	_, _ = db.Exec(`UPDATE attendance_sessions SET status='CLOSED' WHERE session_id=?`, in.SessionID)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func handleScan(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "POST only"})
		return
	}
	var in ScanReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]any{"success": false, "status": "ERROR", "message": "bad JSON"})
		return
	}
	t0 := time.Now()
	code, status, msg, sid := verifyScan(db, in)
	writeJSON(w, code, map[string]any{
		"success": status == "ACCEPTED", "status": status,
		"message": msg, "student": sid, "session": in.SessionID,
		"latency_ms": time.Since(t0).Milliseconds(),
	})
}

func handleDashboard(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		// latest open session
		_ = db.QueryRow(`SELECT session_id FROM attendance_sessions WHERE status='OPEN' ORDER BY id DESC LIMIT 1`).Scan(&sessionID)
	}
	var course, room, status string
	if sessionID != "" {
		_ = db.QueryRow(`SELECT course, room, status FROM attendance_sessions WHERE session_id=?`, sessionID).Scan(&course, &room, &status)
	}
	var present, expected int
	_ = db.QueryRow(`SELECT COUNT(*) FROM attendance WHERE session_id=?`, sessionID).Scan(&present)
	_ = db.QueryRow(`SELECT COUNT(*) FROM students`).Scan(&expected)
	count := func(t string) int {
		var n int
		if sessionID == "" {
			_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type=?`, t).Scan(&n)
		} else {
			_ = db.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type=? AND (session_id=? OR session_id IS NULL)`, t, sessionID).Scan(&n)
		}
		return n
	}
	rows, _ := db.Query(`SELECT event_type, sid, session_id, details, created_at FROM security_events ORDER BY id DESC LIMIT 30`)
	feed := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var et string
			var sid, sess, det sql.NullString
			var ts int64
			_ = rows.Scan(&et, &sid, &sess, &det, &ts)
			feed = append(feed, map[string]any{"type": et, "sid": sid.String, "session": sess.String, "details": det.String, "at": ts})
		}
	}
	attRows, _ := db.Query(`SELECT sid, scanned_at, counter FROM attendance WHERE session_id=? ORDER BY scanned_at DESC LIMIT 100`, sessionID)
	att := []map[string]any{}
	if attRows != nil {
		defer attRows.Close()
		for attRows.Next() {
			var s string
			var ts, c int64
			_ = attRows.Scan(&s, &ts, &c)
			att = append(att, map[string]any{"sid": s, "at": ts, "ctr": c})
		}
	}
	writeJSON(w, 200, map[string]any{
		"session": sessionID, "course": course, "room": room, "status": status,
		"present": present, "expected": expected, "pending": max0(expected - present),
		"replays":        count("REPLAY_NONCE") + count("REPLAY_COUNTER"),
		"tampering":      count("INVALID_MAC"),
		"invalidDevices": count("UNKNOWN_DEVICE") + count("UNKNOWN_STUDENT"),
		"unauth":         count("INVALID_STAFF"),
		"feed":           feed, "attendance": att,
	})
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// ---- login hardening: per-IP attempt limiting (10 fails / 5 min -> 60s block) ----

var loginRL = struct {
	sync.Mutex
	m map[string]*rlEntry
}{m: map[string]*rlEntry{}}

type rlEntry struct {
	fails        int
	windowStart  time.Time
	blockedUntil time.Time
}

func clientIP(r *http.Request) string {
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

func loginAllowed(ip string) bool {
	loginRL.Lock()
	defer loginRL.Unlock()
	e, ok := loginRL.m[ip]
	if !ok {
		return true
	}
	now := time.Now()
	if now.Before(e.blockedUntil) {
		return false
	}
	if now.Sub(e.windowStart) > 5*time.Minute {
		delete(loginRL.m, ip)
	}
	return true
}

func loginFailed(ip string) {
	loginRL.Lock()
	defer loginRL.Unlock()
	now := time.Now()
	e, ok := loginRL.m[ip]
	if !ok || now.Sub(e.windowStart) > 5*time.Minute {
		e = &rlEntry{windowStart: now}
		loginRL.m[ip] = e
	}
	e.fails++
	if e.fails >= 10 {
		e.blockedUntil = now.Add(time.Minute)
	}
}

func loginOK(ip string) {
	loginRL.Lock()
	defer loginRL.Unlock()
	delete(loginRL.m, ip)
}
