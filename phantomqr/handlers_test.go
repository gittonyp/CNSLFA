package main

// Spec §36: valid, bad MAC, expired, future, stale counter,
// duplicate nonce, duplicate attendance, unknown student/device,
// invalid staff, closed session, second student, concurrent duplicate.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fix struct {
	db       *sql.DB
	staffTok string
	sess     string
	keyA     []byte
	keyB     []byte
}

func setupFix(t *testing.T) (*fix, func()) {
	t.Helper()
	f, _ := os.CreateTemp("", "pq-test-*.db")
	f.Close()
	path := f.Name()
	os.Remove(path)
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	staffTok := "stafftok-test-123"
	_, err = db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?)`,
		staffTok, "ST04", "staff-device-04", now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO attendance_sessions(session_id,course,room,staff_id,staff_device_id,start_time,end_time,status,created_at)
		VALUES('S-T1','CNS-601','A-204','ST04','staff-device-04','10:00','10:10','OPEN',?)`, now)
	if err != nil {
		t.Fatal(err)
	}
	mkStudent := func(sid, did string) []byte {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		_, err := db.Exec(`INSERT INTO students(sid,name,created_at) VALUES(?,?,?)`, sid, "N-"+sid, now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`INSERT INTO devices(did,sid,secret_key,created_at) VALUES(?,?,?,?)`, did, sid, hex.EncodeToString(k), now)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	keyA := mkStudent("21BT0451", "d7f3")
	keyB := mkStudent("21BT0452", "a1b2")
	return &fix{db, staffTok, "S-T1", keyA, keyB}, func() { db.Close(); os.Remove(path) }
}

// testNonce maps readable placeholders to deterministic hex (wire format).
// Fixtures use placeholders ("n-valid-…"); prod validation stays strict.
func testNonce(s string) string {
	if isHex(s) {
		return s
	}
	h := sha256.Sum256([]byte("test-nonce:" + s))
	return hex.EncodeToString(h[:])[:32]
}

func tok(key []byte, sid, did string, ctr, ts int64, nonce string) Token {
	nonce = testNonce(nonce)
	return Token{sid, did, ctr, ts, nonce, ComputeMAC(key, CanonicalMessage(sid, did, ctr, ts, nonce))}
}

func scan(f *fix, tk Token, staffTok, sess string) (int, string) {
	if staffTok == "" {
		staffTok = f.staffTok
	}
	if sess == "" {
		sess = f.sess
	}
	code, status, _, _ := verifyScan(f.db, ScanReq{Token: tk, SessionID: sess, StaffSessionTok: staffTok})
	return code, status
}

func TestValidToken(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	code, st := scan(f, tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-valid-0000000000000001"), "", "")
	if code != 200 || st != "ACCEPTED" {
		t.Fatalf("got %d %s", code, st)
	}
}

func TestInvalidHMAC(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	bad := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-badmac-00000000000001")
	bad.Mac = "00" + bad.Mac[2:]
	if _, st := scan(f, bad, "", ""); st != "INVALID_MAC" {
		t.Fatalf("got %s", st)
	}
	// tampered ctr, old mac (sid/did stay known -> reaches MAC check)
	good := tok(f.keyA, "21BT0451", "d7f3", 2, time.Now().Unix(), "n-badmac-00000000000002")
	good.Ctr = 99
	if _, st := scan(f, good, "", ""); st != "INVALID_MAC" {
		t.Fatalf("tamper got %s", st)
	}
}

func TestExpiredAndFuture(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	old := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix()-120, "n-exp-0000000000000001")
	if _, st := scan(f, old, "", ""); st != "STALE_TOKEN" {
		t.Fatalf("expired got %s", st)
	}
	fut := tok(f.keyA, "21BT0451", "d7f3", 2, time.Now().Unix()+600, "n-fut-0000000000000001")
	if _, st := scan(f, fut, "", ""); st != "FUTURE_TOKEN" {
		t.Fatalf("future got %s", st)
	}
}

func TestStaleCounterAndDuplicateNonce(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	first := tok(f.keyA, "21BT0451", "d7f3", 5, time.Now().Unix(), "n-c1-00000000000000001")
	if _, st := scan(f, first, "", ""); st != "ACCEPTED" {
		t.Fatalf("first got %s", st)
	}
	// same token again -> counter stale (ctr 5 <= last 5). Either REPLAY_* is a block.
	if _, st := scan(f, first, "", ""); st != "REPLAY_COUNTER" && st != "REPLAY_NONCE" && st != "DUPLICATE_ATTENDANCE" {
		t.Fatalf("replay got %s", st)
	}
	// lower counter, fresh nonce -> REPLAY_COUNTER
	lower := tok(f.keyA, "21BT0451", "d7f3", 3, time.Now().Unix(), "n-c2-fresh-nonce-000001")
	// need a fresh student to avoid DUPLICATE masking? student A already present, so use new session:
	_, err := f.db.Exec(`INSERT INTO attendance_sessions(session_id,course,room,staff_id,staff_device_id,start_time,end_time,status,created_at)
		VALUES('S-T2','CNS-601','A-204','ST04','staff-device-04','11:00','11:10','OPEN',?)`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, st := scan(f, lower, "", "S-T2"); st != "REPLAY_COUNTER" {
		t.Fatalf("stale counter got %s", st)
	}
}

func TestDuplicateAttendance(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	a := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-d1-00000000000000001")
	if _, st := scan(f, a, "", ""); st != "ACCEPTED" {
		t.Fatalf("first %s", st)
	}
	b := tok(f.keyA, "21BT0451", "d7f3", 2, time.Now().Unix(), "n-d1-00000000000000002")
	if _, st := scan(f, b, "", ""); st != "DUPLICATE_ATTENDANCE" {
		t.Fatalf("dup got %s", st)
	}
}

func TestUnknownStudentDevice(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	ghost := Token{"NOPE", "d7f3", 1, time.Now().Unix(), testNonce("n-u1-0000000000000001"), "ab"}
	if _, st := scan(f, ghost, "", ""); st != "UNKNOWN_STUDENT" {
		t.Fatalf("unknown student %s", st)
	}
	baddev := Token{"21BT0451", "zzzz", 1, time.Now().Unix(), testNonce("n-u2-0000000000000001"), "ab"}
	if _, st := scan(f, baddev, "", ""); st != "UNKNOWN_DEVICE" {
		t.Fatalf("unknown device %s", st)
	}
}

func TestInvalidStaffAndClosedSession(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	good := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-s1-00000000000000001")
	if _, st := scan(f, good, "bogus-token", ""); st != "INVALID_STAFF" {
		t.Fatalf("staff %s", st)
	}
	_, _ = f.db.Exec(`UPDATE attendance_sessions SET status='CLOSED' WHERE session_id=?`, f.sess)
	good2 := tok(f.keyA, "21BT0451", "d7f3", 2, time.Now().Unix(), "n-s1-00000000000000002")
	if _, st := scan(f, good2, "", ""); st != "INVALID_SESSION" {
		t.Fatalf("closed %s", st)
	}
	// unknown session
	good3 := tok(f.keyA, "21BT0451", "d7f3", 3, time.Now().Unix(), "n-s1-00000000000000003")
	if _, st := scan(f, good3, "", "S-NOPE"); st != "INVALID_SESSION" {
		t.Fatalf("nosession %s", st)
	}
}

func TestSecondStudentAndConcurrentDuplicate(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	a := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-m1-00000000000000001")
	b := tok(f.keyB, "21BT0452", "a1b2", 1, time.Now().Unix(), "n-m1-00000000000000002")
	if _, st := scan(f, a, "", ""); st != "ACCEPTED" {
		t.Fatalf("A %s", st)
	}
	if _, st := scan(f, b, "", ""); st != "ACCEPTED" {
		t.Fatalf("B %s", st)
	}
	// concurrent: same student, two fresh tokens, same session S-T3
	_, err := f.db.Exec(`INSERT INTO attendance_sessions(session_id,course,room,staff_id,staff_device_id,start_time,end_time,status,created_at)
		VALUES('S-T3','CNS-601','A-204','ST04','staff-device-04','12:00','12:10','OPEN',?)`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	t1 := tok(f.keyB, "21BT0452", "a1b2", 2, now, "n-race-0000000000000001")
	t2 := tok(f.keyB, "21BT0452", "a1b2", 3, now, "n-race-0000000000000002")
	var wg sync.WaitGroup
	res := make([]string, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, res[0] = scan(f, t1, "", "S-T3") }()
	go func() { defer wg.Done(); _, res[1] = scan(f, t2, "", "S-T3") }()
	wg.Wait()
	var n int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM attendance WHERE sid='21BT0452' AND session_id='S-T3'`).Scan(&n)
	if n != 1 {
		t.Fatalf("concurrent attendance rows=%d results=%v", n, res)
	}
}

func TestRBAC(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	now := time.Now().Unix()
	_, err := f.db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES('admintok-1','ADMIN','admin-dev',?,?)`, now, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	call := func(tok string) (int, string) {
		body := `{"staff_session_token":"` + tok + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/admin/reset", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handleAdminReset(f.db, rec, req)
		var j map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &j)
		return rec.Code, string(rec.Body.Bytes())
	}
	// staff must NOT reset
	if code, b := call(f.staffTok); code != 403 || !strings.Contains(b, "FORBIDDEN") {
		t.Fatalf("staff reset: got %d %s", code, b)
	}
	// anonymous must NOT reset
	if code, _ := call(""); code != 401 {
		t.Fatalf("anon reset: got %d", code)
	}
	// admin CAN reset
	if code, b := call("admintok-1"); code != 200 || !strings.Contains(b, `"ok":true`) {
		t.Fatalf("admin reset: got %d %s", code, b)
	}
	// admin CAN scan
	a := tok(f.keyA, "21BT0451", "d7f3", 1, time.Now().Unix(), "n-rbac-0000000000000001")
	if _, st := scan(f, a, "admintok-1", ""); st != "ACCEPTED" {
		t.Fatalf("admin scan: got %s", st)
	}
	// me reports roles
	for tok, want := range map[string]string{f.staffTok: "staff", "admintok-1": "admin"} {
		req := httptest.NewRequest(http.MethodGet, "/api/staff/me?staff_session_token="+tok, nil)
		rec := httptest.NewRecorder()
		handleStaffMe(f.db, rec, req)
		if !strings.Contains(rec.Body.String(), `"role":"`+want+`"`) {
			t.Fatalf("me(%s): %s", want, rec.Body.String())
		}
	}
}

func postJSON(db *sql.DB, h func(*sql.DB, http.ResponseWriter, *http.Request), body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(db, rec, req)
	return rec.Code, rec.Body.String()
}

func TestBusinessFixes(t *testing.T) {
	f, done := setupFix(t)
	defer done()
	now := time.Now().Unix()
	_, _ = f.db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES('admintok-2','ADMIN','dev',?,?)`, now, now+3600)

	// 1. malformed shapes rejected before crypto
	bad := tok(f.keyA, "21BT0451", "d7f3", 0, now, "zzzz-not-hex")
	if _, st := scan(f, bad, "", ""); st != "MALFORMED" {
		t.Fatalf("ctr0/nonce: got %s", st)
	}

	// 2. re-enroll revokes the old device key
	code, b1 := postJSON(f.db, handleEnroll, `{"sid":"21BT0999","name":"Re"}`)
	if code != 200 {
		t.Fatalf("enroll1: %d %s", code, b1)
	}
	var e1 map[string]any
	_ = json.Unmarshal([]byte(b1), &e1)
	code, b2 := postJSON(f.db, handleEnroll, `{"sid":"21bt0999","name":"Re"}`) // lowercase ok: normalized
	if code != 200 {
		t.Fatalf("enroll2: %d %s", code, b2)
	}
	var e2 map[string]any
	_ = json.Unmarshal([]byte(b2), &e2)
	if e1["did"] == e2["did"] {
		t.Fatalf("re-enroll must issue a fresh device")
	}
	oldKey, _ := hex.DecodeString(e1["secret_key"].(string))
	stale := tok(oldKey, "21BT0999", e1["did"].(string), 1, now, testNonce("reenroll-old"))
	if _, st := scan(f, stale, "", ""); st != "UNKNOWN_DEVICE" {
		t.Fatalf("old device after re-enroll: got %s (want UNKNOWN_DEVICE)", st)
	}

	// 3. admin revoke kills a live device; staff cannot revoke
	code, _ = postJSON(f.db, handleAdminRevoke, `{"staff_session_token":"`+f.staffTok+`","did":"`+e2["did"].(string)+`"}`)
	if code != 403 {
		t.Fatalf("staff revoke: got %d (want 403)", code)
	}
	code, rb := postJSON(f.db, handleAdminRevoke, `{"staff_session_token":"admintok-2","did":"`+e2["did"].(string)+`"}`)
	if code != 200 || !strings.Contains(rb, `"ok":true`) {
		t.Fatalf("admin revoke: %d %s", code, rb)
	}
	newKey, _ := hex.DecodeString(e2["secret_key"].(string))
	dead := tok(newKey, "21BT0999", e2["did"].(string), 2, now, testNonce("reenroll-new"))
	if _, st := scan(f, dead, "", ""); st != "UNKNOWN_DEVICE" {
		t.Fatalf("revoked device: got %s", st)
	}

	// 4. password change: wrong old fails, right old works, old sessions die
	code, _ = postJSON(f.db, handleStaffPassword, `{"staff_session_token":"`+f.staffTok+`","old_password":"nope","new_password":"newpass123"}`)
	if code != 401 {
		t.Fatalf("bad old pw: got %d", code)
	}
	code, _ = postJSON(f.db, handleStaffPassword, `{"staff_session_token":"`+f.staffTok+`","old_password":"demo123","new_password":"short"}`)
	if code != 400 {
		t.Fatalf("short pw: got %d", code)
	}
	// second session for ST04, then change pw from the first: second must die
	_, _ = f.db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES('other-sess','ST04','dev',?,?)`, now, now+3600)
	code, _ = postJSON(f.db, handleStaffPassword, `{"staff_session_token":"`+f.staffTok+`","old_password":"demo123","new_password":"newpass123"}`)
	if code != 200 {
		t.Fatalf("pw change: got %d", code)
	}
	var alive bool
	_ = f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM staff_sessions WHERE token='other-sess')`).Scan(&alive)
	if alive {
		t.Fatalf("other sessions must die on password change")
	}
	_ = f.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM staff_sessions WHERE token=?)`, f.staffTok).Scan(&alive)
	if !alive {
		t.Fatalf("changing session must survive")
	}

	// 5. close ownership: another staffer cannot close; admin can
	_, _ = f.db.Exec(`INSERT INTO staff(staff_id,name,password_hash,role) VALUES('ST09','Other','x','staff')`)
	_, _ = f.db.Exec(`INSERT INTO staff_sessions(token,staff_id,device_id,created_at,expires_at) VALUES('st09tok','ST09','dev',?,?)`, now, now+3600)
	code, _ = postJSON(f.db, handleSessionClose, `{"session_id":"`+f.sess+`","staff_session_token":"st09tok"}`)
	if code != 403 {
		t.Fatalf("foreign close: got %d (want 403)", code)
	}
	code, _ = postJSON(f.db, handleSessionClose, `{"session_id":"`+f.sess+`","staff_session_token":"admintok-2"}`)
	if code != 200 {
		t.Fatalf("admin close: got %d", code)
	}

	// 6. stale OPEN sessions expire (>12h)
	_, _ = f.db.Exec(`INSERT INTO attendance_sessions(session_id,course,room,staff_id,staff_device_id,start_time,end_time,status,created_at) VALUES('S-OLD','C','R','ST04','dev','x','y','OPEN',?)`, now-13*3600)
	old := tok(f.keyA, "21BT0451", "d7f3", 50, now, testNonce("stale-session"))
	if _, st := scan(f, old, "", "S-OLD"); st != "INVALID_SESSION" {
		t.Fatalf("stale session: got %s", st)
	}
}
