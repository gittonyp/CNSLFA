package main

// SQLite store. Pure-Go driver (modernc.org/sqlite) so no system sqlite3 needed.
// UNIQUE(nonce) and UNIQUE(sid, session_id) are enforced by the DB itself,
// so two scanners racing on the same student can only succeed once.

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sid TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT UNIQUE NOT NULL,
  sid TEXT NOT NULL,
  secret_key TEXT NOT NULL,
  last_seen_counter INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS staff(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  staff_id TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS staff_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  staff_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attendance_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT UNIQUE NOT NULL,
  course TEXT NOT NULL,
  room TEXT NOT NULL,
  staff_id TEXT NOT NULL,
  staff_device_id TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'OPEN',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sid TEXT NOT NULL,
  session_id TEXT NOT NULL,
  scanned_at INTEGER NOT NULL,
  counter INTEGER NOT NULL,
  nonce TEXT NOT NULL,
  UNIQUE(sid, session_id)
);
CREATE TABLE IF NOT EXISTS nonces(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sid TEXT NOT NULL,
  nonce TEXT NOT NULL,
  used_at INTEGER NOT NULL,
  UNIQUE(nonce)
);
CREATE TABLE IF NOT EXISTS security_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  sid TEXT,
  session_id TEXT,
  details TEXT,
  created_at INTEGER NOT NULL
);
`

func hashPassword(pw string) (string, error) {
	// bcrypt with per-password salt (cost 10). Production-grade for a demo;
	// argon2id would be the next step up. Never store reversible passwords.
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// legacyHash is the old prototype scheme (salted SHA-256). Kept ONLY so
// databases created before the bcrypt upgrade keep working: a successful
// legacy login transparently re-hashes to bcrypt (see handlers.go).
func legacyHash(pw string) string {
	h := sha256.Sum256([]byte("phantomqr-demo-salt::" + pw))
	return hex.EncodeToString(h[:])
}

// checkPassword accepts bcrypt hashes, plus legacy SHA-256 hex (migrate=true).
func checkPassword(stored, pw string) (ok, migrate bool) {
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)); err == nil {
		return true, false
	}
	if len(stored) == 64 && subtle.ConstantTimeCompare([]byte(stored), []byte(legacyHash(pw))) == 1 {
		return true, true
	}
	return false, false
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4) // small pool: WAL allows concurrent readers; busy_timeout covers writer contention.
	// Belt and suspenders for concurrent scanners: wait on locks, WAL mode.
	_, _ = db.Exec(`PRAGMA busy_timeout = 5000`)
	_, _ = db.Exec(`PRAGMA journal_mode = WAL`)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// ---- RBAC: staff.role in {'admin','staff'} (students are provers, not API callers) ----
	var hasRole int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('staff') WHERE name='role'`).Scan(&hasRole); err != nil {
		db.Close()
		return nil, err
	}
	if hasRole == 0 {
		// Existing rows backfill to 'staff' via the DEFAULT.
		if _, err := db.Exec(`ALTER TABLE staff ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'`); err != nil {
			db.Close()
			return nil, err
		}
	}
	seed := func(id, name, pw, role string) error {
		var c int
		if err := db.QueryRow(`SELECT COUNT(*) FROM staff WHERE staff_id=?`, id).Scan(&c); err != nil {
			return err
		}
		if c == 0 {
			h, err := hashPassword(pw)
			if err != nil {
				return err
			}
			_, err = db.Exec(`INSERT INTO staff(staff_id,name,password_hash,role) VALUES(?,?,?,?)`, id, name, h, role)
			return err
		}
		return nil
	}
	if err := seed("ST04", "Demo Professor", "demo123", "staff"); err != nil {
		db.Close()
		return nil, err
	}
	if err := seed("ADMIN", "Demo Admin", "admin123", "admin"); err != nil {
		db.Close()
		return nil, err
	}
	// Sessions always have a human name (never ID-only): migrate old rows.
	var hasSName int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('attendance_sessions') WHERE name='name'`).Scan(&hasSName); err != nil {
		db.Close()
		return nil, err
	}
	if hasSName == 0 {
		if _, err := db.Exec(`ALTER TABLE attendance_sessions ADD COLUMN name TEXT NOT NULL DEFAULT ''`); err != nil {
			db.Close()
			return nil, err
		}
		_, _ = db.Exec(`UPDATE attendance_sessions SET name=course||' · '||room WHERE name=''`)
	}
	return db, nil
}

func logEvent(db *sql.DB, typ, sid, session, details string) {
	_, _ = db.Exec(`INSERT INTO security_events(event_type,sid,session_id,details,created_at) VALUES(?,?,?,?,?)`,
		typ, nullable(sid), nullable(session), details, time.Now().Unix())
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
