# PhantomQR — Secure QR-Based Classroom Authentication

> "Possession of the QR is not possession of the identity."

**Direction flip:** the student does NOT scan the professor's QR.
The student phone *displays* a rotating HMAC-protected QR; the professor's
authenticated device *scans* it; the **server** verifies everything.
The professor's device is the only attendance writer — a student at home has
no API to call.

```
STUDENT (per-device key) ── signed QR {sid,did,ctr,ts,nonce,mac} ──▶
PROFESSOR SCANNER (dumb camera + staff session) ── POST /api/attendance/scan ──▶
SERVER (HMAC → session → ts → counter → nonce → uniqueness) ──▶ ACCEPTED / blocked
```

## 1. Problem / 2. Threat model

Class QR attendance fails because a valid QR can be screenshotted, WhatsApp-forwarded,
edited, replayed later, forged, or submitted remotely. Attacker model: classmates
cooperate, phones may be rooted, network untrusted, projector/paper QR visible to all.

| Threat | Control |
|---|---|
| Screenshot replay / old QR | 15s rotation, 60s server validity, once-only nonce, monotonic counter |
| Payload edit (sid/ctr/ts) | HMAC-SHA256 over canonical `sid\|did\|ctr\|ts\|nonce`, constant-time compare |
| Forged QR without key | Per-device 32-byte random key; server recomputes MAC |
| Double attendance | `UNIQUE(sid, session_id)` + duplicate check |
| Remote submission from home | Staff session token required; students never POST attendance |
| Stolen scanner | Scanner holds no keys (relay only); keys live on server + student device |
| Two scanners racing | `UNIQUE(nonce)`, `UNIQUE(sid,session)` + single transaction |

## 3. Architecture — why reversed

If the projector shows the QR and phones submit, anyone holding the image can submit
from anywhere (rotation only shrinks the window). Flipping it removes remote
submission *as a category*: there is no student-submit endpoint, only a
staff-authenticated scanner endpoint. The student token carries **no**
session/course/room — it only proves "enrolled device X, fresh moment". The scanner
supplies `session_id`.

## 4. HMAC-SHA256

`mac = hex(HMAC-SHA256(student_key, "sid|did|ctr|ts|nonce"))`.
Key: 32 random bytes per device at enrollment. Verification uses constant-time
comparison (`subtle.ConstantTimeCompare` server-side, `crypto.timingSafeEqual`
equivalent) so attackers can't learn the MAC byte-by-byte from timing.

## 5. Token format / 6. Timestamp / 7. Counter / 8. Nonce

```json
{"sid":"21BT0451","did":"d7f3","ctr":48,"ts":1791432000,"nonce":"9f2c…","mac":"…"}
```

- `ts` = freshness (server `now - ts <= 60s`; future `> now+10s` rejected; client clock never trusted).
- `ctr` = monotonic ordering (server requires `incoming > last_seen`; catches replays inside the 60s window).
- `nonce` = 16 random bytes, once-only (`UNIQUE(nonce)`).

## 9. Staff scanner auth / 10. Replay / 11. Tamper / 12. Offline queue

- Staff login `ST04 / demo123` → 8h session token; every scan needs it.
- Verify order: staff → session exists → OPEN → student/device lookup → binding →
  HMAC (constant-time) → timestamp → counter → nonce → uniqueness → accept in one tx.
- Scanner keeps `localStorage` queue (`{token, session_id, scanned_at}`) when offline,
  auto-uploads on reconnect. `scanned_at` is informational only — validity is always
  evaluated against **server time on arrival** (documented trust limit).

## Setup

```bash
cd phantomqr
go mod download
go build -o phantomqr .
./phantomqr -addr :8812 -db phantomqr.db -web web
# open http://localhost:8812
```

No system sqlite needed (pure-Go driver). No npm/build step (vanilla HTML + vendored `qrcode.min.js`, `jsQR.js`; camera lib via CDN with paste/upload fallback).

## URLs / credentials

| Page | URL |
|---|---|
| Landing | `/` |
| Student enroll | `/student/enroll` |
| Student QR | `/student` |
| Staff login | `/staff/login` (ST04 / demo123) |
| Session | `/staff/session` |
| Scanner | `/staff/scanner` |
| Dashboard | `/dashboard` |
| Security Lab | `/attacks` |

## Tests

```bash
go test ./... -v
```

Covers: valid, bad MAC, expired, future, stale counter, duplicate nonce,
duplicate attendance, unknown student/device, invalid staff, closed session,
second student, concurrent duplicate race.

## 2-minute demo script

1. `/student/enroll` → Priya `21BT0451` → enrolled (fingerprint shown).
2. `/staff/login` → ST04/demo123. `/staff/session` → CNS-601/A-204 → note `S-XXXX`.
3. `/student` → SHOW QR (rotates, counter climbs).
4. `/staff/scanner` → paste token JSON → ✓ ACCEPTED, 38ms.
5. Submit same token → REPLAY blocked. Edit `ctr` → INVALID_MAC. Clear staff token → INVALID_STAFF (remote blocked).
6. `/dashboard` → green acceptance + red blocks in live feed. `/attacks` → RUN all five.

## Limitations (honest)

1. Browser localStorage is not hardware-backed. Production: Android Keystore / iOS Keychain, non-exportable.
2. Phone handoff (give device to friend) is cryptographically invisible.
3. Live video relay of the screen still works inside the 60s window — needs physics (BLE/ultrasonic), listed as future work.
4. Offline-queue `scanned_at` is scanner-reported, not trusted.
5. HMAC = integrity/authentication, **no non-repudiation** (server knows the key too). Ed25519 + secure enclave is the upgrade path.
6. Payload is signed, not encrypted (opaque `did`/short sid preferred over real roll numbers).
7. Demo password hashing is salted SHA-256 (prototype); production needs bcrypt/argon2.

Future work: Ed25519 variant with measured µs table, BLE/ultrasonic proximity, Keystore-backed keys, stronger offline trust.
