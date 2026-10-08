// Server-side verification pipeline (STEPS 1-14, in order, fail-fast).
// The scanner is a dumb camera: all crypto + policy runs here.
const { canonical, verifyMac } = require('./crypto');
const { Student, Device, Staff, StaffSession, Session, Attendance, Nonce, Event } = require('./models');

const TOKEN_VALIDITY = 60; // seconds, server time
const FUTURE_SKEW = 10;
const SESSION_TTL = 12 * 3600;

async function log(type, sid, sessionId, details) {
  await Event.create({ type, sid: sid || null, sessionId: sessionId || null, details: details || '' }).catch(() => {});
}

async function staffOf(token) {
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const s = await StaffSession.findOne({ token, expiresAt: { $gt: now } }).lean();
  if (!s) return null;
  const st = await Staff.findOne({ staffId: s.staffId }).lean();
  if (!st) return null;
  return { staffId: s.staffId, deviceId: s.deviceId, role: st.role || 'staff' };
}

// Returns {code, status, message} — code 0 means permitted.
async function requireRole(token, sessionId, ...allowed) {
  const me = await staffOf(token);
  if (!me) {
    await log('INVALID_STAFF', '', sessionId, 'missing/expired staff session token');
    return { staff: null, code: 401, status: 'INVALID_STAFF', message: 'REMOTE SUBMISSION BLOCKED — Unauthorized scanner (staff login required)' };
  }
  if (!allowed.includes(me.role)) {
    await log('FORBIDDEN', '', sessionId, `role '${me.role}' not permitted`);
    return { staff: null, code: 403, status: 'FORBIDDEN', message: `REJECTED: Role '${me.role}' is not permitted here` };
  }
  return { staff: me, code: 0 };
}

async function verifyScan({ token: t, sessionId, staffToken }) {
  const sid = (t && t.sid) || '';
  // STEP 1: staff session + role.
  const gate = await requireRole(staffToken, sessionId, 'staff', 'admin');
  if (gate.code) return { code: gate.code, status: gate.status, message: gate.message, sid };

  // STEP 1b: shape validation (format only — MAC over these bytes comes next).
  const { isHex } = require('./crypto');
  if (!t || !t.sid || String(t.sid).length > 32 || !t.did || String(t.did).length > 16 ||
      !t.nonce || String(t.nonce).length > 64 || !t.mac || String(t.mac).length > 128 ||
      !(Number(t.ctr) > 0) || !isHex(t.nonce) || !isHex(t.mac)) {
    await log('MALFORMED', sid, sessionId, 'token shape invalid');
    return { code: 400, status: 'MALFORMED', message: 'REJECTED: malformed QR', sid };
  }
  const ctr = Number(t.ctr);

  // STEP 2/3: session exists, OPEN, fresh (12h auto-expiry).
  const sess = await Session.findOne({ sessionId }).lean();
  if (!sess) {
    await log('INVALID_SESSION', sid, sessionId, 'unknown session_id');
    return { code: 404, status: 'INVALID_SESSION', message: 'REJECTED: Invalid attendance session', sid };
  }
  if (sess.status !== 'OPEN') {
    await log('INVALID_SESSION', sid, sessionId, 'session status=' + sess.status);
    return { code: 409, status: 'INVALID_SESSION', message: 'REJECTED: Attendance session closed', sid };
  }
  const now = Math.floor(Date.now() / 1000);
  if (now - sess.createdAt > SESSION_TTL) {
    await log('INVALID_SESSION', sid, sessionId, 'session expired (>12h)');
    return { code: 409, status: 'INVALID_SESSION', message: 'REJECTED: Attendance session expired', sid };
  }

  // STEP 4-6: student + device exist, belong together, device active.
  const student = await Student.findOne({ sid: t.sid }).lean();
  if (!student) {
    await log('UNKNOWN_STUDENT', sid, sessionId, 'sid not enrolled');
    return { code: 404, status: 'UNKNOWN_STUDENT', message: 'REJECTED: Unknown student (not enrolled)', sid };
  }
  const dev = await Device.findOne({ did: t.did }).lean();
  if (!dev) {
    await log('UNKNOWN_DEVICE', sid, sessionId, 'did not enrolled: ' + t.did);
    return { code: 404, status: 'UNKNOWN_DEVICE', message: 'REJECTED: Unknown device', sid };
  }
  if (dev.sid !== t.sid || !dev.active) {
    await log('UNKNOWN_DEVICE', sid, sessionId, 'device/student mismatch or revoked');
    return { code: 403, status: 'UNKNOWN_DEVICE', message: 'REJECTED: Device does not belong to this student', sid };
  }

  // STEPS 7-9: HMAC over canonical bytes, constant-time. Nothing above was trusted.
  const key = Buffer.from(dev.secretKey, 'hex');
  if (!verifyMac(key, canonical(t.sid, t.did, ctr, t.ts, t.nonce), t.mac)) {
    await log('INVALID_MAC', sid, sessionId, 'HMAC mismatch (tampered or forged)');
    return { code: 403, status: 'INVALID_MAC', message: 'REJECTED: Cryptographic verification failed (INVALID_MAC — tampered or forged)', sid };
  }

  // STEP 10: freshness vs SERVER time (client clock never trusted).
  const ts = Number(t.ts);
  if (ts > now + FUTURE_SKEW) {
    await log('FUTURE_TOKEN', sid, sessionId, 'token from the future');
    return { code: 403, status: 'FUTURE_TOKEN', message: 'REJECTED: Token from the future (clock skew / forgery)', sid };
  }
  if (now - ts > TOKEN_VALIDITY) {
    await log('STALE_TOKEN', sid, sessionId, 'token too old');
    return { code: 403, status: 'STALE_TOKEN', message: 'REJECTED: Stale token (expired — QR rotates every 15s, valid 60s)', sid };
  }

  // STEP 11: monotonic counter (ts=freshness, ctr=ordering).
  if (ctr <= dev.lastSeenCounter) {
    await log('REPLAY_COUNTER', sid, sessionId, 'stale counter');
    return { code: 409, status: 'REPLAY_COUNTER', message: 'REJECTED: Replay detected (stale counter)', sid };
  }

  // STEP 12: nonce once-only.
  if (await Nonce.exists({ nonce: t.nonce })) {
    await log('REPLAY_NONCE', sid, sessionId, 'nonce already used');
    return { code: 409, status: 'REPLAY_NONCE', message: 'REJECTED: Replay detected (nonce already used — screenshot replay blocked)', sid };
  }

  // STEP 13: one attendance per (student, session).
  if (await Attendance.exists({ sid: t.sid, sessionId })) {
    await log('DUPLICATE_ATTENDANCE', sid, sessionId, 'already present');
    return { code: 409, status: 'DUPLICATE_ATTENDANCE', message: 'REJECTED: Already marked present for this session', sid };
  }

  // STEP 14: accept. Unique indexes are the atomic backstop: concurrent
  // duplicates fail here with 11000 and map to the same verdicts as the checks.
  try {
    await Nonce.create({ sid: t.sid, nonce: t.nonce, usedAt: now });
  } catch {
    await log('REPLAY_NONCE', sid, sessionId, 'nonce race');
    return { code: 409, status: 'REPLAY_NONCE', message: 'REJECTED: Replay detected (nonce already used)', sid };
  }
  try {
    await Attendance.create({ sid: t.sid, sessionId, scannedAt: now, counter: ctr, nonce: t.nonce });
  } catch {
    await Nonce.deleteOne({ nonce: t.nonce }).catch(() => {});
    await log('DUPLICATE_ATTENDANCE', sid, sessionId, 'attendance race');
    return { code: 409, status: 'DUPLICATE_ATTENDANCE', message: 'REJECTED: Already marked present for this session', sid };
  }
  await Device.updateOne({ did: t.did }, { $set: { lastSeenCounter: ctr } });
  await log('ACCEPTED', sid, sessionId, 'marked present');
  return { code: 200, status: 'ACCEPTED', message: 'ACCEPTED', sid };
}

module.exports = { verifyScan, requireRole, staffOf, log };
