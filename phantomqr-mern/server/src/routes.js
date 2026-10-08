// REST API — same contract as the Go prototype so flows transfer 1:1.
const express = require('express');
const bcrypt = require('bcryptjs');
const { randomHex, fingerprint } = require('./crypto');
const { verifyScan, requireRole, staffOf, log } = require('./verify');
const { Student, Device, Staff, StaffSession, Session, Attendance, Nonce, Event } = require('./models');

const router = express.Router();
const nowS = () => Math.floor(Date.now() / 1000);

// Per-IP login limiting that survives the tunnel: CF-Connecting-IP, else XFF, else socket.
const rl = new Map();
function clientIP(req) {
  const cf = (req.headers['cf-connecting-ip'] || '').trim();
  if (cf) return cf;
  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const first = String(xff).split(',')[0].trim();
    if (first) return first;
  }
  return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
function loginAllowed(ip) {
  const e = rl.get(ip);
  if (!e) return true;
  const now = Date.now();
  if (now < e.blockedUntil) return false;
  if (now - e.windowStart > 5 * 60 * 1000) rl.delete(ip);
  return true;
}
function loginFailed(ip) {
  const now = Date.now();
  let e = rl.get(ip);
  if (!e || now - e.windowStart > 5 * 60 * 1000) { e = { fails: 0, windowStart: now, blockedUntil: 0 }; rl.set(ip, e); }
  if (++e.fails >= 10) e.blockedUntil = now + 60 * 1000;
}
function loginOK(ip) { rl.delete(ip); }

router.get('/health', (req, res) => res.json({ ok: true }));

// ---- student enrollment (self-service kiosk; sid normalized uppercase) ----
router.post('/student/enroll', async (req, res) => {
  let { sid = '', name = '' } = req.body || {};
  sid = String(sid).trim().toUpperCase();
  name = String(name).trim();
  if (!sid || !name) return res.status(400).json({ error: 'sid and name required' });
  if (sid.length > 32 || name.length > 64) return res.status(400).json({ error: 'sid (max 32) or name (max 64) too long' });
  const keyHex = randomHex(32);
  const now = nowS();
  try {
    await Student.updateOne({ sid }, { $set: { name, createdAt: now } }, { upsert: true });
    // Re-enroll = new phone: revoke previous devices first.
    await Device.updateMany({ sid }, { $set: { active: false, revokedAt: now } });
    // 16-bit did with collision retry.
    let did = '';
    for (let i = 0; i < 5 && !did; i++) {
      const cand = randomHex(2);
      try {
        await Device.create({ did: cand, sid, secretKey: keyHex, createdAt: now });
        did = cand;
      } catch { /* collision → retry */ }
    }
    if (!did) return res.status(500).json({ error: 'could not allocate device id, retry' });
    res.json({ sid, name, did, secret_key: keyHex, key_fp: fingerprint(Buffer.from(keyHex, 'hex')) });
  } catch (e) {
    res.status(500).json({ error: 'db error' });
  }
});

// ---- staff auth (bcrypt) ----
router.post('/staff/login', async (req, res) => {
  const ip = clientIP(req);
  if (!loginAllowed(ip)) return res.status(429).json({ ok: false, error: 'too many attempts, try again in a minute' });
  const { staff_id = '', password = '' } = req.body || {};
  const st = await Staff.findOne({ staffId: String(staff_id).trim() }).lean();
  if (!st || !bcrypt.compareSync(String(password), st.passwordHash)) {
    loginFailed(ip);
    await log('INVALID_STAFF', '', '', !st ? 'bad staff_id' : 'bad password');
    return res.status(401).json({ ok: false, error: 'invalid credentials' });
  }
  loginOK(ip);
  const token = randomHex(32);
  const now = nowS();
  await StaffSession.create({ token, staffId: st.staffId, deviceId: 'staff-device-04', createdAt: now, expiresAt: now + 8 * 3600 });
  res.json({ ok: true, staff_session_token: token, staff_id: st.staffId, device_id: 'staff-device-04', role: st.role, expires_in: 8 * 3600 });
});

router.post('/staff/logout', async (req, res) => {
  const tok = (req.body && req.body.staff_session_token) || req.query.staff_session_token || '';
  await StaffSession.deleteOne({ token: tok });
  res.json({ ok: true });
});

router.get('/staff/me', async (req, res) => {
  const me = await staffOf(req.query.staff_session_token || '');
  if (!me) return res.status(401).json({ ok: false });
  const s = await StaffSession.findOne({ token: req.query.staff_session_token }).lean();
  res.json({ ok: true, staff_id: me.staffId, device_id: me.deviceId, role: me.role, expires_at: s.expiresAt });
});

router.post('/staff/password', async (req, res) => {
  const { staff_session_token = '', old_password = '', new_password = '' } = req.body || {};
  const gate = await requireRole(staff_session_token, '', 'staff', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  if (String(new_password).length < 6 || String(new_password).length > 72)
    return res.status(400).json({ error: 'new password must be 6-72 characters' });
  const st = await Staff.findOne({ staffId: gate.staff.staffId });
  if (!st || !bcrypt.compareSync(String(old_password), st.passwordHash)) {
    loginFailed(clientIP(req));
    return res.status(401).json({ ok: false, error: 'current password incorrect' });
  }
  st.passwordHash = bcrypt.hashSync(String(new_password), 10);
  await st.save();
  await StaffSession.deleteMany({ staffId: st.staffId, token: { $ne: staff_session_token } });
  await log('PASSWORD_CHANGED', '', '', 'staff=' + st.staffId);
  res.json({ ok: true });
});

// ---- sessions (name required, ID always server-generated) ----
router.post('/session/open', async (req, res) => {
  const { course = '', room = '', name = '', start = '', end = '', staff_session_token = '' } = req.body || {};
  const gate = await requireRole(staff_session_token, '', 'staff', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  if (!String(course).trim() || !String(room).trim()) return res.status(400).json({ error: 'course and room required' });
  const nm = String(name).trim();
  if (!nm) return res.status(400).json({ error: "session name required (e.g. 'CNS-601 · Morning')" });
  if (String(course).length > 64 || String(room).length > 64 || nm.length > 64)
    return res.status(400).json({ error: 'course/room/name too long' });
  let sessionId = '';
  for (let i = 0; i < 5 && !sessionId; i++) {
    const cand = 'S-' + randomHex(2).toUpperCase();
    try {
      await Session.create({
        sessionId: cand, name: nm, course: String(course), room: String(room),
        staffId: gate.staff.staffId, staffDeviceId: gate.staff.deviceId,
        start: String(start || ''), end: String(end || ''), status: 'OPEN', createdAt: nowS(),
      });
      sessionId = cand;
    } catch { /* collision → retry */ }
  }
  if (!sessionId) return res.status(500).json({ error: 'could not allocate session id, retry' });
  res.json({ session_id: sessionId, name: nm, status: 'OPEN' });
});

router.get('/sessions', async (req, res) => {
  const gate = await requireRole(req.query.staff_session_token || '', '', 'staff', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  const q = req.query.open === '1' ? { status: 'OPEN' } : {};
  const list = await Session.find(q).sort({ _id: -1 }).limit(50).lean();
  const out = [];
  for (const s of list) {
    out.push({
      session_id: s.sessionId, name: s.name, course: s.course, room: s.room,
      status: s.status, present: await Attendance.countDocuments({ sessionId: s.sessionId }),
    });
  }
  res.json({ sessions: out });
});

router.post('/session/close', async (req, res) => {
  const { session_id = '', staff_session_token = '' } = req.body || {};
  const gate = await requireRole(staff_session_token, session_id, 'staff', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  const sess = await Session.findOne({ sessionId: session_id }).lean();
  if (!sess) return res.status(404).json({ error: 'unknown session' });
  if (gate.staff.staffId !== sess.staffId && gate.staff.role !== 'admin') {
    await log('FORBIDDEN', '', session_id, 'close by non-owner ' + gate.staff.staffId);
    return res.status(403).json({ error: 'only the session owner or admin can close it', status: 'FORBIDDEN' });
  }
  await Session.updateOne({ sessionId: session_id }, { $set: { status: 'CLOSED' } });
  res.json({ ok: true });
});

// ---- attendance scan (the 14-step pipeline) ----
router.post('/attendance/scan', async (req, res) => {
  const t0 = Date.now();
  const { token, session_id = '', staff_session_token = '' } = req.body || {};
  const r = await verifyScan({ token, sessionId: session_id, staffToken: staff_session_token });
  res.status(r.code).json({
    success: r.status === 'ACCEPTED', status: r.status, message: r.message,
    student: r.sid, session: session_id, latency_ms: Date.now() - t0,
  });
});

// ---- dashboard ----
router.get('/dashboard', async (req, res) => {
  const sessionId = req.query.session_id || '';
  let sess = null;
  if (sessionId) sess = await Session.findOne({ sessionId }).lean();
  if (!sessionId) sess = await Session.findOne({ status: 'OPEN' }).sort({ _id: -1 }).lean();
  const id = sess ? sess.sessionId : sessionId;
  const present = id ? await Attendance.countDocuments({ sessionId: id }) : 0;
  const expected = await Student.countDocuments({});
  const count = (t) => id
    ? Event.countDocuments({ type: t, sessionId: id })
    : Event.countDocuments({ type: t });
  const [replayN, replayC, tamper, invDev, invStu, unauth] = await Promise.all([
    count('REPLAY_NONCE'), count('REPLAY_COUNTER'), count('INVALID_MAC'),
    count('UNKNOWN_DEVICE'), count('UNKNOWN_STUDENT'), count('INVALID_STAFF'),
  ]);
  const feed = (await Event.find(id ? { sessionId: id } : {}).sort({ _id: -1 }).limit(30).lean())
    .map((e) => ({ type: e.type, sid: e.sid || '', session: e.sessionId || '', details: e.details, at: e.at }));
  const attendance = id ? (await Attendance.find({ sessionId: id }).sort({ scannedAt: -1 }).limit(100).lean())
    .map((a) => ({ sid: a.sid, at: a.scannedAt, ctr: a.counter })) : [];
  res.json({
    session: id, name: sess ? sess.name : '', course: sess ? sess.course : '',
    room: sess ? sess.room : '', status: sess ? sess.status : '',
    present, expected, pending: Math.max(0, expected - present),
    replays: replayN + replayC, tampering: tamper,
    invalidDevices: invDev + invStu, unauth, feed, attendance,
  });
});

// ---- admin ----
router.post('/admin/reset', async (req, res) => {
  const gate = await requireRole((req.body || {}).staff_session_token || '', '', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  const a = await Attendance.deleteMany({});
  const n = await Nonce.deleteMany({});
  const e = await Event.deleteMany({});
  await Device.updateMany({}, { $set: { lastSeenCounter: 0 } });
  await log('RESET', '', '', 'demo data reset');
  res.json({ ok: true, cleared: { attendance: a.deletedCount, nonces: n.deletedCount, events: e.deletedCount } });
});

router.post('/admin/revoke', async (req, res) => {
  const { staff_session_token = '', did = '' } = req.body || {};
  const gate = await requireRole(staff_session_token, '', 'admin');
  if (gate.code) return res.status(gate.code).json({ error: gate.message, status: gate.status });
  if (!String(did).trim()) return res.status(400).json({ error: 'did required' });
  const r = await Device.updateOne({ did: String(did).trim(), active: true }, { $set: { active: false, revokedAt: nowS() } });
  if (!r.modifiedCount) return res.status(404).json({ error: 'unknown device or already revoked' });
  await log('DEVICE_REVOKED', '', '', 'did=' + did);
  res.json({ ok: true, did });
});

module.exports = router;
