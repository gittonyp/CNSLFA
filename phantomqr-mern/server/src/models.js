// Mongo models. Uniqueness is enforced by the DB itself (correct verdicts
// under racing scanners, no transactions needed on standalone mongod):
// unique nonce, compound unique (sid, session_id), unique device/session tokens.
const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
  sid: { type: String, required: true, unique: true, uppercase: true, trim: true, maxlength: 32 },
  name: { type: String, required: true, maxlength: 64 },
  createdAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
});

const deviceSchema = new mongoose.Schema({
  did: { type: String, required: true, unique: true },
  sid: { type: String, required: true, index: true },
  secretKey: { type: String, required: true }, // hex of 32 random bytes
  lastSeenCounter: { type: Number, default: 0 },
  active: { type: Boolean, default: true },
  createdAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
  revokedAt: { type: Number, default: null },
});

const staffSchema = new mongoose.Schema({
  staffId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['staff', 'admin'], default: 'staff' },
});

const staffSessionSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  staffId: { type: String, required: true },
  deviceId: { type: String, default: 'staff-device-04' },
  createdAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
  expiresAt: { type: Number, required: true },
});

const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  name: { type: String, required: true, maxlength: 64 },
  course: { type: String, required: true, maxlength: 64 },
  room: { type: String, required: true, maxlength: 64 },
  staffId: { type: String, required: true },
  staffDeviceId: { type: String, default: '' },
  start: { type: String, default: '' },
  end: { type: String, default: '' },
  status: { type: String, enum: ['OPEN', 'CLOSED'], default: 'OPEN' },
  createdAt: { type: Number, default: () => Math.floor(Date.now() / 1000) },
});

const attendanceSchema = new mongoose.Schema({
  sid: { type: String, required: true },
  sessionId: { type: String, required: true },
  scannedAt: { type: Number, required: true },
  counter: { type: Number, required: true },
  nonce: { type: String, required: true },
});
attendanceSchema.index({ sid: 1, sessionId: 1 }, { unique: true });

const nonceSchema = new mongoose.Schema({
  sid: { type: String, required: true },
  nonce: { type: String, required: true, unique: true },
  usedAt: { type: Number, required: true },
});

const eventSchema = new mongoose.Schema({
  type: { type: String, required: true, index: true },
  sid: { type: String, default: null },
  sessionId: { type: String, default: null, index: true },
  details: { type: String, default: '' },
  at: { type: Number, default: () => Math.floor(Date.now() / 1000) },
});

module.exports = {
  Student: mongoose.model('Student', studentSchema),
  Device: mongoose.model('Device', deviceSchema),
  Staff: mongoose.model('Staff', staffSchema),
  StaffSession: mongoose.model('StaffSession', staffSessionSchema),
  Session: mongoose.model('Session', sessionSchema),
  Attendance: mongoose.model('Attendance', attendanceSchema),
  Nonce: mongoose.model('Nonce', nonceSchema),
  Event: mongoose.model('Event', eventSchema),
};
