// HMAC-SHA256 core (Node built-in crypto only — never hand-rolled).
// Canonical message: sid|did|ctr|ts|nonce ; mac = hex(HMAC(key, canonical)).
const crypto = require('crypto');

function canonical(sid, did, ctr, ts, nonce) {
  return `${sid}|${did}|${ctr}|${ts}|${nonce}`;
}

function computeMac(keyBuf, msg) {
  return crypto.createHmac('sha256', keyBuf).update(msg, 'utf8').digest('hex');
}

// Constant-time compare: rejects length mismatch first (lengths aren't secret;
// MAC bytes are — hence timingSafeEqual, not ===).
function verifyMac(keyBuf, msg, macHex) {
  const want = computeMac(keyBuf, msg);
  const a = Buffer.from(want, 'hex');
  let b;
  try {
    b = Buffer.from(String(macHex).toLowerCase(), 'hex');
  } catch {
    return false;
  }
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function randomHex(nBytes) {
  return crypto.randomBytes(nBytes).toString('hex');
}

function fingerprint(keyBuf) {
  return crypto.createHash('sha256').update(keyBuf).digest('hex').slice(0, 12);
}

function isHex(s) {
  return typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

module.exports = { canonical, computeMac, verifyMac, randomHex, fingerprint, isHex };
