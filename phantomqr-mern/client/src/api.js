// API helpers + client crypto (WebCrypto with vendored-JS fallback for
// insecure contexts, same HMAC-SHA256 math either way).
import { sha256 } from 'js-sha256';

export const store = {
  get: (k, d = '') => localStorage.getItem(k) ?? d,
  set: (k, v) => localStorage.setItem(k, v),
  del: (k) => localStorage.removeItem(k),
};

export async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, ok: r.ok, body };
}
export const post = (path, obj) =>
  api(path, { method: 'POST', body: JSON.stringify(obj || {}) });

const hex2bytes = (h) => new Uint8Array(h.match(/../g).map((b) => parseInt(b, 16)));
const b2hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
export const randHex = (n) => b2hex(crypto.getRandomValues(new Uint8Array(n)));

const subtleOK = () => !!(window.crypto && crypto.subtle);
let subtleKey = null;
let subtleKeyHex = '';

export async function hmacHex(keyHex, msg) {
  if (subtleOK()) {
    if (!subtleKey || subtleKeyHex !== keyHex) {
      subtleKey = await crypto.subtle.importKey(
        'raw', hex2bytes(keyHex),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      subtleKeyHex = keyHex;
    }
    return b2hex(await crypto.subtle.sign('HMAC', subtleKey, new TextEncoder().encode(msg)));
  }
  return sha256.hmac([...hex2bytes(keyHex)], msg); // ASCII canonical: identical digest
}

export async function keyFp(keyHex) {
  if (subtleOK()) {
    const h = await crypto.subtle.digest('SHA-256', hex2bytes(keyHex));
    return b2hex(h).slice(0, 12);
  }
  return sha256([...hex2bytes(keyHex)]).slice(0, 12);
}

export const backendLabel = () =>
  subtleOK() ? 'WebCrypto' : 'JS fallback · same HMAC-SHA256';
