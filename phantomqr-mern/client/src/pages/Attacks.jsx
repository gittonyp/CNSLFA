import { useState } from 'react';
import { store, api, post, randHex, hmacHex } from '../api';

async function scan(token, staffOverride) {
  const { status, body } = await post('/api/attendance/scan', {
    token, session_id: store.get('pq_session') || '',
    staff_session_token: staffOverride !== undefined ? staffOverride : (store.get('pq_staff') || ''),
    scanned_at: Math.floor(Date.now() / 1000),
  });
  return { code: status, body };
}
async function validToken() {
  const sid = store.get('pq_sid'), did = store.get('pq_did'), key = store.get('pq_key');
  const ck = `pq_ctr_${sid}_${did}`;
  const ctr = parseInt(localStorage.getItem(ck) || '0', 10) + 1;
  localStorage.setItem(ck, String(ctr));
  const ts = Math.floor(Date.now() / 1000), nonce = randHex(16);
  const mac = await hmacHex(key, [sid, did, ctr, ts, nonce].join('|'));
  return { sid, did, ctr, ts, nonce, mac };
}

const ATTACKS = [
  { id: 'replay', t: 'Screenshot / old QR replay', d: 'Same valid token twice → second blocked by nonce/counter.',
    run: async () => { const a = await validToken(); const r1 = await scan(a); const r2 = await scan(a);
      return `1st: ${r1.body.status}\n2nd: ${r2.body.status} — ${r2.body.message}` + (/REPLAY|DUPLICATE/.test(r2.body.status) ? '\n✓ REPLAY BLOCKED' : '\n✕ UNEXPECTED'); } },
  { id: 'tamper', t: 'QR payload tampering', d: 'Bump counter without re-signing → INVALID_MAC.',
    run: async () => { const a = await validToken(); a.ctr += 100; const r = await scan(a);
      return `${r.body.status} — ${r.body.message}` + (r.body.status === 'INVALID_MAC' ? '\n✓ TAMPERING DETECTED' : '\n✕ UNEXPECTED'); } },
  { id: 'fake', t: 'Fake QR without secret', d: 'Invented token + random MAC → INVALID_MAC.',
    run: async () => { const a = { sid: store.get('pq_sid') || '21BT0451', did: store.get('pq_did') || 'd7f3', ctr: 99999, ts: Math.floor(Date.now() / 1000), nonce: randHex(16), mac: randHex(32) };
      const r = await scan(a);
      return `${r.body.status} — ${r.body.message}` + (r.body.status === 'INVALID_MAC' ? '\n✓ FORGED TOKEN BLOCKED' : '\n✕ UNEXPECTED'); } },
  { id: 'dup', t: 'Duplicate attendance', d: 'Two fresh tokens, one student → DUPLICATE_ATTENDANCE.',
    run: async () => { const a = await validToken(); const r1 = await scan(a); const b = await validToken(); const r2 = await scan(b);
      return `1st: ${r1.body.status}\n2nd: ${r2.body.status}` + (/DUPLICATE|REPLAY/.test(r2.body.status) ? '\n✓ DUPLICATE BLOCKED' : '\n(note: enroll a fresh student and retry)'); } },
  { id: 'remote', t: 'Remote / unauthorized submission', d: 'POST with no staff session → INVALID_STAFF.',
    run: async () => { const a = await validToken(); const r = await scan(a, '');
      return `${r.body.status} — ${r.body.message}` + (r.body.status === 'INVALID_STAFF' ? '\n✓ REMOTE SUBMISSION BLOCKED' : '\n✕ UNEXPECTED'); } },
  { id: 'role', t: 'Staff tries admin reset', d: 'RBAC: staff calls admin-only reset → 403 FORBIDDEN.',
    run: async () => { const { status, body } = await post('/api/admin/reset', { staff_session_token: store.get('pq_staff') || '' });
      return `${status} ${body.status || ''} — ${body.error || JSON.stringify(body)}` + (status === 403 ? '\n✓ RBAC BLOCKED (login as ADMIN to allow)' : '\n(login as staff ST04 to see the block)'); } },
];

export default function Attacks() {
  const [out, setOut] = useState({});
  const [busy, setBusy] = useState(null);
  const ready = store.get('pq_sid') && store.get('pq_staff') && store.get('pq_session');
  return (
    <div>
      <h2 className="text-xl font-bold">Security Lab</h2>
      <p className="text-slate-400 italic text-sm">Every button calls the real <span className="font-mono2">POST /api/attendance/scan</span>. Nothing is faked.</p>
      {!ready && <div className="mt-2 text-sm px-3 py-2 rounded-xl bg-amber-400/10 text-amber-300">Enroll a student, login staff, and open a session first.</div>}
      <div className="flex flex-col gap-3 mt-3 pb-4">
        {ATTACKS.map((a, i) => (
          <div key={a.id} className="glass rounded-2xl p-4">
            <div className="flex items-center gap-2">
              <span className="w-7 h-7 rounded-full bg-gradient-to-br from-rose-500 to-orange-400 flex items-center justify-center text-xs font-extrabold">{i + 1}</span>
              <b>{a.t}</b>
            </div>
            <p className="text-slate-400 text-xs mt-1">{a.d}</p>
            <button disabled={busy === a.id} onClick={async () => { setBusy(a.id); try { setOut({ ...out, [a.id]: await a.run() }); } catch (e) { setOut({ ...out, [a.id]: 'error: ' + e }); } setBusy(null); }}
              className="mt-2 w-full bg-rose-500/90 rounded-xl py-3 font-bold disabled:opacity-50">
              {busy === a.id ? 'RUNNING…' : 'RUN ATTACK'}
            </button>
            <pre className="font-mono2 text-[11px] text-slate-300 whitespace-pre-wrap mt-2">{out[a.id] || 'not run yet'}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
