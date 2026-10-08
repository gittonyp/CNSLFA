import { useEffect, useRef, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { store, post, hmacHex, keyFp, randHex, backendLabel } from '../api';

export default function Student() {
  const [creds, setCreds] = useState(() => ({
    sid: store.get('pq_sid'), did: store.get('pq_did'),
    key: store.get('pq_key'), name: store.get('pq_name'),
  }));
  const [tok, setTok] = useState(null);
  const [left, setLeft] = useState(15);
  const [err, setErr] = useState('');
  const [fp, setFp] = useState('');
  const [form, setForm] = useState({ sid: '21BT0451', name: 'Priya' });

  const enrolled = !!(creds.sid && creds.did && creds.key);

  useEffect(() => {
    if (!enrolled) return;
    let stop = false;
    const ck = `pq_ctr_${creds.sid}_${creds.did}`;
    async function fresh() {
      try {
        const ctr = parseInt(localStorage.getItem(ck) || '0', 10) + 1;
        localStorage.setItem(ck, String(ctr));
        const ts = Math.floor(Date.now() / 1000);
        const nonce = randHex(16);
        const mac = await hmacHex(creds.key, [creds.sid, creds.did, ctr, ts, nonce].join('|'));
        if (stop) return;
        setTok({ sid: creds.sid, did: creds.did, ctr, ts, nonce, mac });
        setLeft(15);
        setErr('');
      } catch (e) {
        if (!stop) setErr('⚠ ' + (e.message || e));
      }
    }
    fresh();
    const iv = setInterval(() => {
      setLeft((l) => {
        if (l <= 1) { fresh(); return 15; }
        return l - 1;
      });
    }, 1000);
    return () => { stop = true; clearInterval(iv); };
  }, [enrolled, creds.sid, creds.did, creds.key]);

  async function enroll() {
    const { status, body } = await post('/api/student/enroll', { sid: form.sid, name: form.name });
    if (status !== 200) { setErr(body.error || 'enroll failed'); return; }
    store.set('pq_sid', body.sid); store.set('pq_name', body.name);
    store.set('pq_did', body.did); store.set('pq_key', body.secret_key);
    store.set(`pq_ctr_${body.sid}_${body.did}`, '0');
    setCreds({ sid: body.sid, did: body.did, key: body.secret_key, name: body.name });
  }

  if (!enrolled) {
    return (
      <div className="glass rounded-2xl p-5">
        <h2 className="text-xl font-bold">Enroll this device</h2>
        <p className="text-slate-400 text-sm mt-1">One step — your key is created and your QR appears.</p>
        <label className="text-xs text-slate-400 block mt-3 mb-1">Student ID</label>
        <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.sid} onChange={(e) => setForm({ ...form, sid: e.target.value })} />
        <label className="text-xs text-slate-400 block mt-3 mb-1">Student Name</label>
        <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <button onClick={enroll} className="w-full mt-4 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl py-3.5">Enroll + show my QR</button>
        {err && <div className="mt-2 text-rose-400 text-sm">{err}</div>}
      </div>
    );
  }

  const frac = left / 15;
  const R = 26, C = 2 * Math.PI * R;
  return (
    <div className="glass rounded-2xl p-4">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-400 to-fuchsia-500 flex items-center justify-center font-extrabold">
          {(creds.name || creds.sid || '?').trim().charAt(0).toUpperCase()}
        </div>
        <div><b>{creds.name}</b><br /><small className="text-slate-400">{creds.sid} · {creds.did}</small></div>
        <span className="ml-auto text-[11px] px-2 py-1 rounded-full bg-emerald-400/15 text-emerald-300 font-bold">
          <span className="live-dot inline-block">●</span> LIVE
        </span>
      </div>
      <div className="text-[11px] text-slate-500 mt-1">crypto: {backendLabel()}</div>
      {err && <div className="mt-2 text-rose-400 text-sm">{err}</div>}
      <div className="bg-white rounded-2xl p-4 mt-3 flex justify-center pop" key={tok ? tok.nonce : 'none'}>
        {tok && <QRCodeSVG value={JSON.stringify(tok)} size={Math.min(300, window.innerWidth - 110)} level="M" />}
      </div>
      <div className="flex items-center gap-3 mt-3">
        <svg width="54" height="54" viewBox="0 0 60 60">
          <circle cx="30" cy="30" r={R} fill="none" stroke="rgba(255,255,255,.12)" strokeWidth="5" />
          <circle cx="30" cy="30" r={R} fill="none" stroke="#38e1ff" strokeWidth="5" strokeLinecap="round"
            strokeDasharray={C} strokeDashoffset={C * (1 - frac)} transform="rotate(-90 30 30)" />
          <text x="30" y="35" textAnchor="middle" fill="#fff" fontSize="15" fontWeight="bold">{left}</text>
        </svg>
        <div className="text-sm text-slate-400">
          Rotates in <b className="text-white">{left}s</b> · Counter <b className="text-white">{tok ? tok.ctr : '–'}</b><br />
          HMAC-SHA256 · 15s rotation · 60s server validity
        </div>
      </div>
      <div className="font-mono2 text-[11px] break-all bg-black/40 border border-white/10 rounded-xl p-2.5 mt-2 text-slate-300">
        {tok ? JSON.stringify(tok) : '…'}
      </div>
      <button
        onClick={async () => { try { setFp('key fp: ' + (await keyFp(creds.key)) + ' (never shown in full)'); } catch (e) { setErr(String(e.message || e)); } }}
        className="mt-2 text-xs text-slate-400 border border-white/10 rounded-lg px-3 py-2">
        Developer: show key fingerprint
      </button>
      {fp && <div className="font-mono2 text-[11px] text-slate-400 mt-1">{fp}</div>}
      <p className="text-rose-400 text-sm mt-2">DO NOT screenshot or share this code.</p>
    </div>
  );
}
