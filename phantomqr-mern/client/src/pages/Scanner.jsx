import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Html5Qrcode } from 'html5-qrcode';
import { store, api, post } from '../api';

export default function Scanner() {
  const [locked, setLocked] = useState(true);
  const [who, setWho] = useState('');
  const [sessions, setSessions] = useState([]);
  const [sel, setSel] = useState(() => store.get('pq_session'));
  const [info, setInfo] = useState({ course: '–', name: '–' });
  const [last, setLast] = useState(null);
  const [net, setNet] = useState({ q: 0, online: navigator.onLine });
  const [count, setCount] = useState(() => parseInt(store.get('pq_accepted') || '0', 10));
  const [scanning, setScanning] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [nf, setNf] = useState({ name: '', course: 'CNS-601', room: 'A-204' });
  const [paste, setPaste] = useState('');
  const qrRef = useRef(null);
  const cool = useRef({ payload: '', at: 0, lock: false });

  const q = () => JSON.parse(store.get('pq_queue', '[]'));
  const paint = useCallback(() => {
    setNet({ q: q().length, online: navigator.onLine });
  }, []);

  function show(j, queued) {
    setLast({ ...j, queued });
    if (j.success) {
      setCount((c) => { store.set('pq_accepted', String(c + 1)); return c + 1; });
      if (navigator.vibrate) navigator.vibrate(60);
    }
  }

  const submit = useCallback(async (raw) => {
    const staff = store.get('pq_staff');
    const sid = document.getElementById('sesspick')?.value || store.get('pq_session');
    if (!staff) { show({ success: false, status: 'ERROR', message: 'Staff login required.' }); return; }
    if (!sid) { show({ success: false, status: 'INVALID_SESSION', message: 'No session selected — pick one or tap ＋.' }); return; }
    let token = raw;
    if (typeof token === 'string') {
      try { token = JSON.parse(token); } catch { show({ success: false, status: 'ERROR', message: 'Not valid token JSON.' }); return; }
    }
    const now = Date.now();
    const s = typeof raw === 'string' ? raw : JSON.stringify(raw);
    if (s === cool.current.payload && now - cool.current.at < 10000 && cool.current.lock) return;
    cool.current = { payload: s, at: now, lock: true };
    setTimeout(() => { cool.current.lock = false; }, 2000);
    try {
      const { body } = await post('/api/attendance/scan', {
        token, session_id: sid, staff_session_token: staff, scanned_at: Math.floor(now / 1000),
      });
      show(body, false);
    } catch {
      const arr = q(); arr.push({ token, session_id: sid, scanned_at: Math.floor(now / 1000), queued_at: now });
      store.set('pq_queue', JSON.stringify(arr)); paint();
      setLast({ success: false, status: 'QUEUED', message: `Offline — scan queued (${arr.length})` });
    }
  }, [paint]);

  const loadSessions = useCallback(async () => {
    const staff = store.get('pq_staff');
    if (!staff) return;
    const { ok, body } = await api('/api/sessions?open=1&staff_session_token=' + encodeURIComponent(staff));
    if (!ok) return;
    setSessions(body.sessions || []);
    const saved = store.get('pq_session');
    if (!saved && body.sessions?.length) store.set('pq_session', body.sessions[0].session_id);
  }, []);

  useEffect(() => {
    (async () => {
      const t = store.get('pq_staff');
      if (t) {
        const { ok, body } = await api('/api/staff/me?staff_session_token=' + encodeURIComponent(t));
        if (ok && body.ok) {
          setLocked(false);
          setWho(`${body.staff_id} (${body.role})`);
          await loadSessions();
        } else store.del('pq_staff');
      }
    })();
    const on = () => paint();
    window.addEventListener('online', on);
    window.addEventListener('offline', on);
    const flush = setInterval(async () => {
      const staff = store.get('pq_staff');
      const arr = q();
      if (!staff || !arr.length) { paint(); return; }
      const e = arr[0];
      try {
        const { body } = await post('/api/attendance/scan', {
          token: e.token, session_id: e.session_id, staff_session_token: staff, scanned_at: e.scanned_at,
        });
        show(body, true);
        store.set('pq_queue', JSON.stringify(arr.slice(1))); paint();
      } catch { paint(); }
    }, 5000);
    const focus = () => loadSessions();
    window.addEventListener('focus', focus);
    return () => { clearInterval(flush); window.removeEventListener('online', on); window.removeEventListener('offline', on); window.removeEventListener('focus', focus); };
  }, [loadSessions, paint]);

  useEffect(() => {
    const id = sel || store.get('pq_session');
    if (!id) { setInfo({ course: '–', name: '–' }); return; }
    api('/api/dashboard?session_id=' + encodeURIComponent(id)).then(({ body: j }) => {
      if (j.course) setInfo({ course: j.course + (j.room ? ' / ' + j.room : ''), name: (j.name || id) + (j.status && j.status !== 'OPEN' ? ` (${j.status})` : '') });
      else setInfo({ course: 'unknown session', name: id });
    }).catch(() => {});
  }, [sel, sessions]);

  async function toggleCam() {
    if (scanning) { try { await qrRef.current?.stop(); } catch {} setScanning(false); return; }
    try {
      const h = new Html5Qrcode('reader');
      qrRef.current = h;
      await h.start({ facingMode: 'environment' }, { fps: 10, qrbox: (w, hgt) => { const s = Math.min(w, hgt) * 0.75; return { width: s, height: s }; } }, (txt) => submit(txt));
      setScanning(true);
    } catch (e) {
      show({ success: false, status: 'ERROR', message: 'Camera blocked: ' + (e.message || e) + '. Use localhost/HTTPS or manual fallback.' });
    }
  }

  async function logout() {
    await post('/api/staff/logout', { staff_session_token: store.get('pq_staff') });
    store.del('pq_staff'); store.del('pq_role');
    location.reload();
  }

  async function create() {
    if (!nf.name.trim()) { show({ success: false, status: 'ERROR', message: 'Session name is required.' }); return; }
    const { status, body } = await post('/api/session/open', {
      name: nf.name.trim(), course: nf.course, room: nf.room, start: '', end: '',
      staff_session_token: store.get('pq_staff'),
    });
    if (status !== 200) { show({ success: false, status: 'ERROR', message: body.error || 'create failed' }); return; }
    store.set('pq_session', body.session_id);
    setShowNew(false); setNf({ ...nf, name: '' });
    await loadSessions();
  }

  if (locked) {
    return (
      <div className="text-center py-14">
        <h2 className="text-xl font-bold">Staff only</h2>
        <p className="text-slate-400 text-sm mt-1">The scanner needs a staff login — students are rejected by the API.</p>
        <Link to="/staff/login" className="inline-block mt-3 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl px-6 py-3">Staff login</Link>
      </div>
    );
  }

  return (
    <div>
      <div className="glass rounded-2xl px-4 py-2.5 flex gap-3 items-center sticky top-[57px] z-[5] text-[13px]">
        <div className="flex-1 min-w-0"><small className="text-slate-400 block">Course</small><b className="truncate block">{info.course}</b></div>
        <div className="flex-1 min-w-0"><small className="text-slate-400 block">Session</small><b className="truncate block">{info.name}</b></div>
        <div><small className="text-slate-400 block">Scanned</small><b>{count}</b></div>
        <button onClick={logout} className="text-xs border border-white/15 rounded-lg px-2 py-1.5">Logout</button>
      </div>
      <div className="mt-3">
        <label className="text-xs text-slate-400 block mb-1">Session <span className="opacity-70">(pick by name — IDs are automatic)</span></label>
        <div className="flex gap-2">
          <select id="sesspick" className="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-3 text-white"
            value={sel || store.get('pq_session') || ''} onChange={(e) => { setSel(e.target.value); store.set('pq_session', e.target.value); }}>
            {sessions.map((s) => (
              <option key={s.session_id} value={s.session_id} className="text-black">{s.name} — {s.course} ({s.present})</option>
            ))}
            {sessions.length === 0 && <option value="" className="text-black">No open sessions — tap ＋</option>}
          </select>
          <button onClick={() => setShowNew((v) => !v)} className="border border-white/15 rounded-xl px-4 font-bold">＋</button>
        </div>
        {showNew && (
          <div className="border border-white/10 rounded-xl p-3 mt-2 pop">
            <label className="text-xs text-slate-400 block mb-1">Session name (required)</label>
            <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" placeholder="CNS-601 · Morning"
              value={nf.name} onChange={(e) => setNf({ ...nf, name: e.target.value })} />
            <div className="grid grid-cols-2 gap-2 mt-2">
              <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={nf.course} onChange={(e) => setNf({ ...nf, course: e.target.value })} />
              <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={nf.room} onChange={(e) => setNf({ ...nf, room: e.target.value })} />
            </div>
            <button onClick={create} className="w-full mt-2 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl py-3">Create + use</button>
          </div>
        )}
        <div id="reader" className="mt-2 overflow-hidden rounded-2xl bg-black" />
        <button onClick={toggleCam} className={`w-full mt-2 font-bold rounded-xl py-4 text-lg ${scanning ? 'bg-white/10' : 'bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020]'}`}>
          {scanning ? '■ Stop scanner' : '◎ Start scanner'}
        </button>
        {last && (
          <div className={`pop mt-2 rounded-2xl p-4 text-[15px] font-semibold ${last.success ? 'bg-emerald-400/15 text-emerald-300' : last.status === 'QUEUED' ? 'bg-amber-400/15 text-amber-300' : 'bg-rose-400/15 text-rose-300'}`}>
            <b>{last.success ? '✓ ' : last.status === 'QUEUED' ? '○ ' : '✕ '}{last.student || last.status}</b><br />
            <span className="font-normal text-sm">{last.message}</span>
            <div className="text-xs opacity-70">{last.status}{last.queued ? ' · from offline queue' : ' · live'}</div>
          </div>
        )}
        <div className="font-mono2 text-[11px] text-slate-400 mt-2">
          {who} · Queued offline: {net.q} · Server: {net.online ? '● Connected' : '○ Offline'}
        </div>
        <details className="mt-2 text-sm">
          <summary className="text-slate-400 cursor-pointer py-2">No camera? Manual fallback</summary>
          <textarea rows="3" className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 font-mono2 text-xs"
            placeholder='{"sid":"21BT0451",...}' value={paste} onChange={(e) => setPaste(e.target.value)} />
          <button onClick={() => submit(paste)} className="mt-2 border border-white/15 rounded-xl px-4 py-3 font-semibold w-full">Submit pasted token</button>
        </details>
        <p className="text-slate-500 text-xs mt-2">Camera needs localhost or HTTPS (browser rule). Over plain-HTTP LAN, paste works — same API, same verdicts.</p>
      </div>
    </div>
  );
}
