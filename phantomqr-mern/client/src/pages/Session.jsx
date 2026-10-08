import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { store, api, post } from '../api';

export default function Session() {
  const [locked, setLocked] = useState(true);
  const [form, setForm] = useState({ name: '', course: 'CNS-601', room: 'A-204' });
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    (async () => {
      const t = store.get('pq_staff');
      if (!t) return;
      const { ok, body } = await api('/api/staff/me?staff_session_token=' + encodeURIComponent(t));
      if (ok && body.ok) setLocked(false);
      else store.del('pq_staff');
    })();
  }, []);

  if (locked) {
    return (
      <div className="text-center py-14">
        <h2 className="text-xl font-bold">Staff only</h2>
        <p className="text-slate-400 text-sm mt-1">Sessions can only be opened by logged-in staff.</p>
        <Link to="/staff/login" className="inline-block mt-3 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl px-6 py-3">Staff login</Link>
      </div>
    );
  }

  async function open() {
    if (!form.name.trim()) { setMsg({ bad: true, t: 'Session name is required.' }); return; }
    const { status, body } = await post('/api/session/open', {
      name: form.name.trim(), course: form.course, room: form.room,
      start: '', end: '', staff_session_token: store.get('pq_staff'),
    });
    if (status !== 200) { setMsg({ bad: true, t: body.error || 'failed' }); return; }
    store.set('pq_session', body.session_id);
    setMsg({ bad: false, t: `“${body.name}” OPEN — ID ${body.session_id} created automatically` });
  }

  return (
    <div className="glass rounded-2xl p-5">
      <h2 className="text-xl font-bold">Class session</h2>
      <p className="text-slate-400 text-xs mt-1">Give it a name — the ID is created automatically. No session exists without a name.</p>
      <label className="text-xs text-slate-400 block mt-3 mb-1">Session name (required)</label>
      <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" placeholder="CNS-601 · Morning batch"
        value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <div className="grid grid-cols-2 gap-2">
        <div><label className="text-xs text-slate-400 block mt-3 mb-1">Course</label>
          <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.course} onChange={(e) => setForm({ ...form, course: e.target.value })} /></div>
        <div><label className="text-xs text-slate-400 block mt-3 mb-1">Room</label>
          <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.room} onChange={(e) => setForm({ ...form, room: e.target.value })} /></div>
      </div>
      <button onClick={open} className="w-full mt-3 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl py-3.5">Open attendance session</button>
      {msg && <div className={`mt-2 text-sm ${msg.bad ? 'text-rose-400' : 'text-emerald-300'}`}>{msg.t}</div>}
      {!msg?.bad && msg && <Link to="/staff/scanner" className="block text-center mt-2 text-cyan-300 text-sm">→ Open scanner</Link>}
    </div>
  );
}
