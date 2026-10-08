import { useEffect, useState } from 'react';
import { store, api, post } from '../api';

export default function Staff() {
  const [form, setForm] = useState({ sid: 'ST04', pw: 'demo123' });
  const [me, setMe] = useState(null);
  const [msg, setMsg] = useState(null);

  async function refresh(tok) {
    const t = tok ?? store.get('pq_staff');
    if (!t) { setMe(null); return; }
    const { ok, body } = await api('/api/staff/me?staff_session_token=' + encodeURIComponent(t));
    if (ok && body.ok) {
      setMe(body); store.set('pq_role', body.role || 'staff');
    } else {
      store.del('pq_staff'); store.del('pq_role'); setMe(null);
    }
  }
  useEffect(() => { refresh(); }, []);

  async function login() {
    const { status, body } = await post('/api/staff/login', { staff_id: form.sid, password: form.pw });
    if (status !== 200 || !body.ok) { setMsg({ bad: true, t: 'Login failed: ' + (body.error || 'unknown') }); return; }
    store.set('pq_staff', body.staff_session_token);
    store.set('pq_staff_id', body.staff_id);
    store.set('pq_role', body.role || 'staff');
    setMsg({ bad: false, t: `Logged in as ${body.staff_id} (${body.role})` });
    refresh(body.staff_session_token);
  }
  async function logout() {
    await post('/api/staff/logout', { staff_session_token: store.get('pq_staff') });
    store.del('pq_staff'); store.del('pq_role'); setMe(null);
    setMsg({ bad: false, t: 'Logged out on server + this browser.' });
  }
  async function reset() {
    const { status, body } = await post('/api/admin/reset', { staff_session_token: store.get('pq_staff') });
    setMsg(status === 200
      ? { bad: false, t: 'Demo reset: ' + JSON.stringify(body.cleared) }
      : { bad: true, t: JSON.stringify(body) });
  }

  return (
    <div className="glass rounded-2xl p-5">
      <h2 className="text-xl font-bold">Staff console</h2>
      <p className="text-slate-400 text-xs mt-1">ST04 / demo123 (staff) · ADMIN / admin123 (admin). bcrypt · 8h sessions · rate-limited.</p>
      {me && <div className="mt-2 text-sm px-3 py-2 rounded-xl bg-emerald-400/10 text-emerald-300 font-bold">● {me.staff_id} ({me.role})</div>}
      <label className="text-xs text-slate-400 block mt-3 mb-1">Staff ID</label>
      <input className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.sid} onChange={(e) => setForm({ ...form, sid: e.target.value })} />
      <label className="text-xs text-slate-400 block mt-3 mb-1">Password</label>
      <input type="password" className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-3" value={form.pw} onChange={(e) => setForm({ ...form, pw: e.target.value })} />
      <button onClick={login} className="w-full mt-3 bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl py-3.5">Login</button>
      <button onClick={logout} className="w-full mt-2 border border-white/15 rounded-xl py-3 font-semibold">Logout this browser</button>
      {me && me.role === 'admin' && (
        <button onClick={reset} className="w-full mt-2 bg-rose-500/90 rounded-xl py-3 font-bold">Reset demo data (admin)</button>
      )}
      {msg && <div className={`mt-2 text-sm ${msg.bad ? 'text-rose-400' : 'text-emerald-300'}`}>{msg.t}</div>}
    </div>
  );
}
