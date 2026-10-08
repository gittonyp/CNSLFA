import { useEffect, useState } from 'react';
import { store, api } from '../api';

const col = (t) => t === 'ACCEPTED'
  ? 'border-emerald-400'
  : (t === 'INVALID_MAC' || t === 'INVALID_STAFF' || t === 'FORBIDDEN' || t.startsWith('REPLAY') ? 'border-rose-400' : 'border-amber-400');
const tm = (t) => new Date(t * 1000).toLocaleTimeString();

export default function Dashboard() {
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(() => store.get('pq_session'));
  const [d, setD] = useState(null);

  useEffect(() => {
    const staff = store.get('pq_staff');
    if (!staff) return;
    api('/api/sessions?staff_session_token=' + encodeURIComponent(staff)).then(({ ok, body }) => {
      if (ok) {
        setList(body.sessions || []);
        const saved = store.get('pq_session');
        if (!saved && body.sessions?.length) { store.set('pq_session', body.sessions[0].session_id); setSel(body.sessions[0].session_id); }
      }
    }).catch(() => {});
  }, []);

  useEffect(() => {
    async function load() {
      const id = sel || store.get('pq_session') || '';
      const { body } = await api('/api/dashboard?session_id=' + encodeURIComponent(id)).catch(() => ({ body: null }));
      if (body) setD(body);
    }
    load();
    const iv = setInterval(load, 3000);
    return () => clearInterval(iv);
  }, [sel]);

  return (
    <div>
      <div className="glass rounded-2xl p-4">
        <small className="text-slate-400">Session</small>
        <select className="w-full mt-1 bg-white/5 border border-white/10 rounded-xl px-3 py-3 text-white"
          value={sel || store.get('pq_session') || ''} onChange={(e) => { setSel(e.target.value); store.set('pq_session', e.target.value); }}>
          {list.map((s) => <option key={s.session_id} value={s.session_id} className="text-black">{(s.name || s.session_id)} — {s.status}</option>)}
          {list.length === 0 && <option value="" className="text-black">No sessions (staff login shows list)</option>}
        </select>
        <h2 className="text-lg font-bold mt-2">{d ? (d.name || d.session || '(none)') : '–'}</h2>
        <div className="text-xs text-slate-400">{d ? `${d.course || ''} ${d.room || ''} ${d.status || ''}` : ''}</div>
        <div className="flex gap-4 mt-2 items-center">
          <div><b className="text-emerald-300 text-2xl">{d?.present ?? 0}</b> <small className="text-slate-400">/ {d?.expected ?? 0} ({d?.pending ?? 0} pending)</small></div>
          <div className="text-[11px] text-slate-400 font-mono2">
            replays={d?.replays ?? 0} tamper={d?.tampering ?? 0}<br />bad-device={d?.invalidDevices ?? 0} unauth={d?.unauth ?? 0}
          </div>
        </div>
      </div>
      <h3 className="text-xs text-slate-400 uppercase tracking-wider mt-4 mb-1">Security activity</h3>
      <div className="flex flex-col gap-1.5">
        {(d?.feed || []).map((e, i) => (
          <div key={i} className={`glass rounded-xl px-3 py-2 text-sm border-l-4 ${col(e.type)}`}>
            <b>{e.type}</b> {e.sid} <span className="text-slate-500 text-xs">· {tm(e.at)}</span>
          </div>
        ))}
        {d && !d.feed?.length && <span className="text-slate-500 text-sm">No events yet.</span>}
      </div>
      <h3 className="text-xs text-slate-400 uppercase tracking-wider mt-4 mb-1">Attendance</h3>
      <div className="flex flex-col gap-1.5 pb-4">
        {(d?.attendance || []).map((a, i) => (
          <div key={i} className="glass rounded-xl px-3 py-2 text-sm border-l-4 border-emerald-400">
            ✓ {a.sid} <span className="text-slate-500 text-xs">ctr={a.ctr} · {tm(a.at)}</span>
          </div>
        ))}
        {d && !d.attendance?.length && <span className="text-slate-500 text-sm">Nobody marked yet.</span>}
      </div>
    </div>
  );
}
