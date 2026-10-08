import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';

const TILES = [
  { to: '/student/enroll', t: 'Enroll', s: 'join in seconds', g: 'from-sky-500 to-cyan-400' },
  { to: '/student', t: 'My QR', s: 'rotating token', g: 'from-violet-600 to-fuchsia-500' },
  { to: '/staff/scanner', t: 'Scan', s: 'professor cam', g: 'from-emerald-600 to-lime-500' },
  { to: '/dashboard', t: 'Activity', s: 'live feed', g: 'from-amber-500 to-orange-400' },
  { to: '/attacks', t: 'Attacks', s: 'watch them fail', g: 'from-rose-600 to-red-400' },
  { to: '/staff/login', t: 'Staff', s: 'login', g: 'from-slate-600 to-slate-400' },
];
const HLS = [['H', 'HMAC'], ['15s', 'Rotates'], ['R', 'No replay'], ['T', 'Tamper-proof'], ['S', 'Staff-only'], ['O', 'Offline']];

export default function Home() {
  const [st, setSt] = useState({ present: 0, expected: 0, blocked: 0 });
  useEffect(() => {
    api('/api/dashboard').then(({ body: j }) => setSt({
      present: j.present || 0, expected: j.expected || 0,
      blocked: (j.replays || 0) + (j.tampering || 0) + (j.unauth || 0),
    })).catch(() => {});
  }, []);
  return (
    <div className="pb-6">
      <div className="glass rounded-2xl p-4 flex items-center gap-4">
        <div className="grad-ring rounded-full p-[3px] shrink-0">
          <div className="w-16 h-16 rounded-full bg-[#0b1020] flex items-center justify-center font-extrabold text-xl">PQ</div>
        </div>
        <div className="flex-1 flex justify-around text-center">
          {[['present', st.present], ['students', st.expected], ['blocked', st.blocked]].map(([l, v]) => (
            <div key={l}><b className="block text-lg">{v}</b><small className="text-slate-400">{l}</small></div>
          ))}
        </div>
      </div>
      <div className="mt-3">
        <h1 className="text-2xl font-bold">Secure Classroom <span className="grad-text">Authentication</span></h1>
        <p className="text-slate-400 italic text-sm mt-1">“Possession of the QR is not possession of the identity.”</p>
        <div className="flex gap-2 mt-3">
          <Link to="/staff/scanner" className="flex-1 text-center bg-gradient-to-r from-cyan-400 to-violet-500 text-[#0b1020] font-bold rounded-xl py-3">Open Scanner</Link>
          <Link to="/dashboard" className="flex-1 text-center border border-white/15 rounded-xl py-3 font-semibold">Activity</Link>
        </div>
      </div>
      <div className="flex gap-3 overflow-x-auto py-4">
        {HLS.map(([t, l]) => (
          <div key={l} className="flex flex-col items-center gap-1 shrink-0 w-16">
            <div className="grad-ring rounded-full p-[2px]"><div className="w-14 h-14 rounded-full bg-[#0b1020] flex items-center justify-center text-sm font-bold">{t}</div></div>
            <span className="text-[11px] text-slate-400">{l}</span>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-0.5 rounded-xl overflow-hidden">
        {TILES.map((t) => (
          <Link key={t.t} to={t.to} className={`bg-gradient-to-br ${t.g} aspect-square p-2 flex flex-col justify-end font-bold text-[15px] text-white`} style={{ textShadow: '0 1px 6px rgba(0,0,0,.6)' }}>
            {t.t}<small className="font-normal text-[11px]">{t.s}</small>
          </Link>
        ))}
      </div>
      <div className="glass rounded-2xl p-4 mt-3 font-mono2 text-[12px] text-slate-300">
        STUDENT → signed QR → SCANNER → SERVER verify → ATTENDANCE
      </div>
    </div>
  );
}
