import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Home from './pages/Home';
import Student from './pages/Student';
import Staff from './pages/Staff';
import Session from './pages/Session';
import Scanner from './pages/Scanner';
import Dashboard from './pages/Dashboard';
import Attacks from './pages/Attacks';

const I = {
  home: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 10.5 12 3l9 7.5V21H3z" /></svg>,
  qr: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><path d="M14 14h7v7h-7z" /></svg>,
  scan: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3.5" /><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" /></svg>,
  act: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 21s-7.5-4.7-10-9.3C.5 8 2.5 4.5 6 4.5c2 0 3.4 1.1 4 2.2.6-1.1 2-2.2 4-2.2 3.5 0 5.5 3.5 4 7.2C19.5 16.3 12 21 12 21z" /></svg>,
  lab: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 3h6M10 3v6.3L4.7 18a2 2 0 0 0 1.8 3h11a2 2 0 0 0 1.8-3L14 9.3V3" /></svg>,
};

function Tab({ to, icon, label }) {
  return (
    <NavLink to={to} className={({ isActive }) => `flex-1 flex flex-col items-center gap-0.5 py-2 text-[10px] ${isActive ? 'on text-white' : 'text-slate-400'}`}>
      <span className="w-6 h-6 block">{icon}</span><span>{label}</span>
    </NavLink>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="max-w-[520px] mx-auto min-h-screen">
        <header className="sticky top-0 z-10 border-b border-white/10 bg-[#0b1020]/85 backdrop-blur px-4 py-3 flex items-center">
          <a href="/" className="font-extrabold tracking-[0.25em] text-sm">
            <span className="grad-text">PHANTOMQR</span>
          </a>
          <span className="ml-auto text-[11px] text-slate-400">possession of the QR ≠ identity</span>
        </header>
        <main className="px-4 pt-4">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/student/enroll" element={<Student />} />
            <Route path="/student" element={<Student />} />
            <Route path="/staff/login" element={<Staff />} />
            <Route path="/staff/session" element={<Session />} />
            <Route path="/staff/scanner" element={<Scanner />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/attacks" element={<Attacks />} />
          </Routes>
        </main>
        <nav className="tabbar fixed bottom-0 left-0 right-0 z-20 bg-[#0b1020]/90 backdrop-blur border-t border-white/10 flex" style={{ paddingBottom: 'env(safe-area-inset-bottom)' }}>
          <div className="flex w-full max-w-[520px] mx-auto">
            <Tab to="/" icon={I.home} label="Home" />
            <Tab to="/student" icon={I.qr} label="My QR" />
            <Tab to="/staff/scanner" icon={I.scan} label="Scan" />
            <Tab to="/dashboard" icon={I.act} label="Activity" />
            <Tab to="/attacks" icon={I.lab} label="Lab" />
          </div>
        </nav>
      </div>
    </BrowserRouter>
  );
}
