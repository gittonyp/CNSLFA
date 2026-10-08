# PhantomQR MERN — Secure QR Classroom Authentication (MongoDB · Express · React · Node)

Same security design as [`../phantomqr`](../phantomqr) (direction flip, HMAC-SHA256,
14-step verify, RBAC, replay/tamper/remote-submission defenses), re-platformed on
MERN with a polished dark React UI (Tailwind, bottom tab bar, animated QR ring).

## Run it

```bash
# 1. Mongo (persistent volume)
docker run -d --name pq-mongo --restart unless-stopped -p 27017:27017 \
  -v pq-mongo-data:/data/db \
  -e MONGO_INITDB_ROOT_USERNAME=pq -e MONGO_INITDB_ROOT_PASSWORD=pqdemo123 \
  mongo:7 --quiet

# 2. Backend (seeds ST04 + ADMIN on first boot)
cd server && npm install && node src/index.js
# → http://localhost:8813  (serves API + built client)

# 3. Frontend dev (optional; prod build is served by Express)
cd client && npm install && npm run build   # output → client/dist
```

Demo accounts: **ST04 / demo123** (staff) · **ADMIN / admin123** (admin).

## Layout

```
phantomqr-mern/
  server/  Express + Mongoose
    src/index.js    boot, seed, static client serving
    src/models.js   students, devices, staff, sessions, attendance, nonces, events
    src/crypto.js   canonical msg, HMAC, timingSafeEqual, shapes
    src/verify.js   STEPS 1–14 pipeline + RBAC gate
    src/routes.js   REST contract (same as Go prototype)
  client/  React 18 + Vite + Tailwind + React Router
    src/api.js      fetch helpers + WebCrypto HMAC (JS fallback off-localhost)
    src/pages/      Home, Student (rotating QR), Staff, Session,
                    Scanner (auto-scan camera), Dashboard (live feed), Attacks (6)
```

## API (same contract as the Go build)

- `POST /api/student/enroll` · `POST /api/staff/login|logout` · `GET /api/staff/me`
- `POST /api/staff/password` · `POST /api/session/open|close` · `GET /api/sessions`
- `POST /api/attendance/scan` · `GET /api/dashboard`
- `POST /api/admin/reset|revoke` (admin only)

## Notes vs the Go build

- No multi-doc transactions (standalone mongod): unique indexes (`nonce`,
  `(sid, session_id)`) are the atomic backstop — races map to the same verdicts.
- Frontend HMAC uses WebCrypto on secure origins, `js-sha256` fallback otherwise
  (byte-identical digests).
- `dotenv` path is anchored to the server dir, so boot works from any CWD.
- Mongo data persists in the `pq-mongo-data` docker volume.
