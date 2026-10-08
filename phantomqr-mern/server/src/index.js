const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { Staff } = require('./models');
const router = require('./routes');

const PORT = process.env.PORT || 8813;
const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/phantomqr';

async function seed() {
  const ensure = async (id, name, pw, role) => {
    if (!(await Staff.exists({ staffId: id }))) {
      await Staff.create({ staffId: id, name, passwordHash: bcrypt.hashSync(pw, 10), role });
      console.log('seeded', id, '(' + role + ')');
    }
  };
  await ensure('ST04', 'Demo Professor', 'demo123', 'staff');
  await ensure('ADMIN', 'Demo Admin', 'admin123', 'admin');
}

async function main() {
  await mongoose.connect(MONGO_URL);
  console.log('mongo connected');
  await seed();
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '64kb' }));
  app.use('/api', router);
  // Serve the React build when present (single-origin demo).
  const dist = path.join(__dirname, '..', '..', 'client', 'dist');
  app.use(express.static(dist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(dist, 'index.html'), (err) => err && next());
  });
  app.listen(PORT, () => console.log(`PhantomQR MERN on http://localhost:${PORT}`));
}

main().catch((e) => { console.error(e); process.exit(1); });
