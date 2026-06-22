const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuid } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Ensure dirs exist ────────────────────────────────────────────────────────
const DIRS = ['data', 'uploads/photos', 'db'];
DIRS.forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ── Database (lowdb — pure JS JSON store) ────────────────────────────────────
const db = low(new FileSync('db/db.json'));
db.defaults({
  users: [],
  challenges: [],      // community-submitted
  completions: [],
  notifications: [],
}).write();

// ── File uploads ─────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/photos'),
                                   filename: (req, file, cb) => {
                                     const ext = path.extname(file.originalname).toLowerCase();
                                     cb(null, uuid() + ext);
                                   }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Images only'));
  }
});

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'fc-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'none',
    secure: true
  }
}));

// Never let the browser cache API responses — session state (logged in / not)
// must always be re-validated from the server, not replayed from cache.
// Without this, /api/auth/me returns 304 with a stale "user: null" body even
// after login, which makes admin.html think the user isn't logged in.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// ── Auth helpers ──────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  const u = db.get('users').find({ id: req.session.userId }).value();
  if (!u || u.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}
function getUser(req) {
  if (!req.session.userId) return null;
  return db.get('users').find({ id: req.session.userId }).value() || null;
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, role, businessName, businessPhone, businessAddress } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short (min 6)' });
  if (db.get('users').find({ email }).value()) return res.status(400).json({ error: 'Email already registered' });
  if (db.get('users').find({ username }).value()) return res.status(400).json({ error: 'Username taken' });

  const requestedRole = role === 'business' ? 'business_pending' : 'user';
  if (role === 'business' && !businessPhone) return res.status(400).json({ error: 'Business phone required' });

  const hash = await bcrypt.hash(password, 12);
  const user = {
    id: uuid(), username, email, password: hash,
         role: requestedRole,
         businessName: businessName || null,
         businessPhone: businessPhone || null,
         businessAddress: businessAddress || null,
         approved: requestedRole === 'user',
         createdAt: Date.now(),
         completions: [],
  };

  // First user ever becomes admin
  if (db.get('users').size().value() === 0) {
    user.role = 'admin'; user.approved = true;
  }

  db.get('users').push(user).write();

  if (user.approved) {
    req.session.userId = user.id;
    res.json({ ok: true, user: safeUser(user) });
  } else {
    res.json({ ok: true, pending: true, message: 'Business account pending approval. We\'ll call to verify.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
  if (!user.approved) return res.status(403).json({ error: 'Account pending approval' });
  req.session.userId = user.id;
  res.json({ ok: true, user: safeUser(user) });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  const u = getUser(req);
  if (!u) return res.json({ user: null });
  res.json({ user: safeUser(u) });
});

function safeUser(u) {
  const { password, ...safe } = u;
  return safe;
}

// ── Challenge submission ───────────────────────────────────────────────────────
app.post('/api/challenges/submit', requireAuth, upload.array('photos', 6), async (req, res) => {
  const user = getUser(req);
  const {
    title, where, address, phone, website,
    type, price, weight, timeLimit, description, lat, lng
  } = req.body;

  if (!title || !address) return res.status(400).json({ error: 'Title and address required' });

  const photos = (req.files || []).map(f => `/uploads/photos/${f.filename}`);

  const challenge = {
    id: uuid(),
         title, where, address, phone, website,
         type, price, weight, timeLimit, description,
         lat: parseFloat(lat) || null,
         lng: parseFloat(lng) || null,
         photos,
         imgSrc: photos[0] || null,
         submittedBy: user.id,
         submittedByUsername: user.username,
         submittedByRole: user.role,
         status: 'pending',          // pending | approved | rejected
         verificationStatus: 'user_submitted',  // user_submitted | verified | admin_verified
         difficulty: null,
         createdAt: Date.now(),
         updatedAt: Date.now(),
         completionCount: 0,
         rejectionReason: null,
  };

  // Businesses skip to approved but still show as unverified until admin verifies
  if (user.role === 'business') {
    challenge.status = 'approved';
    challenge.verificationStatus = 'business_submitted';
  }

  db.get('challenges').push(challenge).write();

  // Notify admins
  const admins = db.get('users').filter({ role: 'admin' }).value();
  admins.forEach(a => {
    db.get('notifications').push({
      id: uuid(), userId: a.id,
                                 type: 'new_submission',
                                 message: `New challenge submitted: "${title}" by ${user.username}`,
                                 challengeId: challenge.id,
                                 read: false, createdAt: Date.now()
    }).write();
  });

  res.json({ ok: true, challenge });
});

// ── Get all challenges (JSON file + DB submissions) ───────────────────────────
app.get('/api/challenges', (req, res) => {
  // DB submissions
  const dbChallenges = db.get('challenges')
  .filter(c => c.status === 'approved')
  .value()
  .map(c => ({ ...c, _source: 'db' }));

  res.json({ ok: true, challenges: dbChallenges });
});

// Pending submissions (admin only)
app.get('/api/challenges/pending', requireAdmin, (req, res) => {
  const pending = db.get('challenges').filter({ status: 'pending' }).value();
  res.json({ ok: true, challenges: pending });
});

// Single challenge
app.get('/api/challenges/:id', (req, res) => {
  const c = db.get('challenges').find({ id: req.params.id }).value();
  if (!c) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, challenge: c });
});

// Admin: approve/reject/verify
app.post('/api/challenges/:id/review', requireAdmin, (req, res) => {
  const { action, reason, difficulty } = req.body; // action: approve|reject|verify|unverify
  const c = db.get('challenges').find({ id: req.params.id });
  if (!c.value()) return res.status(404).json({ error: 'Not found' });

  const updates = { updatedAt: Date.now() };
  if (action === 'approve') {
    updates.status = 'approved';
    updates.verificationStatus = 'verified';
  } else if (action === 'reject') {
    updates.status = 'rejected';
    updates.rejectionReason = reason || null;
  } else if (action === 'verify') {
    updates.verificationStatus = 'verified';
  } else if (action === 'admin_verify') {
    updates.verificationStatus = 'admin_verified';
  } else if (action === 'unverify') {
    updates.verificationStatus = 'user_submitted';
  }
  if (difficulty) updates.difficulty = parseInt(difficulty);

  c.assign(updates).write();

  // Notify submitter
  const ch = c.value();
  db.get('notifications').push({
    id: uuid(), userId: ch.submittedBy,
                               type: action,
                               message: action === 'approve'
                               ? `Your challenge "${ch.title}" has been approved!`
                               : action === 'reject'
                               ? `Your challenge "${ch.title}" was not approved. ${reason || ''}`
                               : `Your challenge "${ch.title}" has been verified!`,
                               challengeId: ch.id,
                               read: false, createdAt: Date.now()
  }).write();

  res.json({ ok: true });
});

// Admin: edit any challenge field
app.patch('/api/challenges/:id', requireAdmin, upload.array('photos', 6), (req, res) => {
  const c = db.get('challenges').find({ id: req.params.id });
  if (!c.value()) return res.status(404).json({ error: 'Not found' });
  const updates = { ...req.body, updatedAt: Date.now() };
  if (req.files && req.files.length > 0) {
    const newPhotos = req.files.map(f => `/uploads/photos/${f.filename}`);
    updates.photos = [...(c.value().photos || []), ...newPhotos];
    if (!c.value().imgSrc) updates.imgSrc = newPhotos[0];
  }
  if (updates.lat) updates.lat = parseFloat(updates.lat);
  if (updates.lng) updates.lng = parseFloat(updates.lng);
  if (updates.difficulty) updates.difficulty = parseInt(updates.difficulty);
  c.assign(updates).write();
  res.json({ ok: true, challenge: c.value() });
});

// Admin: delete challenge
app.delete('/api/challenges/:id', requireAdmin, (req, res) => {
  db.get('challenges').remove({ id: req.params.id }).write();
  res.json({ ok: true });
});

// ── Completions ───────────────────────────────────────────────────────────────
app.post('/api/completions', requireAuth, upload.array('photos', 4), (req, res) => {
  const user = getUser(req);
  const { challengeId, challengeTitle, notes, time, isJsonChallenge } = req.body;
  if (!challengeId) return res.status(400).json({ error: 'challengeId required' });

  const existing = db.get('completions').find({ userId: user.id, challengeId }).value();
  if (existing) return res.status(400).json({ error: 'Already logged' });

  const photos = (req.files || []).map(f => `/uploads/photos/${f.filename}`);
  const completion = {
    id: uuid(),
         userId: user.id, username: user.username,
         challengeId, challengeTitle: challengeTitle || '',
         notes: notes || '', time: time || null,
         photos,
         isJsonChallenge: isJsonChallenge === 'true',
         createdAt: Date.now(),
  };
  db.get('completions').push(completion).write();

  // Update challenge completion count if DB challenge
  if (!completion.isJsonChallenge) {
    const c = db.get('challenges').find({ id: challengeId });
    if (c.value()) c.assign({ completionCount: (c.value().completionCount || 0) + 1 }).write();
  }

  // Notify business owner if business challenge
  if (!completion.isJsonChallenge) {
    const ch = db.get('challenges').find({ id: challengeId }).value();
    if (ch && ch.submittedBy) {
      const owner = db.get('users').find({ id: ch.submittedBy }).value();
      if (owner && (owner.role === 'business' || owner.role === 'admin')) {
        db.get('notifications').push({
          id: uuid(), userId: owner.id,
                                     type: 'completion',
                                     message: `${user.username} completed your challenge "${ch.title}"!`,
                                     challengeId, read: false, createdAt: Date.now()
        }).write();
      }
    }
  }

  res.json({ ok: true, completion });
});

app.get('/api/completions/me', requireAuth, (req, res) => {
  const user = getUser(req);
  const completions = db.get('completions').filter({ userId: user.id }).value();
  res.json({ ok: true, completions });
});

// Business: get completions for their challenges
app.get('/api/completions/business', requireAuth, (req, res) => {
  const user = getUser(req);
  if (!['business', 'admin'].includes(user.role)) return res.status(403).json({ error: 'Forbidden' });
  const myChallenges = db.get('challenges').filter({ submittedBy: user.id }).map('id').value();
  const completions = db.get('completions').filter(c => myChallenges.includes(c.challengeId)).value();
  res.json({ ok: true, completions });
});

// Admin: all completions
app.get('/api/completions/all', requireAdmin, (req, res) => {
  const completions = db.get('completions').value();
  res.json({ ok: true, completions });
});

app.delete('/api/completions/:id', requireAdmin, (req, res) => {
  db.get('completions').remove({ id: req.params.id }).write();
  res.json({ ok: true });
});

// ── Leaderboard ───────────────────────────────────────────────────────────────
// Ranked by verified completions: a completion counts toward the leaderboard
// once the underlying challenge has verificationStatus 'verified' or
// 'admin_verified'. JSON-file challenges are treated as pre-verified.
app.get('/api/leaderboard', (req, res) => {
  const completions = db.get('completions').value();
  const challenges = db.get('challenges').value();
  const challengeById = {};
  challenges.forEach(c => { challengeById[c.id] = c; });

  let jsonChallenges = [];
  try {
    jsonChallenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'foodchallenges.json'), 'utf8'));
  } catch (e) { jsonChallenges = []; }
  const jsonByLink = {};
  jsonChallenges.forEach(c => { if (c.link) jsonByLink[c.link] = c; });

  function isVerifiedCompletion(comp) {
    if (comp.isJsonChallenge) {
      const jc = jsonByLink[comp.challengeId];
      return !jc || (jc.verificationStatus || 'admin_verified') !== 'user_submitted';
    }
    const ch = challengeById[comp.challengeId];
    if (!ch) return false;
    return ch.verificationStatus === 'verified' || ch.verificationStatus === 'admin_verified';
  }

  const counts = {}; // userId -> { username, total, verified }
  completions.forEach(comp => {
    if (!counts[comp.userId]) counts[comp.userId] = { userId: comp.userId, username: comp.username, total: 0, verified: 0 };
    counts[comp.userId].total += 1;
    if (isVerifiedCompletion(comp)) counts[comp.userId].verified += 1;
  });

  const leaderboard = Object.values(counts)
    .filter(u => u.verified > 0)
    .sort((a, b) => b.verified - a.verified || b.total - a.total)
    .slice(0, 100)
    .map((u, i) => ({ rank: i + 1, ...u }));

  res.json({ ok: true, leaderboard });
});

// ── Geocoding (city/town search) ────────────────────────────────────────────
// Proxies to OpenStreetMap Nominatim so requests carry a proper User-Agent
// per their usage policy, and so the browser doesn't need direct CORS access.
app.get('/api/geocode', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.status(400).json({ error: 'Missing query' });
  try {
    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=5&q=${encodeURIComponent(q)}`;
    const r = await fetch(url, { headers: { 'User-Agent': 'FoodChallengeFinder/1.0' } });
    const results = await r.json();
    res.json({
      ok: true,
      results: results.map(r => ({
        label: r.display_name,
        lat: parseFloat(r.lat),
        lng: parseFloat(r.lon),
      })),
    });
  } catch (e) {
    res.status(500).json({ error: 'Geocoding failed' });
  }
});

// ── Users (admin) ─────────────────────────────────────────────────────────────
app.get('/api/users', requireAdmin, (req, res) => {
  const users = db.get('users').map(safeUser).value();
  res.json({ ok: true, users });
});

app.patch('/api/users/:id', requireAdmin, async (req, res) => {
  const u = db.get('users').find({ id: req.params.id });
  if (!u.value()) return res.status(404).json({ error: 'Not found' });
  const { role, approved, password } = req.body;
  const updates = {};
  if (role) updates.role = role;
  if (approved !== undefined) updates.approved = approved === true || approved === 'true';
  if (password) updates.password = await bcrypt.hash(password, 12);
  u.assign(updates).write();
  res.json({ ok: true, user: safeUser(u.value()) });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const self = getUser(req);
  if (req.params.id === self.id) return res.status(400).json({ error: 'Cannot delete yourself' });
  db.get('users').remove({ id: req.params.id }).write();
  res.json({ ok: true });
});

// Approve business account
app.post('/api/users/:id/approve', requireAdmin, (req, res) => {
  const u = db.get('users').find({ id: req.params.id });
  if (!u.value()) return res.status(404).json({ error: 'Not found' });
  u.assign({ approved: true, role: 'business' }).write();
  db.get('notifications').push({
    id: uuid(), userId: req.params.id,
                               type: 'account_approved',
                               message: 'Your business account has been approved! You can now submit challenges.',
                               read: false, createdAt: Date.now()
  }).write();
  res.json({ ok: true });
});

// ── Notifications ─────────────────────────────────────────────────────────────
app.get('/api/notifications', requireAuth, (req, res) => {
  const user = getUser(req);
  const notes = db.get('notifications').filter({ userId: user.id }).orderBy('createdAt', 'desc').take(50).value();
  res.json({ ok: true, notifications: notes });
});

app.post('/api/notifications/read', requireAuth, (req, res) => {
  const user = getUser(req);
  db.get('notifications').filter({ userId: user.id }).each(n => { n.read = true; }).write();
  res.json({ ok: true });
});

// ── Stats (admin) ─────────────────────────────────────────────────────────────
app.get('/api/stats', requireAdmin, (req, res) => {
  res.json({
    ok: true,
    stats: {
      users: db.get('users').size().value(),
           pendingUsers: db.get('users').filter({ approved: false }).size().value(),
           challenges: db.get('challenges').size().value(),
           pendingChallenges: db.get('challenges').filter({ status: 'pending' }).size().value(),
           approvedChallenges: db.get('challenges').filter({ status: 'approved' }).size().value(),
           completions: db.get('completions').size().value(),
    }
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🍔 Food Challenge server running at http://localhost:${PORT}`);
  console.log(`   Admin panel: http://localhost:${PORT}/admin.html`);
  console.log(`   First registered user becomes admin.\n`);
});
