import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_DAYS = 7;
const app = express();

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new DatabaseSync(path.join(__dirname, 'data', 'bearer-sharer.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    company TEXT DEFAULT '',
    service TEXT DEFAULT '',
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new'
  );
`);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false });
const contactLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: 'Too many contact attempts. Please try again later.' });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-8', legacyHeaders: false, message: 'Too many login attempts. Please wait and try again.' });
app.use('/api', publicLimiter);

const nowIso = () => new Date().toISOString();
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
};
const verifyPassword = (password, hash, salt) => {
  const derived = crypto.scryptSync(password, salt, 64);
  const stored = Buffer.from(hash, 'hex');
  return stored.length === derived.length && crypto.timingSafeEqual(stored, derived);
};
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const cookieOptions = `Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}`;

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const pair of raw.split(';')) {
    const [k, ...rest] = pair.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}
function setCookie(res, name, value, maxAge = SESSION_DAYS * 86400) {
  res.setHeader('Set-Cookie', `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`);
}
function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
}
function getSession(req) {
  const token = getCookie(req, 'bs_session');
  if (!token) return null;
  const row = db.prepare(`SELECT s.*, a.email FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?`).get(tokenHash(token), Date.now());
  return row || null;
}
function requireAdmin(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Unauthorized' });
  req.session = session;
  next();
}
function requireCsrf(req, res, next) {
  const token = req.get('x-csrf-token') || req.body?.csrf;
  if (!req.session || !token || token !== req.session.csrf_token) return res.status(403).json({ error: 'Invalid security token' });
  next();
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function clean(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

app.get('/api/site', (_req, res) => {
  res.json({
    name: 'BEARER SHARER',
    tradingUrl: 'https://www.bearers-trade.quest/#/register',
    platforms: [
      { name: 'YouTube', url: 'https://www.youtube.com/' },
      { name: 'TikTok', url: 'https://www.tiktok.com/' },
      { name: 'Amazon', url: 'https://www.amazon.com/' },
      { name: 'eBay', url: 'https://www.ebay.com/' },
      { name: 'LinkedIn', url: 'https://www.linkedin.com/' }
    ]
  });
});

app.get('/api/contact/csrf', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/contact', contactLimiter, (req, res) => {
  const name = clean(req.body.name, 80);
  const email = clean(req.body.email, 160).toLowerCase();
  const company = clean(req.body.company, 120);
  const service = clean(req.body.service, 80);
  const message = clean(req.body.message, 3000);
  if (!name || !validEmail(email) || !message) return res.status(400).json({ error: 'Please provide your name, valid email and message.' });
  db.prepare(`INSERT INTO messages (name,email,company,service,message,created_at,status) VALUES (?,?,?,?,?,?,?)`).run(name, email, company, service, message, nowIso(), 'new');
  res.status(201).json({ ok: true, message: 'Thanks — your message has been received.' });
});

app.get('/api/admin/status', (_req, res) => {
  const setupNeeded = Number(db.prepare('SELECT COUNT(*) AS count FROM admins').get().count) === 0;
  res.json({ setupNeeded });
});

app.post('/api/admin/setup', loginLimiter, (req, res) => {
  const count = Number(db.prepare('SELECT COUNT(*) AS count FROM admins').get().count);
  if (count > 0) return res.status(409).json({ error: 'Admin setup is already complete.' });
  const email = clean(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || '');
  if (!validEmail(email) || password.length < 12) return res.status(400).json({ error: 'Use a valid email and a password of at least 12 characters.' });
  const { hash, salt } = hashPassword(password);
  const result = db.prepare('INSERT INTO admins (email,password_hash,salt,created_at) VALUES (?,?,?,?)').run(email, hash, salt, nowIso());
  const sessionToken = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash,admin_id,csrf_token,expires_at,created_at) VALUES (?,?,?,?,?)').run(tokenHash(sessionToken), Number(result.lastInsertRowid), csrf, Date.now() + SESSION_DAYS * 86400000, nowIso());
  setCookie(res, 'bs_session', sessionToken);
  res.json({ ok: true, csrf });
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const email = clean(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || '');
  const admin = db.prepare('SELECT * FROM admins WHERE email=?').get(email);
  if (!admin || !verifyPassword(password, admin.password_hash, admin.salt)) return res.status(401).json({ error: 'Invalid email or password.' });
  const sessionToken = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now());
  db.prepare('INSERT INTO sessions (token_hash,admin_id,csrf_token,expires_at,created_at) VALUES (?,?,?,?,?)').run(tokenHash(sessionToken), admin.id, csrf, Date.now() + SESSION_DAYS * 86400000, nowIso());
  setCookie(res, 'bs_session', sessionToken);
  res.json({ ok: true, csrf });
});

app.post('/api/admin/logout', requireAdmin, requireCsrf, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(req.session.token_hash);
  clearCookie(res, 'bs_session');
  res.json({ ok: true });
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ email: req.session.email, csrf: req.session.csrf_token });
});

app.get('/api/admin/messages', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id,name,email,company,service,message,created_at,status FROM messages ORDER BY id DESC LIMIT 100').all();
  res.json({ messages: rows });
});

app.patch('/api/admin/messages/:id', requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const status = clean(req.body.status, 20);
  if (!Number.isInteger(id) || !['new', 'read', 'closed'].includes(status)) return res.status(400).json({ error: 'Invalid request.' });
  db.prepare('UPDATE messages SET status=? WHERE id=?').run(status, id);
  res.json({ ok: true });
});

app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/admin') return next();
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Unexpected server error.' });
});

app.listen(PORT, HOST, () => {
  console.log(`BEARER SHARER running at http://${HOST}:${PORT}`);
  console.log(`Admin: http://${HOST}:${PORT}/admin`);
});
