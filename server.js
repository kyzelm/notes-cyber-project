// Single Express app. SECURE env flips every endpoint between a vulnerable and
// a hardened code path. Run via: npm run start:vuln  /  npm run start:secure
import express from 'express';
import { readFileSync, existsSync } from 'node:fs';
import { createServer as createHttps } from 'node:https';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { db, verifyPassword, hashPassword, seed } from './db.js';
import {
  SECURE, createSession, getSession, destroySession,
  cookieString, applyHeaders, checkCsrf, rateLimited,
} from './security.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || (SECURE ? 3443 : 3000);

seed(SECURE);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// parse sid cookie + attach session; set security headers (secure mode only)
app.use((req, res, next) => {
  applyHeaders(res);
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || '');
  req.sid = m?.[1];
  req.session = req.sid ? getSession(req.sid) : undefined;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session) return res.status(401).json({ error: 'not logged in' });
  next();
}

// --- Auth -------------------------------------------------------------------
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });
  try {
    // register always uses a prepared statement (not the vuln we demo)
    const stored = SECURE ? hashPassword(password) : password; // vuln #4: plaintext
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, stored);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'username taken' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (rateLimited(ip)) return res.status(429).json({ error: 'too many attempts' }); // vuln #8

  let user;
  if (!SECURE) {
    // vuln #2: SQL injection. username/password concatenated straight in.
    // payload  ' OR '1'='1' --   bypasses auth entirely.
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    user = db.prepare(sql).get();
  } else {
    // secure: prepared statement + scrypt verify
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (row && verifyPassword(password, row.password)) user = row;
  }

  if (!user) return res.status(401).json({ error: 'bad credentials' });

  const { token, csrf } = createSession(user.id);
  res.setHeader('Set-Cookie', cookieString(token)); // vuln #6 flags, vuln #10 token
  res.json({ ok: true, csrf, username: user.username });
});

app.post('/api/logout', requireAuth, (req, res) => {
  destroySession(req.sid);
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// --- Notes CRUD -------------------------------------------------------------
app.get('/api/notes', requireAuth, (req, res) => {
  const q = req.query.q;
  if (q !== undefined && !SECURE) {
    // vuln #2 again: search is injectable. payload  ' UNION SELECT id,username,password,'x' FROM users --
    const sql = `SELECT id, title, body FROM notes WHERE user_id = ${req.session.userId} AND title LIKE '%${q}%'`;
    return res.json(db.prepare(sql).all());
  }
  const rows = q !== undefined
    ? db.prepare('SELECT id, title, body FROM notes WHERE user_id = ? AND title LIKE ?')
        .all(req.session.userId, `%${q}%`)
    : db.prepare('SELECT id, title, body FROM notes WHERE user_id = ?').all(req.session.userId);
  res.json(rows);
});

app.get('/api/notes/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  // vuln #5 IDOR: vuln mode ignores ownership -> read anyone's note.
  const row = SECURE
    ? db.prepare('SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?').get(id, req.session.userId)
    : db.prepare('SELECT id, title, body FROM notes WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

app.post('/api/notes', requireAuth, (req, res) => {
  if (!checkCsrf(req.session, req.headers['x-csrf-token'])) // vuln #7
    return res.status(403).json({ error: 'bad csrf token' });
  const { title, body } = req.body;
  // NOTE: body stored raw on purpose. XSS (vuln #3) happens at RENDER time
  // in the browser: vuln frontend uses innerHTML, secure uses textContent.
  const info = db.prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)')
    .run(req.session.userId, title || '', body || '');
  res.json({ id: info.lastInsertRowid });
});

app.put('/api/notes/:id', requireAuth, (req, res) => {
  if (!checkCsrf(req.session, req.headers['x-csrf-token'])) return res.status(403).json({ error: 'bad csrf token' });
  const id = Number(req.params.id);
  const owner = SECURE ? ' AND user_id = ?' : '';
  const stmt = db.prepare(`UPDATE notes SET title = ?, body = ? WHERE id = ?${owner}`);
  SECURE ? stmt.run(req.body.title, req.body.body, id, req.session.userId)
         : stmt.run(req.body.title, req.body.body, id);
  res.json({ ok: true });
});

app.delete('/api/notes/:id', requireAuth, (req, res) => {
  if (!checkCsrf(req.session, req.headers['x-csrf-token'])) return res.status(403).json({ error: 'bad csrf token' });
  const id = Number(req.params.id);
  const owner = SECURE ? ' AND user_id = ?' : '';
  const stmt = db.prepare(`DELETE FROM notes WHERE id = ?${owner}`);
  SECURE ? stmt.run(id, req.session.userId) : stmt.run(id);
  res.json({ ok: true });
});

// --- Static frontend. Vuln mode serves app-vuln.js (innerHTML). -------------
app.get('/mode.js', (_req, res) => {
  res.type('application/javascript').send(`export const SECURE = ${SECURE};`);
});
app.use(express.static(join(__dirname, 'public')));

// --- Boot -------------------------------------------------------------------
const banner = `[${SECURE ? 'SECURE' : 'VULNERABLE'}] notes app on ${SECURE ? 'https' : 'http'}://localhost:${PORT}`;
if (SECURE) {
  const key = join(__dirname, 'certs', 'localhost-key.pem');
  const cert = join(__dirname, 'certs', 'localhost.pem');
  if (!existsSync(key) || !existsSync(cert)) {
    console.error('Missing certs/. Run: mkcert -install && mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost.pem localhost 127.0.0.1');
    process.exit(1);
  }
  createHttps({ key: readFileSync(key), cert: readFileSync(cert) }, app).listen(PORT, () => console.log(banner));
} else {
  app.listen(PORT, () => console.log(banner));
}
