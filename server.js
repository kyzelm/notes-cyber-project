import express from 'express';
import { readFileSync, existsSync } from 'node:fs';
import { createServer as createHttps } from 'node:https';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { db, verifyPassword, hashPassword, seed } from './db.js';
import {
  SECURE, COOKIE, createSession, getSession, destroySession, cookieString,
  applyHeaders, checkCsrf, rateLimited, recordFailure,
  validCredentials, validNewUser, validNote, errorHandler,
} from './security.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || (SECURE ? 3443 : 3000);

seed(SECURE);

// compared when the user doesn't exist, so timing doesn't reveal usernames
const DUMMY_HASH = hashPassword('dummy');
const COOKIE_RE = new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`);

const app = express();
if (SECURE) app.disable('x-powered-by'); // vuln #9

// headers first, so body-parser errors carry them too
app.use((_req, res, next) => { applyHeaders(res); next(); });
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
  const m = COOKIE_RE.exec(req.headers.cookie || '');
  req.sid = m?.[1];
  req.session = req.sid ? getSession(req.sid) : undefined;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session) return res.status(401).json({ error: 'not logged in' });
  next();
}

// vuln #7
function requireCsrf(req, res, next) {
  if (!checkCsrf(req.session, req.headers['x-csrf-token']))
    return res.status(403).json({ error: 'bad csrf token' });
  next();
}

function requireValidNote(req, res, next) {
  if (!validNote(req.body)) return res.status(400).json({ error: 'title: 1-200 chars, body: max 10000 chars' });
  next();
}

// Auth
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });
  if (!validNewUser(req.body))
    return res.status(400).json({ error: 'username: 3-32 of A-Z a-z 0-9 _ . -, password: 8-128 chars' });
  try {
    const stored = SECURE ? hashPassword(password) : password; // vuln #4
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
  if (!validCredentials(req.body)) return res.status(400).json({ error: 'bad request' });

  let user;
  if (!SECURE) {
    // vuln #2
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    user = db.prepare(sql).get();
  } else {
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (verifyPassword(password, row?.password ?? DUMMY_HASH) && row) user = row;
  }

  if (!user) {
    recordFailure(ip);
    return res.status(401).json({ error: 'bad credentials' });
  }

  const { token, csrf } = createSession(user.id);
  res.setHeader('Set-Cookie', cookieString(token)); // vuln #6, #10
  res.json({ ok: true, csrf, username: user.username });
});

app.post('/api/logout', requireAuth, requireCsrf, (req, res) => {
  destroySession(req.sid);
  res.setHeader('Set-Cookie', cookieString('', 0));
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const { username } = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
  res.json({ username, csrf: req.session.csrf });
});

// Notes CRUD
app.get('/api/notes', requireAuth, (req, res) => {
  const q = req.query.q;
  if (q !== undefined && !SECURE) {
    // vuln #2
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
  // vuln #5
  const row = SECURE
    ? db.prepare('SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?').get(id, req.session.userId)
    : db.prepare('SELECT id, title, body FROM notes WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row);
});

app.post('/api/notes', requireAuth, requireCsrf, requireValidNote, (req, res) => {
  const { title, body } = req.body;
  const info = db.prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)')
    .run(req.session.userId, title || '', body || '');
  res.json({ id: info.lastInsertRowid });
});

// vuln #5
app.put('/api/notes/:id', requireAuth, requireCsrf, requireValidNote, (req, res) => {
  const id = Number(req.params.id);
  const { title, body } = req.body;
  const info = SECURE
    ? db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?')
        .run(title, body, id, req.session.userId)
    : db.prepare('UPDATE notes SET title = ?, body = ? WHERE id = ?').run(title, body, id);
  if (!info.changes) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

app.delete('/api/notes/:id', requireAuth, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  const info = SECURE
    ? db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(id, req.session.userId)
    : db.prepare('DELETE FROM notes WHERE id = ?').run(id);
  if (!info.changes) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});

// Static frontend
app.get('/mode.js', (_req, res) => {
  res.type('application/javascript').send(`export const SECURE = ${SECURE};`);
});
app.use(express.static(join(__dirname, 'public')));
app.use(errorHandler); // vuln #11

// Boot
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
