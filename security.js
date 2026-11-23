import { randomBytes, timingSafeEqual } from 'node:crypto';

export const SECURE = process.env.SECURE === '1';

// Sessions (vuln #10, #6)
const sessions = new Map();
const SESSION_S = 30 * 60;
let nextId = 1;

// cookies ignore the port, so each mode needs its own name
export const COOKIE = SECURE ? '__Host-sid' : 'sid';

export function createSession(userId) {
  const token = SECURE
    ? randomBytes(32).toString('hex')
    : String(nextId++);
  const csrf = randomBytes(16).toString('hex');
  const expires = SECURE ? Date.now() + SESSION_S * 1000 : Infinity;
  sessions.set(token, { userId, csrf, expires });
  return { token, csrf };
}

export function getSession(token) {
  const s = sessions.get(token);
  if (s && Date.now() >= s.expires) {
    sessions.delete(token);
    return undefined;
  }
  return s;
}

export function destroySession(token) {
  sessions.delete(token);
}

export function cookieString(token, maxAge = SESSION_S) {
  if (!SECURE) return `${COOKIE}=${token}; Path=/${maxAge ? '' : '; Max-Age=0'}`;
  return `${COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

// Security headers (vuln #3, #9)
export function applyHeaders(res) {
  if (!SECURE) return;
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

// CSRF (vuln #7)
export function checkCsrf(session, token) {
  if (!SECURE) return true;
  if (!session?.csrf || !token) return false;
  const a = Buffer.from(session.csrf);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Login rate limiter (vuln #8)
// only failed logins count
const failures = new Map();
const WINDOW_MS = 60_000;
const MAX = 5;

export function rateLimited(ip) {
  if (!SECURE) return false;
  const rec = failures.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.first > WINDOW_MS) {
    failures.delete(ip);
    return false;
  }
  return rec.count >= MAX;
}

export function recordFailure(ip) {
  const rec = failures.get(ip);
  if (rec) rec.count++;
  else failures.set(ip, { count: 1, first: Date.now() });
}

// Input validation
const isStr = (v, min, max) => typeof v === 'string' && v.length >= min && v.length <= max;

export function validCredentials(body) {
  return !SECURE || (isStr(body.username, 1, 32) && isStr(body.password, 1, 128));
}

export function validNewUser(body) {
  return !SECURE || (validCredentials(body) && /^[\w.-]{3,32}$/.test(body.username) && body.password.length >= 8);
}

export function validNote(body) {
  return !SECURE || (isStr(body.title, 1, 200) && isStr(body.body, 0, 10_000));
}

// Errors (vuln #11)
export function errorHandler(err, _req, res, next) {
  if (!SECURE) return next(err);
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'internal error' : 'bad request' });
}
