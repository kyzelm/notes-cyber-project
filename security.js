// All defences live here, each guarded by the SECURE flag. Hand-rolled with
// node:crypto so the report can explain exactly what every defence does.
import { randomBytes, timingSafeEqual } from 'node:crypto';

export const SECURE = process.env.SECURE === '1';

// --- Sessions (vuln #10: predictable id, vuln #6: cookie flags) -------------
const sessions = new Map(); // token -> { userId, csrf }

export function createSession(userId) {
  // vuln mode: short, guessable id. secure mode: 32 random bytes.
  const token = SECURE
    ? randomBytes(32).toString('hex')
    : String(sessions.size + 1); // sequential -> trivially forgeable
  const csrf = randomBytes(16).toString('hex');
  sessions.set(token, { userId, csrf });
  return { token, csrf };
}

export function getSession(token) {
  return sessions.get(token);
}

export function destroySession(token) {
  sessions.delete(token);
}

export function cookieString(token) {
  // vuln mode: no HttpOnly/Secure/SameSite -> stealable via XSS, sent cross-site.
  if (!SECURE) return `sid=${token}; Path=/`;
  return `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

// --- Security headers (vuln #3 CSP, vuln #9 misc) ---------------------------
export function applyHeaders(res) {
  if (!SECURE) return; // vuln mode sends nothing
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

// --- CSRF (vuln #7) ---------------------------------------------------------
export function checkCsrf(session, token) {
  if (!SECURE) return true; // vuln mode never validates
  if (!session?.csrf || !token) return false;
  const a = Buffer.from(session.csrf);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

// --- Login rate limiter (vuln #8) -------------------------------------------
const attempts = new Map(); // ip -> { count, first }
const WINDOW_MS = 60_000;
const MAX = 5;

export function rateLimited(ip) {
  if (!SECURE) return false; // vuln mode: unlimited guessing
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || now - rec.first > WINDOW_MS) {
    attempts.set(ip, { count: 1, first: now });
    return false;
  }
  rec.count++;
  return rec.count > MAX;
}
