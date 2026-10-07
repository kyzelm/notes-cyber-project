# Vulnerability Findings

Each entry: what the flaw is, where it lives in the code, how to exploit it in
VULN mode, the fix applied in SECURE mode, and the expected observable result.
This is source material for the project report — expand prose as needed.

Demo users: `alice`/`alicepass`, `bob`/`bobsecret`. Note #3 belongs to Bob and
holds a fake "bank pin"; note #2 (Alice) is the IDOR/CSRF target set.

---

## #1 — Cleartext transport (no TLS)
- **Where:** boot in `server.js`; `http.listen` vs `https.createServer`.
- **Exploit:** Wireshark on `lo`, filter `tcp.port == 3000 && http`, follow the
  `POST /api/login` stream → password and `sid` cookie visible in plain text.
- **Fix:** SECURE serves HTTPS (TLS 1.3) + `Strict-Transport-Security`.
- **Expected:** vuln = readable credentials; secure = only `TLSv1.3 Application
  Data`, nothing recoverable.

## #2 — SQL injection
- **Where:** `server.js` `/api/login` and `/api/notes?q=` vuln branches build
  SQL by string concatenation.
- **Exploit:**
  - Auth bypass: username `x' OR '1'='1' -- ` logs in with no valid password.
  - Data theft: search `q = x%' UNION SELECT id, username, password FROM users -- `
    returns every user's credentials. See `attacks/sqli.sh`.
- **Fix:** SECURE uses parameterised prepared statements (`?` placeholders);
  input can never change query structure.
- **Expected:** vuln dumps `alice/alicepass`, `bob/bobsecret`; secure returns
  `bad credentials` / `[]`.

## #3 — Stored XSS
- **Where:** render in `public/app.js` — vuln uses `p.innerHTML = n.body`.
- **Exploit:** save a note with body `<img src=x onerror=alert(document.domain)>`
  (more in `attacks/xss-payload.txt`). Executes on every view; persisted in DB.
- **Fix:** SECURE uses `p.textContent = n.body` (inert) **and** sends
  `Content-Security-Policy: default-src 'self'` (blocks inline handlers as
  defence in depth).
- **Expected:** vuln pops an alert / can exfiltrate the cookie; secure shows the
  payload as literal text.

## #4 — Plaintext password storage
- **Where:** `db.js` `seed()` and `server.js` `/api/register` — vuln stores the
  raw password.
- **Exploit:** any DB read (or the #2 UNION dump) reveals passwords directly.
- **Fix:** SECURE stores `scrypt(password, randomSalt)` as `salt:hash`
  (`db.js hashPassword/verifyPassword`, `node:crypto`).
- **Expected:** vuln rows show `alicepass`; secure rows show a 128-hex-char
  `salt:hash`, irreversible.

## #5 — IDOR (broken object-level authorization)
- **Where:** `server.js` `GET /api/notes/:id` vuln branch omits the owner check.
- **Exploit:** logged in as Alice, `GET /api/notes/3` returns Bob's note. See
  `attacks/idor.sh`.
- **Fix:** SECURE adds `AND user_id = ?` to the query.
- **Expected:** vuln returns Bob's note; secure returns `404 not found`.

## #6 — Insecure session cookie flags
- **Where:** `security.js cookieString()`.
- **Exploit:** vuln cookie `sid=...; Path=/` — readable by JS (`document.cookie`,
  enables #3 theft), sent over HTTP, sent cross-site (enables #7).
- **Fix:** SECURE sets `HttpOnly; Secure; SameSite=Strict`.
- **Expected:** compare in DevTools → Application → Cookies.

## #7 — CSRF
- **Where:** `server.js` note write endpoints call `checkCsrf`, a no-op in vuln.
- **Exploit:** open `attacks/csrf.html` from another origin while logged in →
  deletes the victim's note using the ambient cookie.
- **Fix:** SECURE requires a matching `X-CSRF-Token` (issued at login,
  `timingSafeEqual`) **and** `SameSite=Strict` stops the cookie being sent
  cross-site in the first place.
- **Expected:** vuln = note deleted; secure = `403 bad csrf token` / cookie not
  sent.

## #8 — No login rate limiting (brute force)
- **Where:** `security.js rateLimited()` returns `false` in vuln.
- **Exploit:** `attacks/bruteforce.sh` fires unlimited guesses, all processed.
- **Fix:** SECURE allows 5 attempts / 60 s per IP, then `429`.
- **Expected:** vuln = fifteen `401`s; secure = `429` from the 6th attempt.

## #9 — Missing security headers
- **Where:** `security.js applyHeaders()` sends nothing in vuln.
- **Exploit:** no CSP (XSS unrestricted), no `X-Frame-Options` (clickjacking via
  iframe), no `X-Content-Type-Options` (MIME sniffing).
- **Fix:** SECURE sends CSP, HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`.
- **Expected:** compare response headers in DevTools → Network.

## #10 — Predictable session identifier
- **Where:** `security.js createSession()` — vuln token is a sequential integer.
- **Exploit:** guess/iterate `sid=1,2,3...` to hijack another live session.
- **Fix:** SECURE uses `crypto.randomBytes(32)` (256-bit, unguessable).
- **Expected:** vuln `Set-Cookie: sid=1`; secure `sid=<64 hex chars>`.

---

## Verified during build (curl)
| Attack | VULN result | SECURE result |
|--------|-------------|---------------|
| SQLi auth bypass | logged in as alice | `bad credentials` |
| SQLi UNION dump | `alice/alicepass`, `bob/bobsecret` | `[]` |
| IDOR note #3 | Bob's note returned | `404` |
| Brute force | all `401` | `429` after 5 |
| Cookie flags | none | `HttpOnly; Secure; SameSite=Strict` |
| Session token | `1` | 64 hex chars |
