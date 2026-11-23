# Vulnerability Findings

Each entry: what the flaw is, where it lives in the code, how to exploit it in
VULN mode, the fix applied in SECURE mode, and the expected observable result.

Demo users: `alice`/`alicepass`, `bob`/`bobsecret`. Note #3 belongs to Bob and
holds a fake "bank pin"; it is the IDOR target.

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
  payload as literal text. CSP was also checked on its own: raw markup injected
  past `textContent` still does not run.

## #4 — Plaintext password storage
- **Where:** `db.js` `seed()` and `server.js` `/api/register` — vuln stores the
  raw password.
- **Exploit:** any DB read (or the #2 UNION dump) reveals passwords directly.
- **Fix:** SECURE stores `scrypt(password, randomSalt)` as `salt:hash`
  (`db.js hashPassword/verifyPassword`, `node:crypto`), with N=2^14, r=8, p=5
  (a configuration listed by OWASP) and a constant-time comparison.
- **Expected:** vuln rows show `alicepass`; secure rows show a 32-hex-char salt
  and a 128-hex-char hash; recovery means guessing one slow hash at a time.

## #5 — IDOR (broken object-level authorization)
- **Where:** `server.js` `GET`, `PUT` and `DELETE /api/notes/:id` vuln branches
  omit the owner check.
- **Exploit:** logged in as Alice, `GET /api/notes/3` returns Bob's note and
  `PUT` overwrites it. See `attacks/idor.sh`.
- **Fix:** SECURE adds `AND user_id = ?` to the queries.
- **Expected:** vuln returns/changes Bob's note; secure returns `404 not found`,
  the same answer as for a note that does not exist.

## #6 — Insecure session cookie flags
- **Where:** `security.js cookieString()`.
- **Exploit:** vuln cookie `sid=...; Path=/` — readable by JS (`document.cookie`,
  enables #3 theft), sent over HTTP, sent cross-site (enables #7).
- **Fix:** SECURE sets `HttpOnly; Secure; SameSite=Strict`, names the cookie
  `__Host-sid` (browser then enforces Secure, Path=/ and no Domain) and expires
  the session after 30 minutes, on the server too.
- **Expected:** compare in DevTools → Application → Cookies.

## #7 — CSRF
- **Where:** `server.js` note write endpoints call `checkCsrf`, a no-op in vuln.
- **Exploit:** open `attacks/csrf.html` from another origin while logged in →
  a form POST creates a note in the victim's account using the ambient cookie.
  (A cross-origin `fetch` with `DELETE` does not work: the browser blocks it at
  the CORS preflight. A form POST needs no preflight.)
- **Fix:** SECURE requires a matching `X-CSRF-Token` (issued at login,
  `timingSafeEqual`) **and** `SameSite=Strict` stops the cookie being sent
  cross-site in the first place.
- **Expected:** vuln = note created. Secure = `401` where the browser withholds
  the cookie; `403 bad csrf token` in Firefox from `http://localhost:9000`, which
  does send it (its `network.cookie.sameSite.schemeful` is off by default; with
  the pref on it answers `401` too).
- **Browser detail (vuln):** a cookie without `SameSite` is sent with a
  cross-site POST by Firefox always, by Chrome only for the first 2 minutes.
  `localhost` on another port is same-site, so it works there at any time.

## #8 — No login rate limiting (brute force)
- **Where:** `security.js rateLimited()` returns `false` in vuln.
- **Exploit:** `attacks/bruteforce.sh` runs a 15-word dictionary; the last word
  is the password.
- **Fix:** SECURE allows 5 failed logins / 60 s per IP, then `429`. Successful
  logins do not count. Unknown users cost the same scrypt time as known ones.
- **Expected:** vuln = fourteen `401`s, then `200`; secure = `429` from the 6th
  attempt, even for the correct password.

## #9 — Missing security headers
- **Where:** `security.js applyHeaders()` sends nothing in vuln.
- **Exploit:** no CSP (XSS unrestricted), no `X-Frame-Options` (clickjacking via
  iframe), no `X-Content-Type-Options` (MIME sniffing).
- **Fix:** SECURE sends CSP, HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and drops `X-Powered-By`.
- **Expected:** compare response headers in DevTools → Network.

## #10 — Predictable session identifier
- **Where:** `security.js createSession()` — vuln token is a sequential integer.
- **Exploit:** guess/iterate `sid=1,2,3...` to hijack another live session.
- **Fix:** SECURE uses `crypto.randomBytes(32)` (256-bit, unguessable).
- **Expected:** vuln `Set-Cookie: sid=1`; secure `sid=<64 hex chars>`.

## #11 — Verbose errors (stack traces)
- **Where:** no error handler in vuln, so Express answers with its default page.
- **Exploit:** send malformed JSON to `/api/login`, or `PUT` a note without
  `body` → the response contains the stack trace: absolute paths, library files,
  SQL constraint names.
- **Fix:** SECURE validates types and lengths (`security.js valid*`) and
  `errorHandler` returns a generic JSON error, logging details on the server.
- **Expected:** vuln = HTML with `/…/node_modules/…`; secure =
  `{"error":"bad request"}`.

---

## Verified
`npm test` checks every row below except the browser ones, in both modes. Browser
rows: Chrome 158 and Firefox 160, 2026-11-23.

| Attack | VULN result | SECURE result |
|--------|-------------|---------------|
| #1 sniffing (tshark) | password, cookie, PIN readable | 0 matching frames, TLS 1.3 |
| #2 SQLi auth bypass | logged in as alice | `401 bad credentials` |
| #2/#4 SQLi UNION dump | `alice/alicepass`, `bob/bobsecret` | `[]` |
| #3 XSS (browser) | executed, cookie sent to :9000 | literal text, nothing sent |
| #5 IDOR read / write note 3 | returned / overwritten | `404` / `404` |
| #6 Cookie flags | none | `__Host-`, `HttpOnly; Secure; SameSite=Strict` |
| #7 CSRF (browser) | note created | `401` / `403`, nothing created |
| #8 Brute force | password found on 15th guess | `429` after 5 |
| #9 Headers | none, `X-Powered-By` | CSP, HSTS, XFO, nosniff |
| #10 Session guessing | session taken over with `sid=1` | `401` |
| #11 Errors | stack trace | generic message |
