# notes-cyber-project — Secure vs Vulnerable Notes CRUD

A single notes application that runs in two modes from one codebase, toggled by
the `SECURE` environment variable. It demonstrates 11 common web
vulnerabilities and their fixes, plus plaintext-vs-TLS network traffic.

- **VULNERABLE** — `SECURE=0`, plain HTTP on `:3000`, every defence disabled.
- **SECURE** — `SECURE=1`, HTTPS on `:3443`, every defence enabled.

Users register/log in and perform CRUD on their own notes. Demo accounts:
`alice` / `alicepass`, `bob` / `bobsecret`.

Never expose the vulnerable mode to a network you don't control.

## 1. Setup

```bash
npm install
```

### TLS certificate (secure mode only)

Browser-trusted, no warnings — uses mkcert:

```bash
sudo pacman -S mkcert        # Arch; or your distro's package
mkcert -install
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost.pem localhost 127.0.0.1
```

(An `openssl` self-signed cert also works but the browser will warn.)

## 2. Run

```bash
npm run start:vuln      # http://localhost:3000
npm run start:secure    # https://localhost:3443
```

Run both at once (two terminals) to compare side by side; the modes use
different cookie names, so one browser can stay logged in to both. The DB is
in-memory and reseeded on every start, so a restart resets all data.

```bash
npm test                # every attack against both modes, on ports 3901/3902
```

## 3. Attacks

Scripts in `attacks/` take the base URL as `$1`, or just a port via `PORT=`
(defaults to the vuln server on `:3000`):

```bash
bash attacks/sqli.sh                         # vuln: bypass + dump creds
bash attacks/sqli.sh https://localhost:3443  # secure: fails
bash attacks/idor.sh                         # read + overwrite another user's note
bash attacks/bruteforce.sh                   # password found vs 429
PORT=8080 bash attacks/sqli.sh               # vuln server on a custom port

# session hijack by guessing the id (log someone in first)
for i in 1 2 3; do curl -s -H "Cookie: sid=$i" http://localhost:3000/api/me; echo; done
# stack trace leak
curl -s -X POST http://localhost:3000/api/login -H 'Content-Type: application/json' -d '{bad'
```

After `bruteforce.sh` the secure server refuses logins from your address for a
minute.

- `attacks/xss-payload.txt` — stored-XSS payloads to paste into a note body.
- `attacks/csrf.html` — serve with `python3 -m http.server 9000 -b 127.0.0.1 -d attacks`, open
  `http://localhost:9000/csrf.html` while logged in; another site creates a note
  in your account. Add `?target=https://localhost:3443` for the secure mode.

## 4. Capturing traffic in Wireshark

This is the core of the HTTP-vs-HTTPS comparison (vuln #1).

```bash
sudo pacman -S wireshark-qt
sudo usermod -aG wireshark $USER   # then re-login, so sudo isn't needed
```

1. Start Wireshark, capture on the **Loopback: lo** interface.
2. **VULN:** filter `tcp.port == 3000 && http`. Log in as alice in the browser.
   - Find the `POST /api/login` packet → *Follow → HTTP Stream*: the JSON body
     shows `"password":"alicepass"` in cleartext.
   - The `Set-Cookie: sid=...` and subsequent `Cookie:` headers are also plain.
     → screenshot for the report.
3. **SECURE:** filter `tcp.port == 3443`. Log in as alice.
   - You see only `TLSv1.3` records (`Application Data`); no password, no
     cookie is readable. → screenshot.
4. Browser **DevTools → Network/Application**: compare the session cookie —
   vuln `sid` has no flags, secure `__Host-sid` has `HttpOnly; Secure; SameSite=Strict`. Compare
   response headers — secure adds CSP / HSTS / X-Frame-Options.

Save each capture (`File → Save As → *.pcapng`) to attach as evidence.

`report/collect.sh` does the same without the GUI: it runs both modes in a
private network namespace, captures one full user session each and writes
captures, packet lists, attack output and timings to `report/evidence/`.

## 5. Files

| File | Role |
|------|------|
| `server.js` | Express app; every endpoint branches on `SECURE` |
| `db.js` | `node:sqlite` schema, seed, scrypt hash/verify |
| `test.js` | `npm test`: expected outcome of every attack in both modes |
| `security.js` | sessions, cookies, headers, CSRF, rate limit, validation, errors — all `SECURE`-gated |
| `public/` | frontend; `app.js` renders note body `innerHTML` (vuln) vs `textContent` (secure) |
| `attacks/` | reproducible exploit scripts + malicious pages |
| `report/` | report and slides (Polish, LaTeX), evidence, `collect.sh` |
| `FINDINGS.md` | per-vulnerability writeup: cause, exploit, fix, expected result |

See `FINDINGS.md` for the full vulnerability analysis.
