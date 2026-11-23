import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import http from 'node:http';
import https from 'node:https';

const MODES = {
  vuln: { port: 3901, env: '0', lib: http, proto: 'http:' },
  secure: { port: 3902, env: '1', lib: https, proto: 'https:' },
};
const procs = [];

before(async () => {
  for (const m of Object.values(MODES)) {
    const p = spawn(process.execPath, ['server.js'], {
      env: { ...process.env, SECURE: m.env, PORT: m.port }, stdio: ['ignore', 'pipe', 'ignore'],
    });
    procs.push(p);
    await Promise.race([
      once(p.stdout, 'data'),
      once(p, 'exit').then(() => { throw new Error(`server on ${m.port} did not start`); }),
    ]);
  }
});
after(() => procs.forEach((p) => p.kill()));

// fetch can't skip verification of the mkcert CA
function call(mode, method, path, { body, headers = {}, raw } = {}) {
  const m = MODES[mode];
  return new Promise((resolve, reject) => {
    const req = m.lib.request({
      host: 'localhost', port: m.port, method, path, rejectUnauthorized: false,
      headers: { 'Content-Type': 'application/json', ...headers },
    }, (res) => {
      const proto = res.socket.getProtocol?.();
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json;
        try { json = JSON.parse(text); } catch { /* HTML error page */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json, proto });
      });
    });
    req.on('error', reject);
    req.end(raw ?? (body && JSON.stringify(body)));
  });
}

async function login(mode, username, password) {
  const r = await call(mode, 'POST', '/api/login', { body: { username, password } });
  assert.equal(r.status, 200, r.text);
  const setCookie = r.headers['set-cookie'][0];
  const cookie = setCookie.split(';')[0];
  return { setCookie, cookie, token: cookie.split('=')[1], csrf: r.json.csrf,
    headers: { Cookie: cookie, 'X-CSRF-Token': r.json.csrf } };
}
const alice = (mode) => login(mode, 'alice', 'alicepass');
const bob = (mode) => login(mode, 'bob', 'bobsecret');

const both = (name, fn) => {
  test(`VULN   ${name}`, () => fn('vuln', true));
  test(`SECURE ${name}`, () => fn('secure', false));
};

both('CRUD works for the owner', async (mode) => {
  const { headers } = await alice(mode);
  const { json } = await call(mode, 'POST', '/api/notes', { headers, body: { title: 't', body: 'b' } });
  const path = `/api/notes/${json.id}`;
  assert.equal((await call(mode, 'PUT', path, { headers, body: { title: 't2', body: 'b2' } })).status, 200);
  assert.deepEqual((await call(mode, 'GET', path, { headers })).json, { id: json.id, title: 't2', body: 'b2' });
  assert.equal((await call(mode, 'DELETE', path, { headers })).status, 200);
  assert.equal((await call(mode, 'GET', path, { headers })).status, 404);
  assert.equal((await call(mode, 'DELETE', path, { headers })).status, 404);
});

both('/api/me restores session, logout ends it', async (mode) => {
  const { headers, csrf } = await alice(mode);
  assert.deepEqual((await call(mode, 'GET', '/api/me', { headers })).json, { username: 'alice', csrf });
  const out = await call(mode, 'POST', '/api/logout', { headers });
  assert.match(out.headers['set-cookie'][0], /Max-Age=0/);
  assert.equal((await call(mode, 'GET', '/api/me', { headers })).status, 401);
});

both('#1 transport', async (mode, vuln) => {
  const r = await call(mode, 'GET', '/');
  assert.equal(r.proto, vuln ? undefined : 'TLSv1.3');
});

both('#2 SQLi login bypass', async (mode, vuln) => {
  const r = await call(mode, 'POST', '/api/login', { body: { username: "x' OR '1'='1' -- ", password: 'x' } });
  assert.equal(r.status, vuln ? 200 : 401);
});

both('#2 + #4 SQLi UNION dumps plaintext passwords', async (mode, vuln) => {
  const { headers } = await alice(mode);
  const q = encodeURIComponent("x%' UNION SELECT id, username, password FROM users -- ");
  const r = await call(mode, 'GET', `/api/notes?q=${q}`, { headers });
  if (vuln) assert.match(r.text, /bobsecret/);
  else assert.deepEqual(r.json, []);
});

both('#3 XSS: CSP present only in secure', async (mode, vuln) => {
  const csp = (await call(mode, 'GET', '/')).headers['content-security-policy'];
  assert.equal(csp, vuln ? undefined : "default-src 'self'");
});

both('#5 IDOR read and write', async (mode, vuln) => {
  const a = await alice(mode);
  assert.equal((await call(mode, 'GET', '/api/notes/3', a)).status, vuln ? 200 : 404);
  const put = await call(mode, 'PUT', '/api/notes/3', { ...a, body: { title: 'x', body: 'hacked' } });
  assert.equal(put.status, vuln ? 200 : 404);
  const seen = (await call(mode, 'GET', '/api/notes/3', await bob(mode))).json.body;
  assert.equal(seen, vuln ? 'hacked' : 'my bank pin is 1234');
  assert.equal((await call(mode, 'DELETE', '/api/notes/3', a)).status, vuln ? 200 : 404);
});

both('#6 cookie flags and name', async (mode, vuln) => {
  const { setCookie } = await alice(mode);
  if (vuln) assert.match(setCookie, /^sid=\d+; Path=\/$/);
  else assert.match(setCookie, /^__Host-sid=[0-9a-f]{64}; Path=\/; Max-Age=1800; HttpOnly; Secure; SameSite=Strict$/);
});

both('#7 CSRF: form POST with cookie but no token', async (mode, vuln) => {
  const { cookie } = await alice(mode);
  const headers = { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' };
  assert.equal((await call(mode, 'POST', '/api/notes', { headers, raw: 'title=csrf&body=x' })).status, vuln ? 200 : 403);
  assert.equal((await call(mode, 'POST', '/api/logout', { headers })).status, vuln ? 200 : 403);
});

both('#9 security headers', async (mode, vuln) => {
  const { headers } = await call(mode, 'GET', '/');
  for (const h of ['strict-transport-security', 'x-frame-options', 'x-content-type-options'])
    assert.equal(h in headers, !vuln, h);
  assert.equal('x-powered-by' in headers, vuln);
});

both('#10 session hijack by guessing the id', async (mode, vuln) => {
  const s = await bob(mode);
  assert.equal(/^\d+$/.test(s.token), vuln);
  const name = s.cookie.split('=')[0];
  let hijacked = false;
  for (let i = 1; i <= 50 && !hijacked; i++)
    hijacked = (await call(mode, 'GET', '/api/me', { headers: { Cookie: `${name}=${i}` } })).status === 200;
  assert.equal(hijacked, vuln);
});

both('#11 errors leak stack traces', async (mode, vuln) => {
  const bad = await call(mode, 'POST', '/api/login', { raw: '{bad' });
  assert.equal(bad.status, 400);
  assert.equal(/node_modules/.test(bad.text), vuln);
  const { headers } = await alice(mode);
  const put = await call(mode, 'PUT', '/api/notes/1', { headers, body: { title: 'x' } });
  assert.equal(put.status, vuln ? 500 : 400);
  assert.equal(/server\.js/.test(put.text), vuln);
});

test('SECURE rejects malformed and weak input', async () => {
  const reg = (body) => call('secure', 'POST', '/api/register', { body });
  assert.equal((await reg({ username: 'weak', password: 'short' })).status, 400);
  assert.equal((await reg({ username: '<b>x</b>', password: 'longenough' })).status, 400);
  assert.equal((await reg({ username: 'carol', password: 'x'.repeat(129) })).status, 400);
  assert.equal((await reg({ username: 'carol', password: 'longenough' })).status, 200);
  assert.equal((await reg({ username: 'carol', password: 'longenough' })).status, 409);
  await login('secure', 'carol', 'longenough');
  assert.equal((await call('secure', 'POST', '/api/login', { body: { username: 'alice', password: 123 } })).status, 400);
  assert.equal((await call('secure', 'POST', '/api/login', { body: {} })).status, 400);
});

// must run last: locks this IP out for a minute
both('#8 brute force; successful logins do not count', async (mode, vuln) => {
  for (let i = 0; i < 6; i++) await alice(mode);
  // one failure was already used by the SQLi test
  const codes = [];
  for (let i = 0; i < 6; i++)
    codes.push((await call(mode, 'POST', '/api/login', { body: { username: 'alice', password: `g${i}` } })).status);
  assert.deepEqual(codes, vuln ? [401, 401, 401, 401, 401, 401] : [401, 401, 401, 401, 429, 429]);
  const right = await call(mode, 'POST', '/api/login', { body: { username: 'alice', password: 'alicepass' } });
  assert.equal(right.status, vuln ? 200 : 429);
});

test('SECURE session expires after 30 minutes, rate limit after 1', async () => {
  process.env.SECURE = '1';
  const sec = await import('./security.js');
  mock.timers.enable({ apis: ['Date'], now: 0 });
  const { token } = sec.createSession(1);
  for (let i = 0; i < 5; i++) sec.recordFailure('ip');
  assert.ok(sec.rateLimited('ip'));
  mock.timers.tick(60_001);
  assert.ok(!sec.rateLimited('ip'));
  mock.timers.tick(30 * 60_000 - 60_002);
  assert.ok(sec.getSession(token));
  mock.timers.tick(1);
  assert.equal(sec.getSession(token), undefined);
  mock.timers.reset();
});
