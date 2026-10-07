// Frontend. Imports SECURE from server-generated /mode.js. The ONE security
// difference in the client is how note bodies are rendered:
//   vuln   -> el.innerHTML = body   (stored XSS executes, vuln #3)
//   secure -> el.textContent = body (payload shown as inert text)
import { SECURE } from '/mode.js';

const $ = (id) => document.getElementById(id);
let csrf = null;

$('mode').textContent = SECURE ? '[SECURE]' : '[VULNERABLE]';

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(path, { ...opts, headers });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

function showApp(username) {
  $('auth').classList.add('hide');
  $('app').classList.remove('hide');
  $('who').textContent = username;
  loadNotes();
}

$('loginBtn').onclick = async () => {
  const { status, body } = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username: $('username').value, password: $('password').value }),
  });
  if (status === 200) { csrf = body.csrf; showApp(body.username); }
  else $('authMsg').textContent = body.error || 'login failed';
};

$('registerBtn').onclick = async () => {
  const { status, body } = await api('/api/register', {
    method: 'POST',
    body: JSON.stringify({ username: $('username').value, password: $('password').value }),
  });
  $('authMsg').textContent = status === 200 ? 'registered, now log in' : (body.error || 'failed');
};

$('logoutBtn').onclick = async () => {
  await api('/api/logout', { method: 'POST' });
  location.reload();
};

$('addBtn').onclick = async () => {
  await api('/api/notes', {
    method: 'POST',
    body: JSON.stringify({ title: $('title').value, body: $('body').value }),
  });
  $('title').value = ''; $('body').value = '';
  loadNotes();
};

$('search').oninput = (e) => loadNotes(e.target.value);

async function loadNotes(q) {
  const path = q ? `/api/notes?q=${encodeURIComponent(q)}` : '/api/notes';
  const { body: notes } = await api(path);
  const wrap = $('notes');
  wrap.textContent = '';
  for (const n of notes) {
    const div = document.createElement('div');
    div.className = 'note';
    const h = document.createElement('strong');
    h.textContent = n.title;
    const p = document.createElement('p');
    if (SECURE) p.textContent = n.body;      // safe render
    else p.innerHTML = n.body;                // vuln #3: executes stored markup
    const del = document.createElement('button');
    del.textContent = 'delete';
    del.onclick = async () => { await api(`/api/notes/${n.id}`, { method: 'DELETE' }); loadNotes(); };
    div.append(h, p, del);
    wrap.append(div);
  }
}
