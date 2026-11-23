import { SECURE } from '/mode.js';

const $ = (id) => document.getElementById(id);
let csrf = null;
let editing = null;

$('mode').textContent = SECURE ? '[SECURE]' : '[VULNERABLE]';

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const res = await fetch(path, { ...opts, headers });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

{
  const { status, body } = await api('/api/me');
  if (status === 200) { csrf = body.csrf; showApp(body.username); }
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

function setForm(note) {
  editing = note?.id ?? null;
  $('title').value = note?.title ?? '';
  $('body').value = note?.body ?? '';
  $('formTitle').textContent = note ? 'Edit note' : 'New note';
  $('addBtn').textContent = note ? 'Save' : 'Add note';
  $('cancelBtn').classList.toggle('hide', !note);
  $('appMsg').textContent = '';
}

$('cancelBtn').onclick = () => setForm(null);

$('addBtn').onclick = async () => {
  const { status, body } = await api(editing === null ? '/api/notes' : `/api/notes/${editing}`, {
    method: editing === null ? 'POST' : 'PUT',
    body: JSON.stringify({ title: $('title').value, body: $('body').value }),
  });
  if (status !== 200) { $('appMsg').textContent = body.error || 'failed'; return; }
  setForm(null);
  loadNotes();
};

$('search').oninput = (e) => loadNotes(e.target.value);

async function loadNotes(q) {
  const path = q ? `/api/notes?q=${encodeURIComponent(q)}` : '/api/notes';
  const { status, body: notes } = await api(path);
  if (status === 401) return location.reload();
  if (status !== 200) { $('appMsg').textContent = 'loading notes failed'; return; }
  const wrap = $('notes');
  wrap.textContent = '';
  for (const n of notes) {
    const div = document.createElement('div');
    div.className = 'note';
    const h = document.createElement('strong');
    h.textContent = n.title;
    const p = document.createElement('p');
    if (SECURE) p.textContent = n.body;
    else p.innerHTML = n.body; // vuln #3
    const del = document.createElement('button');
    del.textContent = 'delete';
    del.onclick = async () => {
      await api(`/api/notes/${n.id}`, { method: 'DELETE' });
      if (editing === n.id) setForm(null);
      loadNotes();
    };
    const edit = document.createElement('button');
    edit.textContent = 'edit';
    edit.onclick = () => setForm(n);
    div.append(h, p, edit, del);
    wrap.append(div);
  }
}
