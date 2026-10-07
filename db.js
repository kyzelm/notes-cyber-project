// SQLite layer. Uses Node's built-in node:sqlite (Node >= 22, stable in 26).
// Exposes a raw db handle AND query helpers so vulnerable mode can build
// string-concatenated SQL while secure mode uses prepared statements.
import { DatabaseSync } from 'node:sqlite';
import { scryptSync, randomBytes } from 'node:crypto';

export const db = new DatabaseSync(':memory:'); // in-memory: fresh every run, easy to reset

db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    -- vuln mode stores this as plaintext, secure mode as scrypt hash "salt:hash"
    password TEXT NOT NULL
  );
  CREATE TABLE notes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title   TEXT NOT NULL,
    body    TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// scrypt hash helper (secure mode). Format: "<saltHex>:<hashHex>".
export function hashPassword(plain) {
  const salt = randomBytes(16);
  const hash = scryptSync(plain, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

export function verifyPassword(plain, stored) {
  const [saltHex, hashHex] = stored.split(':');
  if (!saltHex || !hashHex) return false; // not a hash (e.g. plaintext row)
  const hash = scryptSync(plain, Buffer.from(saltHex, 'hex'), 64);
  return hash.toString('hex') === hashHex;
}

// Seed demo data. SECURE flag decides whether passwords are hashed or plaintext,
// so the same DB file demonstrates vuln #4 (plaintext storage).
export function seed(secure) {
  const pw = (p) => (secure ? hashPassword(p) : p);
  const insUser = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
  insUser.run('alice', pw('alicepass'));
  insUser.run('bob', pw('bobsecret'));

  const insNote = db.prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
  insNote.run(1, 'Alice shopping', 'milk, eggs, bread');
  insNote.run(1, 'Alice private', 'my bank pin is 1234'); // target for IDOR demo
  insNote.run(2, 'Bob todo', 'call the dentist');
}
