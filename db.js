import { DatabaseSync } from 'node:sqlite';
import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';

export const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
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

const SCRYPT = { N: 2 ** 14, r: 8, p: 5 };

export function hashPassword(plain) {
  const salt = randomBytes(16);
  const hash = scryptSync(plain, salt, 64, SCRYPT);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

export function verifyPassword(plain, stored) {
  const [saltHex, hashHex] = stored.split(':');
  if (!saltHex || !hashHex) return false;
  const hash = scryptSync(plain, Buffer.from(saltHex, 'hex'), 64, SCRYPT);
  return timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

export function seed(secure) {
  const pw = (p) => (secure ? hashPassword(p) : p);
  const insUser = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
  insUser.run('alice', pw('alicepass'));
  insUser.run('bob', pw('bobsecret'));

  const insNote = db.prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
  insNote.run(1, 'Alice shopping', 'milk, eggs, bread');
  insNote.run(1, 'Alice todo', 'call the dentist');
  insNote.run(2, 'Bob private', 'my bank pin is 1234');
}
