
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';
import fs from 'fs';
import url from 'url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-please';
const EDIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let db;
async function initDb() {
  db = await open({
    filename: path.join(__dirname, 'data.sqlite'),
    driver: sqlite3.Database
  });
  await db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      passwordHash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','user'))
    );
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL, -- YYYY-MM-DD
      category TEXT NOT NULL,
      reference TEXT,
      vendor TEXT,
      account TEXT NOT NULL,
      amount REAL NOT NULL,
      description TEXT,
      type TEXT NOT NULL CHECK(type IN ('income','expense')),
      createdBy TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      editedBy TEXT,
      editedAt TEXT
    );
  `);

  // Seed admin/user and default categories/accounts if empty
  const userCount = (await db.get('SELECT COUNT(*) as c FROM users')).c;
  if (userCount === 0) {
    const hash = bcrypt.hashSync('12345', 10);
    await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?,?,?)', ['Qasim', hash, 'admin']);
  }
  const catCount = (await db.get('SELECT COUNT(*) as c FROM categories')).c;
  if (catCount === 0) {
    await db.run('INSERT INTO categories (name) VALUES (?)', ['General']);
  }
  const accCount = (await db.get('SELECT COUNT(*) as c FROM accounts')).c;
  if (accCount === 0) {
    await db.run('INSERT INTO accounts (name) VALUES (?), (?)', ['Cash', 'Bank']);
  }
}

function auth(required = true) {
  return (req, res, next) => {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) {
      if (required) return res.status(401).json({ error: 'No token' });
      req.user = null; return next();
    }
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ---- Auth ----
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const row = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  if (!row) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, row.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, username: row.username, role: row.role });
});

// ---- Users (admin) ----
app.get('/api/users', auth(), requireAdmin, async (req, res) => {
  const rows = await db.all('SELECT username, role FROM users ORDER BY username');
  res.json(rows);
});
app.post('/api/users', auth(), requireAdmin, async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password || !role) return res.status(400).json({ error: 'username, password, role required' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?,?,?)', [username, hash, role]);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.put('/api/users/:username/role', auth(), requireAdmin, async (req, res) => {
  const { role } = req.body || {};
  await db.run('UPDATE users SET role=? WHERE username=?', [role, req.params.username]);
  res.json({ ok: true });
});
app.put('/api/users/:username/password', auth(), requireAdmin, async (req, res) => {
  const { password } = req.body || {};
  const hash = bcrypt.hashSync(password, 10);
  await db.run('UPDATE users SET passwordHash=? WHERE username=?', [hash, req.params.username]);
  res.json({ ok: true });
});
app.delete('/api/users/:username', auth(), requireAdmin, async (req, res) => {
  // prevent deleting last admin
  const row = await db.get('SELECT COUNT(*) as c FROM users WHERE role="admin"');
  const user = await db.get('SELECT * FROM users WHERE username = ?', [req.params.username]);
  if (user?.role === 'admin' && row.c <= 1) return res.status(400).json({ error: 'At least one admin required' });
  await db.run('DELETE FROM users WHERE username=?', [req.params.username]);
  res.json({ ok: true });
});

// ---- Categories ----
app.get('/api/categories', auth(false), async (req, res) => {
  const rows = await db.all('SELECT name FROM categories ORDER BY name');
  res.json(rows.map(r=>r.name));
});
app.post('/api/categories', auth(), requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  try {
    await db.run('INSERT INTO categories (name) VALUES (?)', [name]);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/categories/:name', auth(), requireAdmin, async (req, res) => {
  const { newName } = req.body || {};
  // update existing transactions too
  await db.run('UPDATE transactions SET category=? WHERE category=?', [newName, req.params.name]);
  await db.run('UPDATE categories SET name=? WHERE name=?', [newName, req.params.name]);
  res.json({ ok: true });
});
app.delete('/api/categories/:name', auth(), requireAdmin, async (req, res) => {
  await db.run('DELETE FROM categories WHERE name=?', [req.params.name]);
  res.json({ ok: true });
});

// ---- Accounts ----
app.get('/api/accounts', auth(false), async (req, res) => {
  const rows = await db.all('SELECT name FROM accounts ORDER BY name');
  res.json(rows.map(r=>r.name));
});
app.post('/api/accounts', auth(), requireAdmin, async (req, res) => {
  const { name } = req.body || {};
  try {
    await db.run('INSERT INTO accounts (name) VALUES (?)', [name]);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/accounts/:name', auth(), requireAdmin, async (req, res) => {
  const { newName } = req.body || {};
  await db.run('UPDATE transactions SET account=? WHERE account=?', [newName, req.params.name]);
  await db.run('UPDATE accounts SET name=? WHERE name=?', [newName, req.params.name]);
  res.json({ ok: true });
});
app.delete('/api/accounts/:name', auth(), requireAdmin, async (req, res) => {
  await db.run('DELETE FROM accounts WHERE name=?', [req.params.name]);
  res.json({ ok: true });
});

// ---- Transactions ----
app.get('/api/transactions', auth(), async (req, res) => {
  const rows = await db.all('SELECT * FROM transactions ORDER BY date DESC, id DESC');
  res.json(rows);
});
app.post('/api/transactions', auth(), async (req, res) => {
  const t = req.body || {};
  if (!t.date || !t.category || !t.account || typeof t.amount !== 'number' || !t.type) {
    return res.status(400).json({ error: 'missing fields' });
  }
  const nowIso = new Date().toISOString();
  const result = await db.run(
    `INSERT INTO transactions (date, category, reference, vendor, account, amount, description, type, createdBy, createdAt, editedBy, editedAt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    [t.date, t.category, t.reference||'', t.vendor||'', t.account, t.amount, t.description||'', t.type, req.user.username, nowIso, null, null]
  );
  const row = await db.get('SELECT * FROM transactions WHERE id=?', [result.lastID]);
  res.json(row);
});

app.put('/api/transactions/:id', auth(), async (req, res) => {
  const id = Number(req.params.id);
  const prev = await db.get('SELECT * FROM transactions WHERE id=?', [id]);
  if (!prev) return res.status(404).json({ error: 'not found' });

  const creator = prev.createdBy;
  const withinWindow = (Date.now() - new Date(prev.createdAt).getTime()) <= EDIT_WINDOW_MS;
  const isAdmin = req.user.role === 'admin';
  const canEdit = isAdmin || (req.user.username === creator && withinWindow);
  if (!canEdit) return res.status(403).json({ error: 'edit window expired or not permitted' });

  const t = req.body || {};
  const nowIso = new Date().toISOString();
  await db.run(
    `UPDATE transactions SET date=?, category=?, reference=?, vendor=?, account=?, amount=?, description=?, type=?, editedBy=?, editedAt=? WHERE id=?`,
    [t.date || prev.date, t.category || prev.category, t.reference ?? prev.reference, t.vendor ?? prev.vendor, t.account || prev.account, 
     typeof t.amount === 'number' ? t.amount : prev.amount, t.description ?? prev.description, t.type || prev.type, req.user.username, nowIso, id]
  );
  const updated = await db.get('SELECT * FROM transactions WHERE id=?', [id]);
  res.json(updated);
});

app.delete('/api/transactions/:id', auth(), async (req, res) => {
  const id = Number(req.params.id);
  const prev = await db.get('SELECT * FROM transactions WHERE id=?', [id]);
  if (!prev) return res.status(404).json({ error: 'not found' });

  const creator = prev.createdBy;
  const withinWindow = (Date.now() - new Date(prev.createdAt).getTime()) <= EDIT_WINDOW_MS;
  const isAdmin = req.user.role === 'admin';
  const canDelete = isAdmin || (req.user.username === creator && withinWindow);
  if (!canDelete) return res.status(403).json({ error: 'delete window expired or not permitted' });

  await db.run('DELETE FROM transactions WHERE id=?', [id]);
  res.json({ ok: true });
});

// ---- Backup/Restore (admin) ----
app.get('/api/backup', auth(), requireAdmin, async (req, res) => {
  const payload = {
    users: await db.all('SELECT username, role FROM users'),
    categories: (await db.all('SELECT name FROM categories')).map(r=>r.name),
    accounts: (await db.all('SELECT name FROM accounts')).map(r=>r.name),
    transactions: await db.all('SELECT * FROM transactions')
  };
  res.json(payload);
});

app.post('/api/restore', auth(), requireAdmin, async (req, res) => {
  const data = req.body || {};
  try {
    await db.exec('BEGIN');
    if (Array.isArray(data.users)) {
      // We cannot restore password hashes from backup that didn't include them.
      // So only ensure existence and role.
      for (const u of data.users) {
        const row = await db.get('SELECT * FROM users WHERE username=?', [u.username]);
        if (!row) {
          const hash = bcrypt.hashSync('changeme', 10);
          await db.run('INSERT INTO users (username, passwordHash, role) VALUES (?,?,?)', [u.username, hash, u.role || 'user']);
        } else {
          await db.run('UPDATE users SET role=? WHERE username=?', [u.role || row.role, u.username]);
        }
      }
    }
    if (Array.isArray(data.categories)) {
      await db.run('DELETE FROM categories');
      for (const c of data.categories) await db.run('INSERT INTO categories (name) VALUES (?)', [c]);
    }
    if (Array.isArray(data.accounts)) {
      await db.run('DELETE FROM accounts');
      for (const a of data.accounts) await db.run('INSERT INTO accounts (name) VALUES (?)', [a]);
    }
    if (Array.isArray(data.transactions)) {
      await db.run('DELETE FROM transactions');
      for (const t of data.transactions) {
        await db.run(
          `INSERT INTO transactions (id, date, category, reference, vendor, account, amount, description, type, createdBy, createdAt, editedBy, editedAt)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          [t.id, t.date, t.category, t.reference||'', t.vendor||'', t.account, t.amount, t.description||'', t.type, t.createdBy, t.createdAt, t.editedBy, t.editedAt]
        );
      }
    }
    await db.exec('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await db.exec('ROLLBACK');
    res.status(400).json({ error: e.message });
  }
});

// Fallback to SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
});
