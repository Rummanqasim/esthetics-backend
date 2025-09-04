
# Esthetics Auto Cashbook — Backend Version (Node.js + Express + SQLite)

This converts your single-file frontend app into a full **client–server** app with a backend API and a SQLite database.

## Quick Start

1. Install Node.js (v18+ recommended).
2. In terminal:
   ```bash
   cd esthetics-backend
   npm install
   npm run start
   ```
3. Open http://localhost:3000 in your browser.
4. Login with the seeded admin:
   - **Username:** `Qasim`
   - **Password:** `12345`

> Change `JWT_SECRET` in `server.js` for production and reset the admin password immediately.

## Project Structure

```
esthetics-backend/
├─ server.js          # Express server + API + SQLite schema
├─ package.json
├─ data.sqlite        # Created automatically on first run
└─ public/
   └─ index.html      # Updated frontend that talks to the backend API
```

## API Highlights

- `POST /api/auth/login` → returns JWT
- `GET /api/transactions` (auth) → list
- `POST /api/transactions` (auth) → create
- `PUT /api/transactions/:id` (auth) → update (creator within 10 mins, or admin)
- `DELETE /api/transactions/:id` (auth) → delete (creator within 10 mins, or admin)
- `GET /api/categories` → list
- `POST /api/categories` (admin) → create
- `PUT /api/categories/:name` (admin) → rename (also updates existing transactions)
- `GET /api/accounts` → list
- `POST /api/accounts` (admin) → create
- `PUT /api/accounts/:name` (admin) → rename (also updates existing transactions)
- `GET /api/users` (admin) → list
- `POST /api/users` (admin) → add (password hashed with bcrypt)
- `PUT /api/users/:username/role` (admin) → change role
- `PUT /api/users/:username/password` (admin) → reset password
- `GET /api/backup` (admin) → JSON backup (users without password hashes)
- `POST /api/restore` (admin) → restore from backup (new users get password `changeme`)

## Notes

- Passwords are stored as **bcrypt hashes**.
- JWT expires in **12 hours** by default.
- Edit/delete rule is enforced on the server: creator can edit/delete within **10 minutes** of creation; admins can always edit/delete.
- The frontend keeps all the UI and export features (Excel/PDF) and now fetches data from the server.

## Deploying

- Use any Node-friendly host.
- Set env vars:
  - `PORT` (optional)
  - `JWT_SECRET` (recommended)
- Use a persistent disk for `data.sqlite`.
