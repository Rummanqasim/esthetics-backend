import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import pkg from "pg";

const { Pool } = pkg;
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("frontend"));

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper function for queries
async function query(sql, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(sql, params);
    return result;
  } finally {
    client.release();
  }
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Middleware to check JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- API ROUTES ---

// Register new user
app.post("/api/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
      [username, hashedPassword, role]
    );
    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "User registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: "User not found" });

    if (await bcrypt.compare(password, user.password)) {
      const accessToken = jwt.sign(
        { username: user.username, role: user.role },
        JWT_SECRET
      );
      res.json({ accessToken, role: user.role });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Get all users (Admin only)
app.get("/api/users", authenticateToken, async (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);

  try {
    const result = await query("SELECT id, username, role FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Transactions
app.post("/api/transactions", authenticateToken, async (req, res) => {
  const {
    date,
    category,
    reference,
    vendor,
    account,
    amount,
    description,
    type,
  } = req.body;

  try {
    await query(
      `INSERT INTO transactions
       (date, category, reference, vendor, account, amount, description, type, createdBy, createdAt)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())`,
      [
        date,
        category,
        reference,
        vendor,
        account,
        amount,
        description,
        type,
        req.user.username,
      ]
    );
    res.json({ message: "Transaction added" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add transaction" });
  }
});

app.get("/api/transactions", authenticateToken, async (req, res) => {
  try {
    const result = await query("SELECT * FROM transactions ORDER BY date DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});
// Health check route
app.get("/", (req, res) => {
  res.send("Backend is working 🚀");
});
// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
