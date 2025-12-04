// index.js
require('dotenv').config(); // loads .env for local dev

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;

// Parse JSON bodies
app.use(express.json());

let pool = null;
let dbEnabled = false;

if (dbUrl) {
  pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false },
  });
  dbEnabled = true;
  console.log('DATABASE_URL found, DB features enabled');
} else {
  console.log('No DATABASE_URL set, running WITHOUT database (local dev mode)');
}

if (!jwtSecret) {
  console.warn('⚠️ JWT_SECRET is not set. JWT features will not work correctly.');
}

// Ensure core tables exist (only if DB is enabled)
async function ensureTables() {
  if (!dbEnabled) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log('Users table is ready');
}

// ---------- Helper functions ----------

function generateToken(user) {
  if (!jwtSecret) {
    throw new Error('JWT_SECRET not configured');
  }
  return jwt.sign(
    { userId: user.id, email: user.email },
    jwtSecret,
    { expiresIn: '7d' }
  );
}

async function findUserByEmail(email) {
  const result = await pool.query(
    'SELECT id, email, password_hash, full_name, created_at FROM users WHERE email = $1',
    [email]
  );
  return result.rows[0] || null;
}

// Auth middleware to protect routes
function authMiddleware(req, res, next) {
  if (!jwtSecret) {
    return res.status(500).json({ error: 'JWT not configured' });
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = { id: payload.userId, email: payload.email };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- Public endpoints ----------

// Root endpoint
app.get('/', (req, res) => {
  res.send('Dating backend is running');
});

// Health check
app.get('/health', async (req, res) => {
  if (!dbEnabled) {
    return res.json({
      status: 'ok',
      db: 'disabled (no DATABASE_URL)',
    });
  }

  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      dbTime: result.rows[0].now,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ---------- Auth endpoints ----------

// Register
app.post('/auth/register', async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const { email, password, fullName } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existing = await findUserByEmail(email.toLowerCase());
    if (existing) {
      return res.status(409).json({ error: 'Email already in use' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, full_name)
       VALUES ($1, $2, $3)
       RETURNING id, email, full_name, created_at`,
      [email.toLowerCase(), passwordHash, fullName || null]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        createdAt: user.created_at,
      },
    });
  } catch (err) {
    console.error('Error in /auth/register', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await findUserByEmail(email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        createdAt: user.created_at,
      },
    });
  } catch (err) {
    console.error('Error in /auth/login', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------- Protected endpoint example ----------

app.get('/me', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, full_name, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      createdAt: user.created_at,
    });
  } catch (err) {
    console.error('Error in /me', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// TEMP: list users (debug)
app.get('/users', async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email, full_name, created_at FROM users ORDER BY id'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Start the server
async function start() {
  try {
    if (dbEnabled) {
      await ensureTables();
    }
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();