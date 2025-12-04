// index.js
const express = require('express');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;

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

// TEMP: list users (only works when DB is enabled)
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