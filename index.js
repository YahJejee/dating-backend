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

  // Users table (auth basics)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Profiles table (1–1 with users)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      gender TEXT CHECK (gender IN ('male','female')),

      -- ISO date string, e.g. 1990-05-21
      date_of_birth DATE,

      country TEXT,
      city TEXT,
      religion TEXT,
      sect TEXT,

      marital_status TEXT, -- e.g. 'single','divorced','widowed','separated'

      has_children BOOLEAN,
      wants_children BOOLEAN,

      education_level TEXT, -- e.g. 'high_school','bachelor','master','phd'
      occupation TEXT,
      income_range TEXT,

      languages TEXT[],     -- e.g. ['Arabic','English']
      bio TEXT,
      interests TEXT[],     -- e.g. ['travel','music','reading'],

      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log('Users and Profiles tables are ready');
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

// Map DB profile row -> API response
function mapProfileRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    gender: row.gender,
    dateOfBirth: row.date_of_birth, // ISO date from PG
    country: row.country,
    city: row.city,
    religion: row.religion,
    sect: row.sect,
    maritalStatus: row.marital_status,
    hasChildren: row.has_children,
    wantsChildren: row.wants_children,
    educationLevel: row.education_level,
    occupation: row.occupation,
    incomeRange: row.income_range,
    languages: row.languages || [],
    bio: row.bio,
    interests: row.interests || [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
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

// ---------- Protected account endpoints ----------

// Get own account (basic)
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

// ---------- Profile endpoints (Step 1) ----------

// Get my profile
app.get('/me/profile', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM profiles WHERE user_id = $1',
      [req.user.id]
    );
    const profile = result.rows[0] || null;
    res.json({ profile: mapProfileRow(profile) });
  } catch (err) {
    console.error('Error in GET /me/profile', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or update my profile
app.put('/me/profile', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const {
      gender,
      dateOfBirth,
      country,
      city,
      religion,
      sect,
      maritalStatus,
      hasChildren,
      wantsChildren,
      educationLevel,
      occupation,
      incomeRange,
      languages,
      bio,
      interests,
    } = req.body;

    // Optional basic validation
    if (gender && !['male', 'female'].includes(gender)) {
      return res.status(400).json({ error: 'gender must be "male" or "female"' });
    }

    // languages/interests should be arrays or undefined
    const languagesArr = Array.isArray(languages) ? languages : null;
    const interestsArr = Array.isArray(interests) ? interests : null;

    const result = await pool.query(
      `
      INSERT INTO profiles (
        user_id, gender, date_of_birth, country, city, religion, sect,
        marital_status, has_children, wants_children,
        education_level, occupation, income_range,
        languages, bio, interests, created_at, updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, $9, $10,
        $11, $12, $13,
        $14, $15, $16, NOW(), NOW()
      )
      ON CONFLICT (user_id) DO UPDATE SET
        gender = EXCLUDED.gender,
        date_of_birth = EXCLUDED.date_of_birth,
        country = EXCLUDED.country,
        city = EXCLUDED.city,
        religion = EXCLUDED.religion,
        sect = EXCLUDED.sect,
        marital_status = EXCLUDED.marital_status,
        has_children = EXCLUDED.has_children,
        wants_children = EXCLUDED.wants_children,
        education_level = EXCLUDED.education_level,
        occupation = EXCLUDED.occupation,
        income_range = EXCLUDED.income_range,
        languages = EXCLUDED.languages,
        bio = EXCLUDED.bio,
        interests = EXCLUDED.interests,
        updated_at = NOW()
      RETURNING *;
      `,
      [
        req.user.id,
        gender || null,
        dateOfBirth || null,
        country || null,
        city || null,
        religion || null,
        sect || null,
        maritalStatus || null,
        typeof hasChildren === 'boolean' ? hasChildren : null,
        typeof wantsChildren === 'boolean' ? wantsChildren : null,
        educationLevel || null,
        occupation || null,
        incomeRange || null,
        languagesArr,
        bio || null,
        interestsArr,
      ]
    );

    const profile = result.rows[0];

    res.json({ profile: mapProfileRow(profile) });
  } catch (err) {
    console.error('Error in PUT /me/profile', err);
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