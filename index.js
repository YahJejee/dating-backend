// 🔥 messaging route cleanup commit test
// index.js
require('dotenv').config(); // loads .env for local dev

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');


const app = express();
const port = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;

// Parse JSON bodies + allow CORS
app.use(cors());
app.use(express.json());
const s3Bucket = process.env.S3_BUCKET_NAME;
const s3Region = process.env.AWS_REGION;
const s3Prefix = process.env.S3_PREFIX || 'profiles/';

const s3Enabled = !!(s3Bucket && s3Region && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY);

const s3 = s3Enabled
  ? new S3Client({
      region: s3Region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    })
  : null;

if (!s3Enabled) {
  console.warn('⚠️ S3 is not configured. Photo upload features will be disabled.');
}

const S3_BUCKET = process.env.S3_BUCKET || process.env.AWS_S3_BUCKET;

async function presignGetUrl(s3Key, expiresInSeconds = 300) {
  if (!S3_BUCKET) throw new Error('S3_BUCKET is not set');
  const cmd = new GetObjectCommand({
    Bucket: S3_BUCKET,
    Key: s3Key,
  });
  return await getSignedUrl(s3, cmd, { expiresIn: expiresInSeconds });
}



let pool = null;
let dbEnabled = false;

const isProd = process.env.NODE_ENV === 'production';

if (dbUrl) {
  // Supports either real multiline cert OR cert pasted with "\n"
  const caCertRaw = process.env.DATABASE_CA_CERT;
  const caCert = caCertRaw ? caCertRaw.replace(/\\n/g, '\n') : undefined;

  pool = new Pool({
    connectionString: dbUrl,
    ssl: isProd
      ? (caCert
          ? { rejectUnauthorized: true, ca: caCert }
          : { rejectUnauthorized: false }) // fallback if CA not set yet
      : false,
  });
  
 
  dbEnabled = true;
}


if (!jwtSecret) {
  console.warn('⚠️ JWT_SECRET is not set. JWT features will not work correctly.');
}


// Ensure core tables exist (only if DB is enabled)
async function ensureTables() {
  if (!dbEnabled) return;

  // Entitlements (free/premium)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_entitlements (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free','premium')),
      source TEXT NOT NULL DEFAULT 'admin' CHECK (source IN ('admin','android','ios','web')),
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Conversations (one per match)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      match_id INTEGER UNIQUE REFERENCES matches(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Messages
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);



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
      date_of_birth DATE,
      country TEXT,
      city TEXT,
      religion TEXT,
      sect TEXT,
      marital_status TEXT,
      has_children BOOLEAN,
      wants_children BOOLEAN,
      education_level TEXT,
      occupation TEXT,
      income_range TEXT,
      languages TEXT[],
      bio TEXT,
      interests TEXT[],
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Preferences table (1–1 with users)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS preferences (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      preferred_gender TEXT CHECK (preferred_gender IN ('male','female') OR preferred_gender IS NULL),
      min_age INTEGER,
      max_age INTEGER,
      preferred_religions TEXT[],
      preferred_sects TEXT[],
      preferred_marital_statuses TEXT[],
      accept_has_children BOOLEAN,
      wants_children BOOLEAN,
      max_distance_km INTEGER,
      preferred_countries TEXT[],
      preferred_cities TEXT[],
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Likes table (one-directional "like")
  await pool.query(`
    CREATE TABLE IF NOT EXISTS likes (
      liker_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      liked_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (liker_id, liked_id)
    );
  `);

  // Passes table (one-directional "pass")
  await pool.query(`
    CREATE TABLE IF NOT EXISTS passes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, target_user_id)
    );
  `);

  // Matches table (mutual like)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS matches (
      id SERIAL PRIMARY KEY,
      user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user1_id, user2_id)
    );
  `);

  console.log('Users, Profiles, Preferences, Likes, Passes, Matches tables are ready');
}

// ---------- Helper functions ----------

function extFromContentType(ct) {
  if (!ct) return 'bin';
  const c = ct.toLowerCase();
  if (c.includes('jpeg')) return 'jpg';
  if (c.includes('png')) return 'png';
  if (c.includes('webp')) return 'webp';
  return 'bin';
}

async function countUserPhotos(userId) {
  const r = await pool.query(
    `SELECT COUNT(*)::int AS cnt FROM user_photos WHERE user_id = $1`,
    [userId]
  );
  return r.rows[0].cnt;
}

async function ensurePrimaryIfNone(userId) {
  const r = await pool.query(
    `SELECT 1 FROM user_photos WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`,
    [userId]
  );
  if (r.rowCount > 0) return;

  await pool.query(
    `
    WITH first_photo AS (
      SELECT id FROM user_photos
      WHERE user_id = $1
      ORDER BY created_at ASC, id ASC
      LIMIT 1
    )
    UPDATE user_photos
    SET is_primary = TRUE
    WHERE id IN (SELECT id FROM first_photo);
    `,
    [userId]
  );
}


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

async function getOrCreateConversation(matchId) {
  const existing = await pool.query(
    `SELECT id FROM conversations WHERE match_id = $1`,
    [matchId]
  );
  if (existing.rowCount > 0) return existing.rows[0].id;

  const created = await pool.query(
    `INSERT INTO conversations (match_id) VALUES ($1) RETURNING id`,
    [matchId]
  );
  return created.rows[0].id;
}

async function userIsInMatch(userId, matchId) {
  const r = await pool.query(
    `SELECT 1 FROM matches WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
    [matchId, userId]
  );
  return r.rowCount > 0;
}


async function findUserByEmail(email) {
  const result = await pool.query(
    'SELECT id, email, password_hash, full_name, created_at FROM users WHERE email = $1',
    [email]
  );
  return result.rows[0] || null;
}

async function getEntitlement(userId) {
  const r = await pool.query(
    `SELECT tier, expires_at FROM user_entitlements WHERE user_id = $1`,
    [userId]
  );

  // default to free if no row exists
  if (r.rowCount === 0) return { tier: 'free', isPremium: false };

  const { tier, expires_at } = r.rows[0];
  const isPremium =
    tier === 'premium' && (!expires_at || new Date(expires_at) > new Date());

  return { tier, isPremium };
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
// Set a photo as my primary photo
app.post('/photos/:photoId/primary', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  let inTx = false;

  try {
    const userId = req.user.id;
    const photoId = Number.parseInt(req.params.photoId, 10);
    if (!Number.isFinite(photoId)) return res.status(400).json({ error: 'Invalid photoId' });

    // Ensure the photo belongs to this user
    const owned = await pool.query(
      `SELECT id FROM user_photos WHERE id = $1 AND user_id = $2`,
      [photoId, userId]
    );
    if (owned.rowCount === 0) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    await pool.query('BEGIN');
    inTx = true;

    await pool.query(`UPDATE user_photos SET is_primary = FALSE WHERE user_id = $1`, [userId]);

    const updated = await pool.query(
      `UPDATE user_photos
       SET is_primary = TRUE
       WHERE id = $1 AND user_id = $2
       RETURNING id, user_id, s3_key, content_type, bytes, is_primary, created_at;`,
      [photoId, userId]
    );

    await pool.query('COMMIT');
    inTx = false;

    res.json({ photo: updated.rows[0] });
  } catch (e) {
    if (inTx) {
      try { await pool.query('ROLLBACK'); } catch (_) {}
    }
    console.error('Error in POST /photos/:photoId/primary', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});
cd C:\dating-backend
Select-String -Path .\index.js -Pattern "photos/:photoId/primary" -SimpleMatch
git status


// Get my entitlement
app.get('/me/entitlement', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  try {
    const ent = await getEntitlement(req.user.id);
    res.json(ent);
  } catch (e) {
    console.error('Error in GET /me/entitlement', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// TEMP admin: set entitlement (remove/secure later!)
app.post('/admin/entitlement', async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  try {
    const { userId, tier, expiresAt } = req.body;
    if (!userId || !['free','premium'].includes(tier)) {
      return res.status(400).json({ error: 'userId and tier (free|premium) required' });
    }

    const result = await pool.query(
      `
      INSERT INTO user_entitlements (user_id, tier, source, expires_at, updated_at)
      VALUES ($1, $2, 'admin', $3, NOW())
      ON CONFLICT (user_id) DO UPDATE SET
        tier = EXCLUDED.tier,
        source = EXCLUDED.source,
        expires_at = EXCLUDED.expires_at,
        updated_at = NOW()
      RETURNING user_id, tier, source, expires_at;
      `,
      [userId, tier, expiresAt || null]
    );

    res.json(result.rows[0]);
  } catch (e) {
    console.error('Error in POST /admin/entitlement', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Map DB profile row -> API response
function mapProfileRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    gender: row.gender,
    dateOfBirth: row.date_of_birth,
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

// Map DB preferences row -> API response
function mapPreferencesRow(row) {
  if (!row) return null;
  return {
    userId: row.user_id,
    preferredGender: row.preferred_gender,
    minAge: row.min_age,
    maxAge: row.max_age,
    preferredReligions: row.preferred_religions || [],
    preferredSects: row.preferred_sects || [],
    preferredMaritalStatuses: row.preferred_marital_statuses || [],
    acceptHasChildren: row.accept_has_children,
    wantsChildren: row.wants_children,
    maxDistanceKm: row.max_distance_km,
    preferredCountries: row.preferred_countries || [],
    preferredCities: row.preferred_cities || [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// Map DB match row -> API response
function mapMatchRow(row) {
  if (!row) return null;
  return {
    matchId: row.match_id,
    userId: row.other_user_id,
    email: row.other_email,
    fullName: row.other_full_name,
    createdAt: row.match_created_at,
  };
}

// Compute age from a DATE string (e.g. "1990-05-21")
function computeAge(dateOfBirth) {
  if (!dateOfBirth) return null;
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime())) return null;
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) {
    age--;
  }
  return age;
}

// Basic matching score between my prefs/profile and candidate profile
function computeMatchScore(myProfile, myPrefs, candidateProfile) {
  let score = 0;

  // 🔒 Hard constraint 1: only opposite-gender matches
  if (myProfile.gender && candidateProfile.gender) {
    if (myProfile.gender === candidateProfile.gender) {
      return -1; // do not match same gender
    }
  }

  const candidateAge = computeAge(candidateProfile.date_of_birth);

  // 🔒 Hard constraint 2: never match anyone under 18
  if (candidateAge != null && candidateAge < 18) {
    return -1;
  }

  // 🔒 Hard constraints from preferences

  if (myPrefs.min_age != null && candidateAge != null && candidateAge < myPrefs.min_age) {
    return -1;
  }
  if (myPrefs.max_age != null && candidateAge != null && candidateAge > myPrefs.max_age) {
    return -1;
  }

  // We are no longer using preferred_gender for matching
  // (the matching is always opposite-gender now)

  if (myPrefs.preferred_religions && myPrefs.preferred_religions.length > 0) {
    if (!candidateProfile.religion || !myPrefs.preferred_religions.includes(candidateProfile.religion)) {
      return -1;
    }
  }

  if (myPrefs.preferred_marital_statuses && myPrefs.preferred_marital_statuses.length > 0) {
    if (!candidateProfile.marital_status || !myPrefs.preferred_marital_statuses.includes(candidateProfile.marital_status)) {
      return -1;
    }
  }

  if (myPrefs.accept_has_children === false && candidateProfile.has_children === true) {
    return -1;
  }

  if (myPrefs.wants_children === true && candidateProfile.wants_children === false) {
    return -1;
  }

  // -------- Soft scoring (same as before) --------

  // Age closeness
  if (candidateAge != null && myPrefs.min_age != null && myPrefs.max_age != null) {
    const mid = (myPrefs.min_age + myPrefs.max_age) / 2;
    const diff = Math.abs(candidateAge - mid);
    score += Math.max(0, 20 - diff); // up to 20 points
  }

  // Same country / preferred countries
  if (myPrefs.preferred_countries && myPrefs.preferred_countries.length > 0) {
    if (candidateProfile.country && myPrefs.preferred_countries.includes(candidateProfile.country)) {
      score += 15;
    }
  } else if (myProfile.country && candidateProfile.country && myProfile.country === candidateProfile.country) {
    score += 10;
  }

  // Same city
  if (myProfile.city && candidateProfile.city && myProfile.city === candidateProfile.city) {
    score += 10;
  }

  // Same religion / sect
  if (myProfile.religion && candidateProfile.religion && myProfile.religion === candidateProfile.religion) {
    score += 10;
  }
  if (myProfile.sect && candidateProfile.sect && myProfile.sect === candidateProfile.sect) {
    score += 5;
  }

  // Interests overlap
  const myInterests = myProfile.interests || [];
  const candInterests = candidateProfile.interests || [];
  if (myInterests.length > 0 && candInterests.length > 0) {
    const overlap = myInterests.filter((i) => candInterests.includes(i));
    score += overlap.length * 3;
  }

  // Languages overlap
  const myLangs = myProfile.languages || [];
  const candLangs = candidateProfile.languages || [];
  if (myLangs.length > 0 && candLangs.length > 0) {
    const overlapLang = myLangs.filter((l) => candLangs.includes(l));
    score += overlapLang.length * 2;
  }

  return score;
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

// ---------- Profile endpoints ----------

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

    if (gender && !['male', 'female'].includes(gender)) {
      return res.status(400).json({ error: 'gender must be "male" or "female"' });
    }

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

// Create a presigned URL for uploading a profile photo
app.post('/photos/presign', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });
  if (!s3Enabled) return res.status(503).json({ error: 'S3 not configured' });

  try {
    const userId = req.user.id;

    const { contentType, bytes } = req.body;
    if (!contentType || typeof contentType !== 'string') {
      return res.status(400).json({ error: 'contentType is required' });
    }

    // Enforce max 6 total photos per user
    const existingCount = await countUserPhotos(userId);
    if (existingCount >= 6) {
      return res.status(400).json({ error: 'Maximum of 6 photos reached' });
    }

    const ext = extFromContentType(contentType);
    const key = `${s3Prefix}${userId}/${crypto.randomUUID()}.${ext}`;

    const cmd = new PutObjectCommand({
      Bucket: s3Bucket,
      Key: key,
      ContentType: contentType,
      // Private bucket; access via presigned GET later
    });

    const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 60 * 5 }); // 5 min

    res.json({
      uploadUrl,
      s3Key: key,
      bucket: s3Bucket,
      expiresInSeconds: 300,
    });
  } catch (e) {
    console.error('Error in POST /photos/presign', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Confirm upload + store metadata in DB
app.post('/photos/confirm', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });
  if (!s3Enabled) return res.status(503).json({ error: 'S3 not configured' });

  try {
    const userId = req.user.id;
    const { s3Key, contentType, bytes } = req.body;

    if (!s3Key || typeof s3Key !== 'string') {
      return res.status(400).json({ error: 's3Key is required' });
    }

    // Enforce max 6 total photos per user
    const existingCount = await countUserPhotos(userId);
    if (existingCount >= 6) {
      return res.status(400).json({ error: 'Maximum of 6 photos reached' });
    }

    const inserted = await pool.query(
      `
      INSERT INTO user_photos (user_id, s3_key, content_type, bytes, is_primary)
      VALUES ($1, $2, $3, $4,
        CASE WHEN (SELECT COUNT(*) FROM user_photos WHERE user_id = $1) = 0 THEN TRUE ELSE FALSE END
      )
      RETURNING id, user_id, s3_key, content_type, bytes, is_primary, created_at;
      `,
      [userId, s3Key, contentType || null, Number.isFinite(bytes) ? bytes : null]
    );

    await ensurePrimaryIfNone(userId);

    res.status(201).json({ photo: inserted.rows[0] });
  } catch (e) {
    console.error('Error in POST /photos/confirm', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// List my photos (returns presigned GET URLs)
app.get('/me/photos', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });
  if (!s3Enabled) return res.status(503).json({ error: 'S3 not configured' });

  try {
    const userId = req.user.id;

    const r = await pool.query(
      `
      SELECT id, user_id, s3_key, content_type, bytes, is_primary, created_at
      FROM user_photos
      WHERE user_id = $1
      ORDER BY is_primary DESC, created_at DESC, id DESC;
      `,
      [userId]
    );

    const photos = await Promise.all(
      r.rows.map(async (row) => {
        const cmd = new GetObjectCommand({
          Bucket: s3Bucket,
          Key: row.s3_key,
        });

        const url = await getSignedUrl(s3, cmd, { expiresIn: 60 * 10 }); // 10 min

        return {
          id: row.id,
          userId: row.user_id,
          s3Key: row.s3_key,
          contentType: row.content_type,
          bytes: row.bytes,
          isPrimary: row.is_primary,
          createdAt: row.created_at,
          url,
        };
      })
    );

    res.json({ photos });
  } catch (e) {
    console.error('Error in GET /me/photos', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Set a photo as my primary photo
app.post('/photos/:photoId/primary', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  try {
    const userId = req.user.id;
    const photoId = Number.parseInt(req.params.photoId, 10);
    if (!Number.isFinite(photoId)) return res.status(400).json({ error: 'Invalid photoId' });

    // Ensure the photo belongs to this user
    const owned = await pool.query(
      `SELECT id FROM user_photos WHERE id = $1 AND user_id = $2`,
      [photoId, userId]
    );
    if (owned.rowCount === 0) {
      return res.status(404).json({ error: 'Photo not found' });
    }

    await pool.query('BEGIN');

    // Clear existing primary
    await pool.query(
      `UPDATE user_photos SET is_primary = FALSE WHERE user_id = $1`,
      [userId]
    );

    // Set selected
    const updated = await pool.query(
      `UPDATE user_photos SET is_primary = TRUE WHERE id = $1 AND user_id = $2
       RETURNING id, user_id, s3_key, content_type, bytes, is_primary, created_at;`,
      [photoId, userId]
    );

    await pool.query('COMMIT');

    res.json({ photo: updated.rows[0] });
  } catch (e) {
    try { await pool.query('ROLLBACK'); } catch (_) {}
    console.error('Error in POST /photos/:photoId/primary', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});


 // Get my preferences
app.get('/me/preferences', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled' });
  }



// Update my preferences


   
  
    const {
      preferredGender,
      minAge,
      maxAge,
      preferredReligions,
      preferredSects,
      preferredMaritalStatuses,
      acceptHasChildren,
      wantsChildren,
      maxDistanceKm,
      preferredCountries,
      preferredCities,
    } = req.body;

    // Validate preferredGender if provided
    

    // -------- 18+ BACKEND GUARD --------
    const minAgeNum =
      minAge === undefined || minAge === null ? null : Number(minAge);
    const maxAgeNum =
      maxAge === undefined || maxAge === null ? null : Number(maxAge);

    if (minAgeNum !== null && !Number.isInteger(minAgeNum)) {
      return res.status(400).json({ error: 'minAge must be a number' });
    }
    if (maxAgeNum !== null && !Number.isInteger(maxAgeNum)) {
      return res.status(400).json({ error: 'maxAge must be a number' });
    }

    if (minAgeNum !== null && minAgeNum < 18) {
      return res.status(400).json({ error: 'minAge must be at least 18' });
    }
    if (maxAgeNum !== null && maxAgeNum < 18) {
      return res.status(400).json({ error: 'maxAge must be at least 18' });
    }

    let finalMinAge = minAgeNum;
    let finalMaxAge = maxAgeNum;

    if (
      finalMinAge !== null &&
      finalMaxAge !== null &&
      finalMaxAge < finalMinAge
    ) {
      finalMaxAge = finalMinAge;
    }

    // Normalize arrays
    const religionsArr = Array.isArray(preferredReligions) ? preferredReligions : null;
    const sectsArr = Array.isArray(preferredSects) ? preferredSects : null;
    const maritalArr = Array.isArray(preferredMaritalStatuses) ? preferredMaritalStatuses : null;
    const countriesArr = Array.isArray(preferredCountries) ? preferredCountries : null;
    const citiesArr = Array.isArray(preferredCities) ? preferredCities : null;

    const result = await pool.query(
      `
      INSERT INTO preferences (
        user_id,
        preferred_gender,
        min_age,
        max_age,
        preferred_religions,
        preferred_sects,
        preferred_marital_statuses,
        accept_has_children,
        wants_children,
        max_distance_km,
        preferred_countries,
        preferred_cities,
        created_at,
        updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, $9, $10, $11, $12, NOW(), NOW()
      )
      ON CONFLICT (user_id) DO UPDATE SET
        preferred_gender = EXCLUDED.preferred_gender,
        min_age = EXCLUDED.min_age,
        max_age = EXCLUDED.max_age,
        preferred_religions = EXCLUDED.preferred_religions,
        preferred_sects = EXCLUDED.preferred_sects,
        preferred_marital_statuses = EXCLUDED.preferred_marital_statuses,
        accept_has_children = EXCLUDED.accept_has_children,
        wants_children = EXCLUDED.wants_children,
        max_distance_km = EXCLUDED.max_distance_km,
        preferred_countries = EXCLUDED.preferred_countries,
        preferred_cities = EXCLUDED.preferred_cities,
        updated_at = NOW()
      RETURNING *;
      `,
      [
        req.user.id,
        preferredGender || null,
        finalMinAge,
        finalMaxAge,
        religionsArr,
        sectsArr,
        maritalArr,
        typeof acceptHasChildren === 'boolean' ? acceptHasChildren : null,
        typeof wantsChildren === 'boolean' ? wantsChildren : null,
        typeof maxDistanceKm === 'number' ? maxDistanceKm : null,
        countriesArr,
        citiesArr,
      ]
    );

    res.json({ preferences: mapPreferencesRow(result.rows[0]) });
 
    console.error('Error in PUT /me/preferences', err);
    res.status(500).json({ error: 'Internal server error' });
  



  try {


    // We no longer use preferredGender for matching,
    // but if it comes in, keep it limited to male/female
    if (preferredGender && !['male', 'female'].includes(preferredGender)) {
      return res.status(400).json({ error: 'preferredGender must be "male" or "female"' });
    }

    // -------- 18+ BACKEND GUARD ON AGE PREFERENCES --------
    // Normalize to numbers if they came as strings
    const minAgeNum =
  minAge === undefined || minAge === null
    ? null
    : Number(minAge);

const maxAgeNum =
  maxAge === undefined || maxAge === null
    ? null
    : Number(maxAge);

// Reject non-numeric values
if (minAgeNum !== null && !Number.isInteger(minAgeNum)) {
  return res.status(400).json({ error: 'minAge must be a number' });
}
if (maxAgeNum !== null && !Number.isInteger(maxAgeNum)) {
  return res.status(400).json({ error: 'maxAge must be a number' });
}

// 🔒 HARD 18+ ENFORCEMENT
if (minAgeNum !== null && minAgeNum < 18) {
  return res.status(400).json({ error: 'minAge must be at least 18' });
}
if (maxAgeNum !== null && maxAgeNum < 18) {
  return res.status(400).json({ error: 'maxAge must be at least 18' });
}

// Normalize min/max
let finalMinAge = minAgeNum;
let finalMaxAge = maxAgeNum;

if (
  finalMinAge !== null &&
  finalMaxAge !== null &&
  finalMaxAge < finalMinAge
) {
  finalMaxAge = finalMinAge;
}


    // Prepare arrays
    const religionsArr = Array.isArray(preferredReligions) ? preferredReligions : null;
    const sectsArr = Array.isArray(preferredSects) ? preferredSects : null;
    const maritalArr = Array.isArray(preferredMaritalStatuses) ? preferredMaritalStatuses : null;
    const countriesArr = Array.isArray(preferredCountries) ? preferredCountries : null;
    const citiesArr = Array.isArray(preferredCities) ? preferredCities : null;

    const result = await pool.query(
      `
      INSERT INTO preferences (
        user_id,
        preferred_gender,
        min_age,
        max_age,
        preferred_religions,
        preferred_sects,
        preferred_marital_statuses,
        accept_has_children,
        wants_children,
        max_distance_km,
        preferred_countries,
        preferred_cities,
        created_at,
        updated_at
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8, $9, $10, $11, $12, NOW(), NOW()
      )
      ON CONFLICT (user_id) DO UPDATE SET
        preferred_gender = EXCLUDED.preferred_gender,
        min_age = EXCLUDED.min_age,
        max_age = EXCLUDED.max_age,
        preferred_religions = EXCLUDED.preferred_religions,
        preferred_sects = EXCLUDED.preferred_sects,
        preferred_marital_statuses = EXCLUDED.preferred_marital_statuses,
        accept_has_children = EXCLUDED.accept_has_children,
        wants_children = EXCLUDED.wants_children,
        max_distance_km = EXCLUDED.max_distance_km,
        preferred_countries = EXCLUDED.preferred_countries,
        preferred_cities = EXCLUDED.preferred_cities,
        updated_at = NOW()
      RETURNING *;
      `,
    
    );

    const prefs = result.rows[0];
    res.json({ preferences: mapPreferencesRow(prefs) });
  } catch (err) {
    console.error('Error in PUT /me/preferences', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// ---------- Likes / Passes / Matches endpoints ----------

// Like someone
app.post('/swipes/like', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const { targetUserId } = req.body;
    const currentUserId = req.user.id;

    if (!targetUserId || typeof targetUserId !== 'number') {
      return res.status(400).json({ error: 'targetUserId (number) is required' });
    }

    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: 'You cannot like yourself' });
    }

    // Ensure target user exists
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [targetUserId]
    );
    if (userCheck.rowCount === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Record the like (ignore if already liked)
    await pool.query(
      `
      INSERT INTO likes (liker_id, liked_id)
      VALUES ($1, $2)
      ON CONFLICT (liker_id, liked_id) DO NOTHING;
      `,
      [currentUserId, targetUserId]
    );

    // Check if the other user already liked this user (mutual like)
    const mutual = await pool.query(
      'SELECT 1 FROM likes WHERE liker_id = $1 AND liked_id = $2',
      [targetUserId, currentUserId]
    );

    let isMatch = false;
    let matchId = null;

    if (mutual.rowCount > 0) {
      const user1 = Math.min(currentUserId, targetUserId);
      const user2 = Math.max(currentUserId, targetUserId);

      const matchResult = await pool.query(
        `
        INSERT INTO matches (user1_id, user2_id)
        VALUES ($1, $2)
        ON CONFLICT (user1_id, user2_id) DO UPDATE SET user1_id = matches.user1_id
        RETURNING id, created_at;
        `,
        [user1, user2]
      );

      isMatch = true;
      matchId = matchResult.rows[0].id;
    }

    res.json({
      status: 'liked',
      isMatch,
      matchId,
    });
  } catch (err) {
    console.error('Error in POST /swipes/like', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Pass on someone
app.post('/swipes/pass', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  try {
    const { targetUserId } = req.body;
    const currentUserId = req.user.id;

    if (!targetUserId || typeof targetUserId !== 'number') {
      return res.status(400).json({ error: 'targetUserId (number) is required' });
    }

    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: 'You cannot pass on yourself' });
    }

    // Ensure target user exists
    const userCheck = await pool.query(
      'SELECT id FROM users WHERE id = $1',
      [targetUserId]
    );
    if (userCheck.rowCount === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }

    // Record the pass (ignore if already passed)
    await pool.query(
      `
      INSERT INTO passes (user_id, target_user_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id, target_user_id) DO NOTHING;
      `,
      [currentUserId, targetUserId]
    );

    res.json({ status: 'passed' });
  } catch (err) {
    console.error('Error in POST /swipes/pass', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get my matches (no conversations here)
app.get('/matches', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled' });
  }

  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT
        m.id AS match_id,
        m.created_at AS matched_at,
        CASE
          WHEN m.user1_id = $1 THEN m.user2_id
          ELSE m.user1_id
        END AS other_user_id,
        u.full_name AS other_full_name
      FROM matches m
      JOIN users u
        ON u.id = CASE
          WHEN m.user1_id = $1 THEN m.user2_id
          ELSE m.user1_id
        END
      WHERE m.user1_id = $1 OR m.user2_id = $1
      ORDER BY m.created_at DESC;
      `,
      [userId]
    );

    res.json({
      matches: result.rows.map(r => ({
        matchId: r.match_id,
        matchedAt: r.matched_at,
        user: {
          id: r.other_user_id,
          fullName: r.other_full_name
        }
      }))
    });
  } catch (e) {
    console.error('Error in GET /matches', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.get('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  try {
    const userId = req.user.id;
    const matchId = Number.parseInt(req.params.matchId, 10);
    if (!Number.isFinite(matchId)) return res.status(400).json({ error: 'Invalid matchId' });

    const ok = await userIsInMatch(userId, matchId);
    if (!ok) return res.status(403).json({ error: 'Not allowed' });

    const conversationId = await getOrCreateConversation(matchId);

    const msgs = await pool.query(
      `
      SELECT id, sender_id, body, created_at
      FROM messages
      WHERE conversation_id = $1
      ORDER BY created_at ASC
      LIMIT 200;
      `,
      [conversationId]
    );

    res.json({ matchId, conversationId, messages: msgs.rows });
  } catch (e) {
    console.error('Error in GET /matches/:matchId/messages', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  if (!dbEnabled) return res.status(503).json({ error: 'Database not enabled' });

  try {
    const userId = req.user.id;
    const matchId = Number.parseInt(req.params.matchId, 10);
    if (!Number.isFinite(matchId)) return res.status(400).json({ error: 'Invalid matchId' });

    const { body } = req.body;
    if (!body || typeof body !== 'string' || body.trim().length === 0) {
      return res.status(400).json({ error: 'Message body is required' });
    }
    if (body.length > 2000) {
      return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
    }

    const ok = await userIsInMatch(userId, matchId);
    if (!ok) return res.status(403).json({ error: 'Not allowed' });

    const conversationId = await getOrCreateConversation(matchId);

    // Entitlement check
    const ent = await getEntitlement(userId);

    if (!ent.isPremium) {
      // Free users: allow only 1 message PER MATCH total (their first message)
      const count = await pool.query(
        `
        SELECT COUNT(*)::int AS cnt
        FROM messages
        WHERE conversation_id = $1 AND sender_id = $2
        `,
        [conversationId, userId]
      );

      if (count.rows[0].cnt >= 1) {
        return res.status(402).json({
          error: 'Upgrade required: free members can only send 1 message per match.',
          code: 'UPGRADE_REQUIRED'
        });
      }
    }

    const inserted = await pool.query(
      `
      INSERT INTO messages (conversation_id, sender_id, body)
      VALUES ($1, $2, $3)
      RETURNING id, sender_id, body, created_at;
      `,
      [conversationId, userId, body.trim()]
    );

    res.status(201).json({
      matchId,
      conversationId,
      message: inserted.rows[0],
      entitlement: ent
    });
  } catch (e) {
    console.error('Error in POST /matches/:matchId/messages', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Get messages


// Send message



// ---------- Suggestions endpoint (matching engine) ----------

app.get('/suggestions', authMiddleware, async (req, res) => {
  if (!dbEnabled) {
    return res.status(503).json({ error: 'Database not enabled in this environment' });
  }

  const currentUserId = req.user.id;
  const limit = Number.parseInt(req.query.limit || '20', 10);

  try {
    // Load my profile & preferences
    const [profileResult, prefsResult] = await Promise.all([
      pool.query('SELECT * FROM profiles WHERE user_id = $1', [currentUserId]),
      pool.query('SELECT * FROM preferences WHERE user_id = $1', [currentUserId]),
    ]);

    const myProfileRow = profileResult.rows[0];
    const myPrefsRow = prefsResult.rows[0];

    if (!myProfileRow) {
      return res.status(400).json({ error: 'Profile not set. Please complete your profile first.' });
    }
    if (!myPrefsRow) {
      return res.status(400).json({ error: 'Preferences not set. Please set your preferences first.' });
    }

    const myProfile = myProfileRow;
    const myPrefs = myPrefsRow;

    // Get candidate users with profiles, excluding:
    // - myself
    // - users I've already liked
    // - users I've already passed
    const candidatesResult = await pool.query(
      `
      SELECT
        u.id AS user_id,
        u.email,
        u.full_name,
        p.*
      FROM users u
      JOIN profiles p ON p.user_id = u.id
      WHERE u.id != $1
        AND NOT EXISTS (
          SELECT 1 FROM likes l
          WHERE l.liker_id = $1 AND l.liked_id = u.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM passes ps
          WHERE ps.user_id = $1 AND ps.target_user_id = u.id
        );
      `,
      [currentUserId]
    );

    const candidates = candidatesResult.rows;

    const scored = candidates
      .map((row) => {
        const candidateProfile = row;
        const score = computeMatchScore(myProfile, myPrefs, candidateProfile);
        return { row, score };
      })
      .filter((item) => item.score >= 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);

    const suggestions = scored.map(({ row, score }) => ({
      userId: row.user_id,
      fullName: row.full_name,
      // email intentionally omitted for privacy
      gender: row.gender,
      age: computeAge(row.date_of_birth),
      country: row.country,
      city: row.city,
      religion: row.religion,
      sect: row.sect,
      maritalStatus: row.marital_status,
      hasChildren: row.has_children,
      wantsChildren: row.wants_children,
      interests: row.interests || [],
      languages: row.languages || [],
      bio: row.bio,
      matchScore: score,
    }));

    res.json({ suggestions });
  } catch (err) {
    console.error('Error in GET /suggestions', err);
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
