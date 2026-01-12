// index.js - YahHabibi backend (clean rebuild)
// Node.js + Express + Postgres + AWS S3 (presigned upload + presigned GET)

'use strict';

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// AWS SDK v3
const { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// -------------------- ENV --------------------
const port = Number.parseInt(process.env.PORT || '8080', 10);

const jwtSecret = process.env.JWT_SECRET || '';
const nodeEnv = process.env.NODE_ENV || 'development';

const dbUrl = process.env.DATABASE_URL || '';
const dbEnabled = !!dbUrl;

const awsRegion = (process.env.AWS_REGION || '').trim();          // must be like "us-east-2"
const s3Bucket = (process.env.AWS_S3_BUCKET || process.env.S3_BUCKET || 'yahhabibi-photos-prod').trim();
const s3Enabled = !!awsRegion && !!s3Bucket;

// Optional: allow forcing SSL verification behavior
// - If DATABASE_CA_CERT is present, we default to rejectUnauthorized=true
// - If not present, we default to rejectUnauthorized=false (to avoid SELF_SIGNED_CERT issues on managed DB)
const caCertRaw = (process.env.DATABASE_CA_CERT || '').trim();
const caCert = caCertRaw ? caCertRaw.replace(/\\n/g, '\n') : '';
const sslRejectUnauthorized =
  process.env.DB_SSL_REJECT_UNAUTHORIZED
    ? String(process.env.DB_SSL_REJECT_UNAUTHORIZED).toLowerCase() === 'true'
    : (caCert ? true : false);

if (!jwtSecret) {
  console.warn('WARNING: JWT_SECRET is not set. Auth will fail.');
}

if (s3Enabled && !/^[a-z0-9-]+$/.test(awsRegion)) {
  console.warn(`WARNING: AWS_REGION looks invalid: "${awsRegion}". It must be like "us-east-2".`);
}

// -------------------- DB --------------------
let pool = null;

if (dbEnabled) {
  pool = new Pool({
    connectionString: dbUrl,
    ssl: {
      rejectUnauthorized: sslRejectUnauthorized,
      ...(caCert ? { ca: caCert } : {}),
    },
  });
}

// -------------------- S3 (SINGLE DECLARATION) --------------------
const s3Client = (s3Enabled)
  ? new S3Client({ region: awsRegion })
  : null;

// -------------------- HELPERS --------------------
function requireDb(req, res) {
  if (!dbEnabled || !pool) {
    res.status(503).json({ error: 'Database not enabled in this environment' });
    return false;
  }
  return true;
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const parts = h.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const payload = jwt.verify(parts[1], jwtSecret);
    req.user = { id: payload.userId, email: payload.email };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function generateToken(user) {
  if (!jwtSecret) throw new Error('JWT_SECRET is not configured');
  return jwt.sign(
    { userId: user.id, email: user.email },
    jwtSecret,
    { expiresIn: '7d' }
  );
}

function computeAge(dob) {
  if (!dob) return null;
  const birth = new Date(dob);
  const now = new Date();
  let age = now.getUTCFullYear() - birth.getUTCFullYear();
  const m = now.getUTCMonth() - birth.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < birth.getUTCDate())) age--;
  return age;
}

// Simple match scoring (safe + deterministic)
function computeMatchScore(myProfile, myPrefs, candidateProfile) {
  let score = 0;

  // Hard filters
  const age = computeAge(candidateProfile.date_of_birth);
  if (age !== null) {
    if (myPrefs.min_age !== null && age < myPrefs.min_age) return -1;
    if (myPrefs.max_age !== null && age > myPrefs.max_age) return -1;
  }

  // Preferences arrays
  const prefReligions = myPrefs.preferred_religions || null;
  const prefSects = myPrefs.preferred_sects || null;
  const prefMarital = myPrefs.preferred_marital_statuses || null;
  const prefCountries = myPrefs.preferred_countries || null;
  const prefCities = myPrefs.preferred_cities || null;

  // Boosts
  if (prefReligions && candidateProfile.religion && prefReligions.includes(candidateProfile.religion)) score += 20;
  if (prefSects && candidateProfile.sect && prefSects.includes(candidateProfile.sect)) score += 10;
  if (prefMarital && candidateProfile.marital_status && prefMarital.includes(candidateProfile.marital_status)) score += 10;

  if (prefCountries && candidateProfile.country && prefCountries.includes(candidateProfile.country)) score += 10;
  if (prefCities && candidateProfile.city && prefCities.includes(candidateProfile.city)) score += 10;

  // Children preference
  if (myPrefs.accept_has_children === true) score += 5;
  if (myPrefs.accept_has_children === false && candidateProfile.has_children === true) return -1;

  // Wants children (if set on prefs)
  if (typeof myPrefs.wants_children === 'boolean') {
    if (typeof candidateProfile.wants_children === 'boolean' && myPrefs.wants_children === candidateProfile.wants_children) score += 5;
  }

  // Similar interests boost
  const myInterests = Array.isArray(myProfile.interests) ? myProfile.interests : [];
  const theirInterests = Array.isArray(candidateProfile.interests) ? candidateProfile.interests : [];
  const common = myInterests.filter(x => theirInterests.includes(x)).length;
  score += Math.min(common * 3, 15);

  // Small base score so list isn't all zeros
  score += 5;

  return score;
}

async function getEntitlement(userId) {
  const r = await pool.query(
    `SELECT user_id, is_premium, tier, expires_at
     FROM user_entitlements
     WHERE user_id = $1`,
    [userId]
  );

  if (r.rowCount === 0) {
    return { userId, isPremium: false, tier: null, expiresAt: null };
  }

  const row = r.rows[0];
  const expiresAt = row.expires_at ? new Date(row.expires_at) : null;
  const active = row.is_premium === true && (!expiresAt || expiresAt.getTime() > Date.now());

  return {
    userId,
    isPremium: active,
    tier: row.tier || null,
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  };
}

// Photos helpers
async function countPhotos(userId) {
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
      SELECT id
      FROM user_photos
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

function safeNowIso() {
  return new Date().toISOString();
}

async function presignPutPhotoUrl(s3Key, contentType) {
  if (!s3Client) return null;
  const cmd = new PutObjectCommand({
    Bucket: s3Bucket,
    Key: s3Key,
    ContentType: contentType || 'application/octet-stream',
  });
  return await getSignedUrl(s3Client, cmd, { expiresIn: 300 }); // 5 minutes
}

async function presignGetPhotoUrl(s3Key) {
  if (!s3Client) return null;
  if (!s3Key) return null;

  const cmd = new GetObjectCommand({
    Bucket: s3Bucket,
    Key: s3Key,
  });
  return await getSignedUrl(s3Client, cmd, { expiresIn: 600 }); // 10 minutes
}

async function headObjectExists(s3Key) {
  if (!s3Client) return false;
  try {
    const cmd = new HeadObjectCommand({ Bucket: s3Bucket, Key: s3Key });
    await s3Client.send(cmd);
    return true;
  } catch (_) {
    return false;
  }
}

// -------------------- TABLES --------------------
async function ensureTables() {
  // Create tables if missing. Safe to run repeatedly.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      gender TEXT,
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

    CREATE TABLE IF NOT EXISTS preferences (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      preferred_gender TEXT,
      min_age INTEGER,
      max_age INTEGER,
      preferred_religions TEXT[],
      preferred_sects TEXT[],
      preferred_marital_statuses TEXT[],
      accept_has_children BOOLEAN,
      wants_children BOOLEAN,
      max_distance_km NUMERIC,
      preferred_countries TEXT[],
      preferred_cities TEXT[],
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS likes (
      liker_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      liked_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (liker_id, liked_id)
    );

    CREATE TABLE IF NOT EXISTS passes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, target_user_id)
    );

    CREATE TABLE IF NOT EXISTS matches (
      id SERIAL PRIMARY KEY,
      user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user1_id, user2_id)
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      match_id INTEGER UNIQUE REFERENCES matches(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_entitlements (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      is_premium BOOLEAN NOT NULL DEFAULT FALSE,
      tier TEXT,
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_photos (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      s3_key TEXT NOT NULL,
      content_type TEXT,
      bytes INTEGER,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, s3_key)
    );

    CREATE INDEX IF NOT EXISTS idx_user_photos_user_primary ON user_photos(user_id, is_primary);
  `);
}

// Conversation helpers
async function userIsInMatch(userId, matchId) {
  const r = await pool.query(
    `SELECT 1 FROM matches
     WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)`,
    [matchId, userId]
  );
  return r.rowCount > 0;
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

// -------------------- ROUTES --------------------
app.get('/health', async (req, res) => {
  if (!dbEnabled || !pool) {
    return res.json({ status: 'ok', dbTime: null });
  }
  try {
    const r = await pool.query('SELECT NOW() AS now');
    return res.json({ status: 'ok', dbTime: r.rows[0].now });
  } catch (e) {
    return res.status(500).json({ status: 'error', error: 'DB check failed' });
  }
});

// Auth
app.post('/auth/register', async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const { email, password, fullName } = req.body || {};
    if (!email || typeof email !== 'string') return res.status(400).json({ error: 'email is required' });
    if (!password || typeof password !== 'string' || password.length < 6) return res.status(400).json({ error: 'password must be at least 6 chars' });
    if (!fullName || typeof fullName !== 'string') return res.status(400).json({ error: 'fullName is required' });

    const hash = await bcrypt.hash(password, 10);
    const created = await pool.query(
      `INSERT INTO users (email, password_hash, full_name)
       VALUES ($1, $2, $3)
       RETURNING id, email, full_name, created_at`,
      [email.toLowerCase(), hash, fullName]
    );

    const user = created.rows[0];
    const token = generateToken({ id: user.id, email: user.email });

    res.status(201).json({
      user: { id: user.id, email: user.email, fullName: user.full_name, createdAt: user.created_at },
      token,
    });
  } catch (e) {
    if (String(e.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    console.error('Error in POST /auth/register', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const { email, password } = req.body || {};
    if (!email || typeof email !== 'string') return res.status(400).json({ error: 'email is required' });
    if (!password || typeof password !== 'string') return res.status(400).json({ error: 'password is required' });

    const r = await pool.query(
      `SELECT id, email, password_hash, full_name, created_at
       FROM users
       WHERE email = $1`,
      [email.toLowerCase()]
    );

    if (r.rowCount === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken({ id: user.id, email: user.email });

    res.json({
      user: { id: user.id, email: user.email, fullName: user.full_name, createdAt: user.created_at },
      token,
    });
  } catch (e) {
    console.error('Error in POST /auth/login', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/me', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const r = await pool.query(
      `SELECT id, email, full_name, created_at FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'User not found' });
    const u = r.rows[0];
    res.json({ id: u.id, email: u.email, fullName: u.full_name, createdAt: u.created_at });
  } catch (e) {
    console.error('Error in GET /me', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Profile
app.get('/me/profile', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const r = await pool.query(`SELECT * FROM profiles WHERE user_id = $1`, [req.user.id]);
    res.json({ profile: r.rows[0] || null });
  } catch (e) {
    console.error('Error in GET /me/profile', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/me/profile', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const {
      gender, dateOfBirth, country, city, religion, sect, maritalStatus,
      hasChildren, wantsChildren, educationLevel, occupation, incomeRange,
      languages, bio, interests
    } = req.body || {};

    const languagesArr = Array.isArray(languages) ? languages : null;
    const interestsArr = Array.isArray(interests) ? interests : null;

    const r = await pool.query(
      `
      INSERT INTO profiles (
        user_id, gender, date_of_birth, country, city, religion, sect, marital_status,
        has_children, wants_children, education_level, occupation, income_range,
        languages, bio, interests, created_at, updated_at
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,
        $9,$10,$11,$12,$13,
        $14,$15,$16,NOW(),NOW()
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

    res.json({ profile: r.rows[0] });
  } catch (e) {
    console.error('Error in PUT /me/profile', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Preferences
app.get('/me/preferences', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const r = await pool.query(`SELECT * FROM preferences WHERE user_id = $1`, [req.user.id]);
    res.json({ preferences: r.rows[0] || null });
  } catch (e) {
    console.error('Error in GET /me/preferences', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/me/preferences', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
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
      preferredCities
    } = req.body || {};

    // preferredGender validation (optional)
    if (preferredGender && !['male', 'female'].includes(preferredGender)) {
      return res.status(400).json({ error: 'preferredGender must be "male" or "female"' });
    }

    // 18+ hard enforcement on age prefs
    const minAgeNum = (minAge === undefined || minAge === null) ? null : Number(minAge);
    const maxAgeNum = (maxAge === undefined || maxAge === null) ? null : Number(maxAge);

    if (minAgeNum !== null && !Number.isInteger(minAgeNum)) return res.status(400).json({ error: 'minAge must be a number' });
    if (maxAgeNum !== null && !Number.isInteger(maxAgeNum)) return res.status(400).json({ error: 'maxAge must be a number' });

    if (minAgeNum !== null && minAgeNum < 18) return res.status(400).json({ error: 'minAge must be at least 18' });
    if (maxAgeNum !== null && maxAgeNum < 18) return res.status(400).json({ error: 'maxAge must be at least 18' });

    let finalMinAge = minAgeNum;
    let finalMaxAge = maxAgeNum;
    if (finalMinAge !== null && finalMaxAge !== null && finalMaxAge < finalMinAge) {
      finalMaxAge = finalMinAge;
    }

    const religionsArr = Array.isArray(preferredReligions) ? preferredReligions : null;
    const sectsArr = Array.isArray(preferredSects) ? preferredSects : null;
    const maritalArr = Array.isArray(preferredMaritalStatuses) ? preferredMaritalStatuses : null;
    const countriesArr = Array.isArray(preferredCountries) ? preferredCountries : null;
    const citiesArr = Array.isArray(preferredCities) ? preferredCities : null;

    const maxDist = (typeof maxDistanceKm === 'number') ? maxDistanceKm : null;

    const r = await pool.query(
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
        $1,$2,$3,$4,$5,$6,$7,
        $8,$9,$10,$11,$12,
        NOW(),NOW()
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
        maxDist,
        countriesArr,
        citiesArr
      ]
    );

    res.json({ preferences: r.rows[0] });
  } catch (e) {
    console.error('Error in PUT /me/preferences', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Entitlement
app.get('/me/entitlement', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const ent = await getEntitlement(req.user.id);
    res.json(ent);
  } catch (e) {
    console.error('Error in GET /me/entitlement', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Photos: presign PUT
app.post('/photos/presign', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;
  if (!s3Enabled || !s3Client) return res.status(503).json({ error: 'S3 not configured' });

  try {
    const userId = req.user.id;
    const { contentType, bytes } = req.body || {};

    const ct = (typeof contentType === 'string' && contentType.trim()) ? contentType.trim() : 'application/octet-stream';
    const size = Number.isFinite(Number(bytes)) ? Number(bytes) : null;

    // Max photos = 6
    const cnt = await countPhotos(userId);
    if (cnt >= 6) return res.status(400).json({ error: 'Maximum of 6 photos reached' });

    // Create key
    const ext = (ct === 'image/png') ? 'png' : 'jpg';
    const uuid = cryptoRandomId();
    const s3Key = `profiles/${userId}/${uuid}.${ext}`;

    const uploadUrl = await presignPutPhotoUrl(s3Key, ct);
    if (!uploadUrl) return res.status(500).json({ error: 'Failed to presign upload URL' });

    res.json({
      uploadUrl,
      s3Key,
      bucket: s3Bucket,
      expiresInSeconds: 300,
      hint: 'Upload with PUT using Content-Type exactly as provided to presign',
      debug: { now: safeNowIso(), region: awsRegion, bucket: s3Bucket }
    });
  } catch (e) {
    console.error('Error in POST /photos/presign', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Photos: confirm (writes DB row)
app.post('/photos/confirm', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const userId = req.user.id;
    const { s3Key, contentType, bytes } = req.body || {};

    if (!s3Key || typeof s3Key !== 'string') {
      return res.status(400).json({ error: 's3Key is required' });
    }

    // Max photos = 6
    const cnt = await countPhotos(userId);
    if (cnt >= 6) return res.status(400).json({ error: 'Maximum of 6 photos reached' });

    // Optional: verify object exists (prevents DB rows for missing objects)
    // If your IAM lacks HeadObject permission, this returns false and we still allow insert.
    let exists = true;
    if (s3Client) {
      const ok = await headObjectExists(s3Key);
      if (!ok) exists = false;
    }

    // Insert row
    const inserted = await pool.query(
      `
      INSERT INTO user_photos (user_id, s3_key, content_type, bytes, is_primary)
      VALUES ($1, $2, $3, $4,
        CASE WHEN (SELECT COUNT(*) FROM user_photos WHERE user_id = $1) = 0 THEN TRUE ELSE FALSE END
      )
      RETURNING id, user_id, s3_key, content_type, bytes, is_primary, created_at;
      `,
      [userId, s3Key, contentType || null, Number.isFinite(Number(bytes)) ? Number(bytes) : null]
    );

    await ensurePrimaryIfNone(userId);

    res.status(201).json({
      photo: inserted.rows[0],
      objectExists: exists
    });
  } catch (e) {
    console.error('Error in POST /photos/confirm', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Photos: list my photos + presigned GET url
app.get('/me/photos', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

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
      r.rows.map(async (row) => ({
        id: row.id,
        userId: row.user_id,
        s3Key: row.s3_key,
        contentType: row.content_type,
        bytes: row.bytes,
        isPrimary: row.is_primary,
        createdAt: row.created_at,
        url: await presignGetPhotoUrl(row.s3_key),
      }))
    );

    res.json({ photos });
  } catch (e) {
    console.error('Error in GET /me/photos', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Photos: set primary
app.post('/photos/:photoId/primary', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  let inTx = false;
  try {
    const userId = req.user.id;
    const photoId = Number.parseInt(req.params.photoId, 10);
    if (!Number.isFinite(photoId)) return res.status(400).json({ error: 'Invalid photoId' });

    const owned = await pool.query(
      `SELECT id FROM user_photos WHERE id = $1 AND user_id = $2`,
      [photoId, userId]
    );
    if (owned.rowCount === 0) return res.status(404).json({ error: 'Photo not found' });

    await pool.query('BEGIN');
    inTx = true;

    await pool.query(`UPDATE user_photos SET is_primary = FALSE WHERE user_id = $1`, [userId]);

    const updated = await pool.query(
      `
      UPDATE user_photos
      SET is_primary = TRUE
      WHERE id = $1 AND user_id = $2
      RETURNING id, user_id, s3_key, content_type, bytes, is_primary, created_at;
      `,
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

// Likes / Passes / Matches
app.post('/swipes/like', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const { targetUserId } = req.body || {};
    const currentUserId = req.user.id;

    if (!targetUserId || typeof targetUserId !== 'number') {
      return res.status(400).json({ error: 'targetUserId (number) is required' });
    }
    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: 'You cannot like yourself' });
    }

    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [targetUserId]);
    if (userCheck.rowCount === 0) return res.status(404).json({ error: 'Target user not found' });

    await pool.query(
      `
      INSERT INTO likes (liker_id, liked_id)
      VALUES ($1, $2)
      ON CONFLICT (liker_id, liked_id) DO NOTHING;
      `,
      [currentUserId, targetUserId]
    );

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

    res.json({ status: 'liked', isMatch, matchId });
  } catch (e) {
    console.error('Error in POST /swipes/like', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/swipes/pass', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const { targetUserId } = req.body || {};
    const currentUserId = req.user.id;

    if (!targetUserId || typeof targetUserId !== 'number') {
      return res.status(400).json({ error: 'targetUserId (number) is required' });
    }
    if (targetUserId === currentUserId) {
      return res.status(400).json({ error: 'You cannot pass on yourself' });
    }

    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [targetUserId]);
    if (userCheck.rowCount === 0) return res.status(404).json({ error: 'Target user not found' });

    await pool.query(
      `
      INSERT INTO passes (user_id, target_user_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id, target_user_id) DO NOTHING;
      `,
      [currentUserId, targetUserId]
    );

    res.json({ status: 'passed' });
  } catch (e) {
    console.error('Error in POST /swipes/pass', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/matches', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  try {
    const userId = req.user.id;

    const result = await pool.query(
      `
      SELECT
        m.id AS match_id,
        m.created_at AS matched_at,
        CASE WHEN m.user1_id = $1 THEN m.user2_id ELSE m.user1_id END AS other_user_id,
        u.full_name AS other_full_name
      FROM matches m
      JOIN users u ON u.id = CASE WHEN m.user1_id = $1 THEN m.user2_id ELSE m.user1_id END
      WHERE m.user1_id = $1 OR m.user2_id = $1
      ORDER BY m.created_at DESC;
      `,
      [userId]
    );

    res.json({
      matches: result.rows.map(r => ({
        matchId: r.match_id,
        matchedAt: r.matched_at,
        user: { id: r.other_user_id, fullName: r.other_full_name }
      }))
    });
  } catch (e) {
    console.error('Error in GET /matches', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/matches/:matchId/messages', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

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
  if (!requireDb(req, res)) return;

  try {
    const userId = req.user.id;
    const matchId = Number.parseInt(req.params.matchId, 10);
    if (!Number.isFinite(matchId)) return res.status(400).json({ error: 'Invalid matchId' });

    const { body } = req.body || {};
    if (!body || typeof body !== 'string' || body.trim().length === 0) {
      return res.status(400).json({ error: 'Message body is required' });
    }
    if (body.length > 2000) {
      return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
    }

    const ok = await userIsInMatch(userId, matchId);
    if (!ok) return res.status(403).json({ error: 'Not allowed' });

    const conversationId = await getOrCreateConversation(matchId);

    const ent = await getEntitlement(userId);

    if (!ent.isPremium) {
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

// Suggestions (Discover)
app.get('/suggestions', authMiddleware, async (req, res) => {
  if (!requireDb(req, res)) return;

  const currentUserId = req.user.id;
  const limit = Number.parseInt(req.query.limit || '20', 10);

  try {
    const [profileResult, prefsResult] = await Promise.all([
      pool.query('SELECT * FROM profiles WHERE user_id = $1', [currentUserId]),
      pool.query('SELECT * FROM preferences WHERE user_id = $1', [currentUserId]),
    ]);

    const myProfileRow = profileResult.rows[0];
    const myPrefsRow = prefsResult.rows[0];

    if (!myProfileRow) return res.status(400).json({ error: 'Profile not set. Please complete your profile first.' });
    if (!myPrefsRow) return res.status(400).json({ error: 'Preferences not set. Please set your preferences first.' });

    const candidatesResult = await pool.query(
      `
      SELECT
        u.id AS user_id,
        u.full_name,
        p.*,
        ph.s3_key AS primary_s3_key
      FROM users u
      JOIN profiles p ON p.user_id = u.id
      LEFT JOIN LATERAL (
        SELECT s3_key
        FROM user_photos
        WHERE user_id = u.id AND is_primary = true
        ORDER BY created_at DESC
        LIMIT 1
      ) ph ON true
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
        const score = computeMatchScore(myProfileRow, myPrefsRow, row);
        return { row, score };
      })
      .filter((item) => item.score >= 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);

    const suggestions = await Promise.all(
      scored.map(async ({ row, score }) => {
        const primaryKey = row.primary_s3_key || null;
        return {
          userId: row.user_id,
          fullName: row.full_name,
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
          matchScore: Number(score.toFixed(1)),
          primaryPhotoKey: primaryKey,
          primaryPhotoUrl: primaryKey ? await presignGetPhotoUrl(primaryKey) : null,
        };
      })
    );

    res.json({ suggestions });
  } catch (e) {
    console.error('Error in GET /suggestions', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Debug: list users (no auth)
app.get('/users', async (req, res) => {
  if (!requireDb(req, res)) return;
  try {
    const result = await pool.query('SELECT id, email, full_name, created_at FROM users ORDER BY id');
    res.json({ value: result.rows });
  } catch (e) {
    console.error('Error in GET /users', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// -------------------- START --------------------
async function start() {
  try {
    if (dbEnabled) {
      await ensureTables();
    }
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (e) {
    console.error('Failed to start server:', e);
    process.exit(1);
  }
}

start();

// -------------------- tiny util --------------------
function cryptoRandomId() {
  // Avoid adding a dependency; good enough for S3 keys
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : ((r & 0x3) | 0x8);
    return v.toString(16);
  });
}
