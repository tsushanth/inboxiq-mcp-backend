import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

/**
 * Opens (and migrates) the SQLite database. Migrations are strictly additive and
 * idempotent: CREATE ... IF NOT EXISTS, and ALTER TABLE ... ADD COLUMN guarded by
 * PRAGMA table_info. Nothing here deletes or rewrites existing links or tokens.
 */
export function openDb(dbPath) {
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  migrate(db);
  return db;
}

// The schema exactly as shipped before the security hardening (kept verbatim so an
// existing production database and a fresh one converge on the same shape).
const BASE_SCHEMA = `
  -- OAuth clients, created via dynamic client registration (RFC 7591) when Claude
  -- adds InboxIQ as a Connector. No secret — this is a public client using PKCE.
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT,
    redirect_uris TEXT NOT NULL, -- JSON array
    created_at INTEGER NOT NULL
  );

  -- Short-lived authorization codes, single-use, tied to a verified phone number.
  CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );

  -- Access + refresh tokens. Hashed at rest, same pattern as the on-device pairing.
  CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  -- OTP challenges used during /authorize (and phone linking) to prove ownership of the phone number.
  CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    phone_number TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL
  );

  -- The InboxIQ app's own long-lived relay credential, minted on-device and linked to a
  -- phone number here. This is what authenticates the phone's outbound WebSocket to us —
  -- separate from anything Claude ever sees.
  CREATE TABLE IF NOT EXISTS phone_links (
    phone_number TEXT PRIMARY KEY,
    relay_token_hash TEXT NOT NULL,
    linked_at INTEGER NOT NULL,
    last_connected_at INTEGER
  );
`;

// [table, column, definition]. Added only when missing.
const ADDED_COLUMNS = [
  ['phone_links', 'phone_key', 'TEXT'],
  ['phone_links', 'link_proof', 'TEXT'], // NULL/'legacy' = pre-hardening row, 'tofu', 'otp'
  ['access_tokens', 'phone_key', 'TEXT'],
  ['access_tokens', 'grant_id', 'TEXT'],
  ['refresh_tokens', 'phone_key', 'TEXT'],
  ['refresh_tokens', 'grant_id', 'TEXT'],
  ['refresh_tokens', 'expires_at', 'INTEGER'], // NULL = created_at + REFRESH_TTL
  ['refresh_tokens', 'family_started_at', 'INTEGER'], // NULL = created_at
  ['refresh_tokens', 'last_used_at', 'INTEGER'],
  ['refresh_tokens', 'rotated_at', 'INTEGER'],
  ['auth_codes', 'phone_key', 'TEXT'],
  ['otp_challenges', 'phone_key', 'TEXT'],
  ['otp_challenges', 'purpose', "TEXT NOT NULL DEFAULT 'auth'"],
];

const ADDED_TABLES_AND_INDEXES = `
  -- Fixed-window counters backing per-phone / per-IP / global limits (survive restarts).
  CREATE TABLE IF NOT EXISTS rate_counters (
    key TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_phone_links_token ON phone_links (relay_token_hash);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_phone_links_key ON phone_links (phone_key);
  CREATE INDEX IF NOT EXISTS idx_access_tokens_phone ON access_tokens (phone_key);
  CREATE INDEX IF NOT EXISTS idx_access_tokens_grant ON access_tokens (grant_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_phone ON refresh_tokens (phone_key);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_grant ON refresh_tokens (grant_id);
  CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_challenges (phone_key, purpose);
`;

export function migrate(db) {
  db.exec(BASE_SCHEMA);
  for (const [table, column, definition] of ADDED_COLUMNS) {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all();
    if (!cols.some((c) => c.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
  db.exec(ADDED_TABLES_AND_INDEXES);
}

const PHONE_TABLES = ['phone_links', 'access_tokens', 'refresh_tokens', 'auth_codes', 'otp_challenges'];

function getMeta(db, key) {
  return db.prepare('SELECT value FROM meta WHERE key = ?').get(key)?.value;
}
function setMeta(db, key, value) {
  db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
}

/**
 * Fills phone_key for rows that predate it. Additive: phone_number is left untouched.
 * Also records which keying mode the database uses and refuses to start if the mode (or
 * secret) changes, because every existing link would silently stop matching.
 * `keyFn` is makePhoneKeyFn(secret); `secretCheck` is a non-reversible fingerprint of it.
 */
export function backfillPhoneKeys(db, keyFn, { hashed, secretCheck }) {
  const mode = getMeta(db, 'phone_key_mode');
  if (mode === 'hmac' && !hashed) {
    throw new Error('Database uses hashed phone keys but PHONE_HASH_SECRET is not set; refusing to start.');
  }
  if (mode === 'hmac' && getMeta(db, 'phone_secret_check') !== secretCheck) {
    throw new Error('PHONE_HASH_SECRET does not match the one this database was keyed with; refusing to start.');
  }
  const run = db.transaction(() => {
    for (const table of PHONE_TABLES) {
      if (!hashed) {
        db.prepare(`UPDATE ${table} SET phone_key = phone_number WHERE phone_key IS NULL`).run();
      } else {
        const phones = db.prepare(`SELECT DISTINCT phone_number FROM ${table} WHERE phone_key IS NULL`).all();
        const upd = db.prepare(`UPDATE ${table} SET phone_key = ? WHERE phone_number = ? AND phone_key IS NULL`);
        for (const { phone_number } of phones) upd.run(keyFn(phone_number), phone_number);
      }
    }
    if (hashed) {
      setMeta(db, 'phone_key_mode', 'hmac');
      setMeta(db, 'phone_secret_check', secretCheck);
    }
  });
  run();
}

/**
 * Optional, irreversible step (SCRUB_PLAINTEXT_PHONES=1 at boot, hashed mode only):
 * replaces the plaintext phone_number column with the hashed key. After this the previous
 * release can no longer read these rows, so only enable it once rollback is off the table.
 */
export function scrubPlaintextPhones(db) {
  if (getMeta(db, 'phone_key_mode') !== 'hmac') throw new Error('Refusing to scrub: database is not in hashed mode.');
  db.transaction(() => {
    for (const table of PHONE_TABLES) db.prepare(`UPDATE ${table} SET phone_number = phone_key WHERE phone_key IS NOT NULL AND phone_number != phone_key`).run();
  })();
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  db.exec('VACUUM');
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
}
