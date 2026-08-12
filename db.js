import Database from 'better-sqlite3';
import fs from 'fs';

const DB_PATH = process.env.DB_PATH || '/data/inboxiq-mcp.db';
fs.mkdirSync(DB_PATH.substring(0, DB_PATH.lastIndexOf('/')) || '.', { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
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

  -- SMS OTP challenges used during /authorize to prove ownership of the phone number.
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
`);
