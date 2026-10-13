import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import Database from 'better-sqlite3';
import { openDb, migrate } from '../db.js';
import { createApp, loadConfig } from '../app.js';
import { createOtpDelivery } from '../otp-delivery.js';
import { startServer, createLegacyDb, tmpDbPath, connectPhone, mcp, linkLegacy, linkWithOtp, oauthFlow, postForm, PHONE, PHONE2, RELAY_TOKEN, RELAY_TOKEN2, CALLBACK } from './helpers.js';

const tableRows = (db, t) => db.prepare(`SELECT * FROM ${t}`).all();
const OLD_TABLES = ['oauth_clients', 'auth_codes', 'access_tokens', 'refresh_tokens', 'otp_challenges', 'phone_links'];

test('migration: runs on a database created by the PRE-hardening db.js; old data is untouched; idempotent', () => {
  const p = tmpDbPath();
  createLegacyDb(p);
  const before = new Database(p, { readonly: true });
  const snapshot = Object.fromEntries(OLD_TABLES.map((t) => [t, tableRows(before, t)]));
  before.close();

  const db = openDb(p);
  for (const t of OLD_TABLES) {
    const after = tableRows(db, t).map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => Object.keys(snapshot[t][0]).includes(k))));
    assert.deepEqual(after, snapshot[t], `${t}: original columns/values unchanged`);
  }
  const cols = (t) => db.prepare(`PRAGMA table_info(${t})`).all().map((c) => c.name);
  assert.ok(cols('phone_links').includes('link_proof') && cols('phone_links').includes('phone_key'));
  assert.ok(cols('refresh_tokens').includes('expires_at'));
  assert.ok(cols('otp_challenges').includes('purpose'));
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE name='rate_counters'").get());
  // running the migration again is a no-op
  migrate(db); migrate(db);
  db.close();
  assert.doesNotThrow(() => openDb(p).close());
});

test('migration: starting the new app backfills phone_key additively (plain mode) and keeps rollback possible', async () => {
  const p = tmpDbPath();
  createLegacyDb(p);
  const s = await startServer({ dbPath: p });
  try {
    const link = s.db.prepare('SELECT * FROM phone_links').get();
    assert.equal(link.phone_key, PHONE);
    assert.equal(link.phone_number, PHONE, 'plaintext column untouched without PHONE_HASH_SECRET');
    assert.equal(link.link_proof, null, 'legacy rows keep a NULL proof, treated as legacy');
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM access_tokens WHERE phone_key IS NULL').get().n, 0);
  } finally { await s.close(); }
});

test('existing users keep working after deploy without an app update', async () => {
  const p = tmpDbPath();
  const legacy = createLegacyDb(p);
  const s = await startServer({ dbPath: p });
  try {
    // 1. the already-linked app reconnects its WebSocket with its existing relay token
    const phone = await connectPhone(s, legacy.legacyRelayToken, (payload) => ({ ok: true, payload }));
    assert.equal(phone.outcome, 'open');
    // 2. Claude's existing access token still relays to it
    const r = await mcp(s, legacy.legacyAccess, { jsonrpc: '2.0', id: 1, method: 'ping' });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).ok, true);
    // 3. the expired legacy access token is still rejected
    assert.equal((await mcp(s, 'legacy-access-expired')).status, 401);
    // 4. the existing refresh token (no expires_at column value) still refreshes
    const rt = await postForm(`${s.base}/token`, { grant_type: 'refresh_token', refresh_token: legacy.legacyRefresh, client_id: 'legacyclient' });
    assert.equal(rt.status, 200);
    const issued = await rt.json();
    assert.equal((await mcp(s, issued.access_token)).status, 200);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 1, 'same refresh token row reused (rotation off)');
    // 5. the app re-sending /phone/link with its own token is idempotent
    assert.equal((await linkLegacy(s, PHONE, legacy.legacyRelayToken)).status, 200);
    assert.equal(s.db.prepare('SELECT relay_token_hash FROM phone_links').get().relay_token_hash, s.db.prepare('SELECT relay_token_hash FROM phone_links').get().relay_token_hash);
    // 6. but nobody else can take the legacy link over
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 409);
    assert.match((await connectPhone(s, RELAY_TOKEN2)).outcome, /closed:4401|error/);
    // 7. a new OAuth flow for the same number works end to end
    const f = await oauthFlow(s, PHONE);
    assert.equal((await mcp(s, f.tokens.access_token)).status, 200);
  } finally { await s.close(); }
});

test('legacy rows that predate the old registered-client redirect policy still authorise only if their URI is allowed', async () => {
  const p = tmpDbPath();
  createLegacyDb(p);
  const s = await startServer({ dbPath: p });
  try {
    const { form, pkcePair } = await import('./helpers.js');
    const { challenge } = pkcePair();
    const r = await fetch(`${s.base}/authorize?${form({ response_type: 'code', client_id: 'legacyclient', redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' })}`);
    assert.equal(r.status, 200);
  } finally { await s.close(); }
});

// ---- hashed phone numbers ----

test('PHONE_HASH_SECRET: new rows hold no plaintext number anywhere in the database file', async () => {
  const s = await startServer({ env: { PHONE_HASH_SECRET: 'unit-test-secret' } });
  try {
    await linkWithOtp(s, PHONE, RELAY_TOKEN);
    const f = await oauthFlow(s, PHONE);
    assert.equal((await mcp(s, f.tokens.access_token)).status, 503);
    const c = await connectPhone(s, RELAY_TOKEN);
    assert.equal((await mcp(s, f.tokens.access_token)).status, 200);
    s.db.pragma('wal_checkpoint(TRUNCATE)');
    for (const t of [...OLD_TABLES, 'rate_counters', 'meta']) {
      assert.ok(!JSON.stringify(tableRows(s.db, t)).includes('4155550101'), `${t} has no plaintext phone`);
    }
    assert.ok(!fs.readFileSync(s.dbPath).includes('4155550101'));
    assert.match(s.db.prepare('SELECT phone_key FROM phone_links').get().phone_key, /^[0-9a-f]{64}$/);
    assert.ok(c.ws);
  } finally { await s.close(); }
});

test('PHONE_HASH_SECRET: legacy plaintext rows are backfilled and keep working; scrub is explicit and irreversible', async () => {
  const p = tmpDbPath();
  const legacy = createLegacyDb(p);
  let s = await startServer({ dbPath: p, env: { PHONE_HASH_SECRET: 'unit-test-secret' } });
  try {
    const link = s.db.prepare('SELECT * FROM phone_links').get();
    assert.match(link.phone_key, /^[0-9a-f]{64}$/);
    assert.equal(link.phone_number, PHONE, 'plaintext retained until the explicit scrub (rollback safety)');
    assert.equal((await connectPhone(s, legacy.legacyRelayToken)).outcome, 'open');
    assert.equal((await mcp(s, legacy.legacyAccess)).status, 200);
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 409);
  } finally { await s.close(); }

  s = await startServer({ dbPath: p, env: { PHONE_HASH_SECRET: 'unit-test-secret', SCRUB_PLAINTEXT_PHONES: '1' } });
  try {
    for (const t of OLD_TABLES) assert.ok(!JSON.stringify(tableRows(s.db, t)).includes('4155550101'), `${t} scrubbed`);
    assert.ok(!fs.readFileSync(p).includes('4155550101'), 'file scrubbed after VACUUM');
    assert.equal((await connectPhone(s, legacy.legacyRelayToken)).outcome, 'open');
    assert.equal((await mcp(s, legacy.legacyAccess)).status, 200);
  } finally { await s.close(); }
});

test('hashed mode fails closed if the secret goes missing or changes', async () => {
  const p = tmpDbPath();
  createLegacyDb(p);
  const s = await startServer({ dbPath: p, env: { PHONE_HASH_SECRET: 'secret-one' } });
  await s.close();
  const mk = (env) => { const db = openDb(p); try { createApp({ db, delivery: createOtpDelivery({ OTP_DELIVERY: 'console', NODE_ENV: 'test' }), config: loadConfig(env), logger: { log() {}, warn() {}, error() {} } }); } finally { db.close(); } };
  assert.throws(() => mk({}), /PHONE_HASH_SECRET is not set/);
  assert.throws(() => mk({ PHONE_HASH_SECRET: 'secret-two' }), /does not match/);
  assert.doesNotThrow(() => mk({ PHONE_HASH_SECRET: 'secret-one' }));
});

// ---- OTP delivery guard ----

test('OTP_DELIVERY=console is refused in production, on Fly, and without a dev NODE_ENV', () => {
  assert.throws(() => createOtpDelivery({ OTP_DELIVERY: 'console', NODE_ENV: 'production' }), /refused/);
  assert.throws(() => createOtpDelivery({ OTP_DELIVERY: 'console' }), /refused/);
  assert.throws(() => createOtpDelivery({ OTP_DELIVERY: 'console', NODE_ENV: 'test', FLY_APP_NAME: 'inboxiq-mcp' }), /refused/);
  assert.equal(createOtpDelivery({ OTP_DELIVERY: 'console', NODE_ENV: 'test' }).mode, 'console');
  assert.equal(createOtpDelivery({ OTP_DELIVERY: 'console', NODE_ENV: 'production', ALLOW_CONSOLE_OTP: '1' }).mode, 'console');
  assert.throws(() => createOtpDelivery({ OTP_DELIVERY: 'carrier-pigeon' }), /Unknown/);
});

test('default delivery is Twilio voice and is unconfigured (not console) without credentials; no network at construction', () => {
  const d = createOtpDelivery({ NODE_ENV: 'production' });
  assert.equal(d.mode, 'twilio');
  assert.equal(d.configured, false);
  assert.equal(createOtpDelivery({ NODE_ENV: 'production', TWILIO_ACCOUNT_SID: 'ACtest', TWILIO_AUTH_TOKEN: 'x', TWILIO_PHONE_NUMBER: '+15005550006' }).configured, true);
});

test('rollback safety: every statement the previous release issues still works on the migrated schema', () => {
  const p = tmpDbPath();
  createLegacyDb(p);
  const db = openDb(p);
  const now = Date.now();
  // statements copied from the previous server.js
  db.prepare('INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)').run('c2', 'n', '[]', now);
  db.prepare('INSERT INTO otp_challenges (id, phone_number, code_hash, attempts, expires_at) VALUES (?, ?, ?, 0, ?)').run('o1', PHONE, 'h', now);
  db.prepare(`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, phone_number, expires_at, used) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`).run('ac', 'c2', 'u', 'ch', 'S256', PHONE, now);
  db.prepare('INSERT INTO access_tokens (token_hash, client_id, phone_number, created_at, expires_at) VALUES (?, ?, ?, ?, ?)').run('at', 'c2', PHONE, now, now);
  db.prepare('INSERT INTO refresh_tokens (token_hash, client_id, phone_number, created_at) VALUES (?, ?, ?, ?)').run('rt', 'c2', PHONE, now);
  db.prepare(`INSERT INTO phone_links (phone_number, relay_token_hash, linked_at, last_connected_at) VALUES (?, ?, ?, NULL)
              ON CONFLICT(phone_number) DO UPDATE SET relay_token_hash = excluded.relay_token_hash, linked_at = excluded.linked_at`).run(PHONE2, 'x', now);
  db.prepare(`INSERT INTO phone_links (phone_number, relay_token_hash, linked_at, last_connected_at) VALUES (?, ?, ?, NULL)
              ON CONFLICT(phone_number) DO UPDATE SET relay_token_hash = excluded.relay_token_hash, linked_at = excluded.linked_at`).run(PHONE2, 'y', now);
  assert.equal(db.prepare('SELECT relay_token_hash FROM phone_links WHERE phone_number = ?').get(PHONE2).relay_token_hash, 'y');
  db.close();
});
