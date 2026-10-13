import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, oauthFlow, linkLegacy, postForm, PHONE, RELAY_TOKEN } from './helpers.js';

const refresh = (s, f, token = f.tokens.refresh_token) => postForm(`${s.base}/token`, { grant_type: 'refresh_token', refresh_token: token, client_id: f.client_id });
const DAY = 86400e3;

test('refresh token expiry is sliding (90d default) and capped (365d absolute)', async () => {
  const s = await startServer();
  try {
    const f = await oauthFlow(s);
    const row = () => s.db.prepare('SELECT * FROM refresh_tokens').get();
    assert.ok(row().expires_at > Date.now() + 89 * DAY && row().expires_at < Date.now() + 91 * DAY);
    s.db.prepare('UPDATE refresh_tokens SET expires_at = ?').run(Date.now() + DAY);
    assert.equal((await refresh(s, f)).status, 200);
    assert.ok(row().expires_at > Date.now() + 89 * DAY, 'use slides the window forward');
    // idle past the window
    s.db.prepare('UPDATE refresh_tokens SET expires_at = ?').run(Date.now() - 1);
    assert.equal((await refresh(s, f)).status, 400);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 0, 'expired token is deleted');
    // absolute cap
    const g = await oauthFlow(s);
    s.db.prepare('UPDATE refresh_tokens SET family_started_at = ?, created_at = ?').run(Date.now() - 366 * DAY, Date.now() - 366 * DAY);
    assert.equal((await refresh(s, g)).status, 400);
  } finally { await s.close(); }
});

test('refresh rotation (opt-in): new token each time, grace for the old one, late reuse revokes the grant', async () => {
  const s = await startServer({ env: { REFRESH_ROTATION: '1', REFRESH_ROTATION_GRACE_MIN: '10' } });
  try {
    const f = await oauthFlow(s);
    const first = f.tokens.refresh_token;
    const r1 = await (await refresh(s, f)).json();
    assert.notEqual(r1.refresh_token, first);
    assert.equal((await refresh(s, f, first)).status, 200, 'old token still works inside the grace window (lost-response safety)');
    const r2 = await (await refresh(s, f, r1.refresh_token)).json();
    assert.ok(r2.access_token);
    s.db.prepare('UPDATE refresh_tokens SET rotated_at = ? WHERE rotated_at IS NOT NULL').run(Date.now() - 11 * 60e3);
    assert.equal((await refresh(s, f, first)).status, 400, 'late reuse is rejected');
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 0, 'and kills the whole grant');
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM access_tokens').get().n, 0);
  } finally { await s.close(); }
});

test('refresh requires the right client and a known token', async () => {
  const s = await startServer();
  try {
    const f = await oauthFlow(s);
    assert.equal((await postForm(`${s.base}/token`, { grant_type: 'refresh_token', refresh_token: f.tokens.refresh_token, client_id: 'x' })).status, 400);
    assert.equal((await refresh(s, f, 'unknown')).status, 400);
    assert.equal((await postForm(`${s.base}/token`, { grant_type: 'refresh_token', client_id: f.client_id })).status, 400);
  } finally { await s.close(); }
});

test('purge removes expired rows and keeps everything live', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const live = await oauthFlow(s);
    const dead = await oauthFlow(s);
    const now = Date.now();
    s.db.prepare('UPDATE access_tokens SET expires_at = ? WHERE client_id = ?').run(now - 2 * 3600e3, dead.client_id);
    s.db.prepare('UPDATE refresh_tokens SET expires_at = ? WHERE client_id = ?').run(now - 1000, dead.client_id);
    s.db.prepare('UPDATE auth_codes SET expires_at = ? WHERE client_id = ?').run(now - 2 * 3600e3, dead.client_id);
    s.db.prepare("INSERT INTO otp_challenges (id, phone_number, phone_key, purpose, code_hash, attempts, expires_at) VALUES ('old', ?, ?, 'auth', 'h', 0, ?)").run(PHONE, PHONE, now - 2 * 3600e3);
    s.db.prepare("INSERT INTO rate_counters VALUES ('stale', ?, 1)").run(now - 3 * DAY);
    s.db.prepare('INSERT INTO oauth_clients VALUES (?, ?, ?, ?)').run('unused', 'x', '[]', now - 91 * DAY);
    const removed = s.purgeExpired();
    assert.equal(removed.access_tokens, 1);
    assert.equal(removed.refresh_tokens, 1);
    assert.equal(removed.auth_codes, 1);
    assert.equal(removed.otp_challenges, 1);
    assert.equal(removed.rate_counters, 1);
    assert.equal(removed.oauth_clients, 1);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM phone_links').get().n, 1, 'links are never purged');
    assert.equal((await refresh(s, live)).status, 200);
  } finally { await s.close(); }
});
