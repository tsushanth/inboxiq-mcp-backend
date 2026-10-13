import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, oauthFlow, connectPhone, mcp, linkLegacy, linkWithOtp, postJson, PHONE, PHONE2, RELAY_TOKEN, RELAY_TOKEN2 } from './helpers.js';

const del = (s, path, token) => fetch(`${s.base}${path}`, { method: 'DELETE', headers: token ? { Authorization: `Bearer ${token}` } : {} });

test('legacy client (app <= 0.4.1): first link works and the request/response shape is unchanged', async () => {
  const s = await startServer();
  try {
    // exactly what RelayApi.linkPhone sends
    const r = await linkLegacy(s, PHONE, RELAY_TOKEN);
    assert.equal(r.status, 200);
    assert.equal((await r.json()).ok, true);
    // re-enabling the toggle re-sends the same token: idempotent success
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN)).status, 200);
    const row = s.db.prepare('SELECT link_proof FROM phone_links').get();
    assert.equal(row.link_proof, 'tofu');
    const c = await connectPhone(s, RELAY_TOKEN);
    assert.equal(c.outcome, 'open');
  } finally { await s.close(); }
});

test('HIJACK FIX: a different token can no longer overwrite an existing link', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const victim = await connectPhone(s, RELAY_TOKEN);
    assert.equal(victim.outcome, 'open');
    const flow = await oauthFlow(s, PHONE);

    const attack = await linkLegacy(s, PHONE, RELAY_TOKEN2);
    assert.equal(attack.status, 409);
    assert.equal((await attack.json()).otp_required, true);
    const attacker = await connectPhone(s, RELAY_TOKEN2);
    assert.match(attacker.outcome, /closed:4401|error/);

    // the victim's relay is intact and still receives Claude's calls
    const res = await mcp(s, flow.tokens.access_token);
    assert.equal(res.status, 200);
  } finally { await s.close(); }
});

test('first-use squat by a legacy client cannot block the real owner once the owner can prove the number by OTP', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN2); // squatter claims first
    const owner = await linkWithOtp(s, PHONE, RELAY_TOKEN);
    assert.equal(owner.status, 200);
    const body = await owner.json();
    assert.equal(body.link_proof, 'otp');
    assert.equal(body.replaced, true);
    assert.match((await connectPhone(s, RELAY_TOKEN2)).outcome, /closed:4401|error/);
    assert.equal((await connectPhone(s, RELAY_TOKEN)).outcome, 'open');
    // and now a legacy attempt can no longer touch an otp-verified link
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 409);
  } finally { await s.close(); }
});

test('OTP link: replaces the link, kicks the old socket, codes are single use and bound to the phone', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const old = await connectPhone(s, RELAY_TOKEN);
    assert.equal(old.outcome, 'open');
    assert.equal((await linkWithOtp(s, PHONE, RELAY_TOKEN2)).status, 200);
    assert.equal(await old.closed, 4401);

    // wrong code
    const st = await (await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE })).json();
    const wrong = s.lastCode() === '123456' ? '654321' : '123456';
    const bad = await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN, challenge_id: st.challenge_id, otp_code: wrong });
    assert.equal(bad.status, 401);
    // a code issued for another phone cannot be used here
    await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE2 });
    const other = await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN, challenge_id: st.challenge_id, otp_code: s.lastCode() });
    assert.equal(other.status, 401);
    // single use
    const st2 = await (await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE })).json();
    const code = s.lastCode();
    const ok = await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN, challenge_id: st2.challenge_id, otp_code: code });
    assert.equal(ok.status, 200);
    const again = await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN2, challenge_id: st2.challenge_id, otp_code: code });
    assert.equal(again.status, 401);
  } finally { await s.close(); }
});

test('an authorize-purpose OTP cannot be redeemed to link a phone', async () => {
  const s = await startServer();
  try {
    await oauthFlow(s, PHONE).catch(() => {});
    const { registerClient, pkcePair, postForm, CALLBACK } = await import('./helpers.js');
    const client_id = await registerClient(s);
    const { challenge } = pkcePair();
    const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    await postForm(`${s.base}/authorize/send-otp`, { ...params, phone_number: PHONE2 });
    const r = await postJson(`${s.base}/phone/link`, { phone_number: PHONE2, relay_token: RELAY_TOKEN2, otp_code: s.lastCode() });
    assert.equal(r.status, 401);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM phone_links').get().n, 0);
  } finally { await s.close(); }
});

test('OTP link start is rate limited per phone and brute force is locked out', async () => {
  const s = await startServer({ env: { OTP_MAX_SENDS_PER_HOUR: '2', OTP_MAX_FAILS_PER_HOUR: '4' } });
  try {
    const a = await (await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE })).json();
    const wrong = s.lastCode() === '000000' ? '111111' : '000000';
    for (let i = 0; i < 4; i++) {
      await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN, challenge_id: a.challenge_id, otp_code: wrong });
    }
    const locked = await postJson(`${s.base}/phone/link`, { phone_number: PHONE, relay_token: RELAY_TOKEN, challenge_id: a.challenge_id, otp_code: s.lastCode() });
    assert.equal(locked.status, 429);
    assert.equal((await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE })).status, 200);
    assert.equal((await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE })).status, 429);
    assert.equal(s.sent.length, 2);
  } finally { await s.close(); }
});

test('LEGACY_LINK_COMPAT=0 requires OTP for every link; invalid input is rejected', async () => {
  const s = await startServer({ env: { LEGACY_LINK_COMPAT: '0' } });
  try {
    const r = await linkLegacy(s, PHONE, RELAY_TOKEN);
    assert.equal(r.status, 403);
    assert.equal((await r.json()).error, 'otp_required');
    assert.equal((await linkWithOtp(s, PHONE, RELAY_TOKEN)).status, 200);
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN)).status, 403);
    for (const body of [{ phone_number: PHONE, relay_token: 'short' }, { phone_number: '4155550101', relay_token: RELAY_TOKEN }, { phone_number: PHONE }, { phone_number: PHONE, relay_token: { a: 1 } }, {}]) {
      assert.equal((await postJson(`${s.base}/phone/link`, body)).status, 400, JSON.stringify(body));
    }
  } finally { await s.close(); }
});

test('legacy mass-claim is throttled per IP', async () => {
  const s = await startServer({ env: { LEGACY_NEW_LINKS_PER_IP_HOUR: '3', IP_LIMIT_SCALE: '1' } });
  try {
    const out = [];
    for (let i = 0; i < 5; i++) out.push((await linkLegacy(s, `+1415555020${i}`, RELAY_TOKEN)).status);
    assert.deepEqual(out, [200, 200, 200, 429, 429]);
  } finally { await s.close(); }
});

test('optional stale takeover: legacy relink allowed only after LEGACY_RELINK_STALE_DAYS of silence, never over an OTP link', async () => {
  const s = await startServer({ env: { LEGACY_RELINK_STALE_DAYS: '14' } });
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 409);
    s.db.prepare('UPDATE phone_links SET linked_at = ?').run(Date.now() - 15 * 86400e3);
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 200);
    await linkWithOtp(s, PHONE, RELAY_TOKEN);
    s.db.prepare('UPDATE phone_links SET linked_at = ?, last_connected_at = NULL').run(Date.now() - 400 * 86400e3);
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 409);
  } finally { await s.close(); }
});

test('unlink: DELETE /phone/link removes the link, revokes tokens, closes the socket; wrong token is 401', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const c = await connectPhone(s, RELAY_TOKEN);
    const flow = await oauthFlow(s, PHONE);
    assert.equal((await mcp(s, flow.tokens.access_token)).status, 200);

    assert.equal((await del(s, '/phone/link', RELAY_TOKEN2)).status, 401);
    assert.equal((await del(s, '/phone/link')).status, 401);
    assert.equal((await del(s, '/phone/link', RELAY_TOKEN)).status, 200);
    assert.equal(await c.closed, 4401);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM phone_links').get().n, 0);
    assert.equal((await mcp(s, flow.tokens.access_token)).status, 401);
    const refresh = await postJson(`${s.base}/token`, { grant_type: 'refresh_token', refresh_token: flow.tokens.refresh_token, client_id: flow.client_id });
    assert.equal(refresh.status, 400);
    // the number can be linked afresh afterwards
    assert.equal((await linkLegacy(s, PHONE, RELAY_TOKEN2)).status, 200);
  } finally { await s.close(); }
});

test('revoke-all: DELETE /phone/tokens kills OAuth grants but keeps the link; /revoke handles a single grant', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const flow = await oauthFlow(s, PHONE);
    assert.equal((await del(s, '/phone/tokens', RELAY_TOKEN)).status, 200);
    assert.equal((await mcp(s, flow.tokens.access_token)).status, 401);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM phone_links').get().n, 1);

    const f2 = await oauthFlow(s, PHONE);
    const bad = await postJson(`${s.base}/revoke`, { token: f2.tokens.refresh_token, client_id: 'someone-else' });
    assert.equal(bad.status, 200);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 1, 'wrong client_id must not revoke');
    await postJson(`${s.base}/revoke`, { token: f2.tokens.refresh_token, client_id: f2.client_id });
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 0);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM access_tokens').get().n, 0);
  } finally { await s.close(); }
});
