import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, oauthFlow, registerClient, pkcePair, postForm, postJson, form, CALLBACK, PHONE, PHONE2 } from './helpers.js';
import { redirectUriAllowed, normalizePhone, verifyPkce } from '../util.js';

test('healthz, metadata, and hardening headers', async () => {
  const s = await startServer();
  try {
    const h = await fetch(`${s.base}/healthz`);
    assert.equal((await h.json()).ok, true);
    assert.equal(h.headers.get('x-powered-by'), null);
    assert.equal(h.headers.get('x-frame-options'), 'DENY');
    const m = await (await fetch(`${s.base}/.well-known/oauth-authorization-server`)).json();
    assert.deepEqual(m.code_challenge_methods_supported, ['S256']);
    assert.ok(m.revocation_endpoint.endsWith('/revoke'));
  } finally { await s.close(); }
});

test('util: phone normalisation is strict E.164, redirect policy, pkce format', () => {
  assert.equal(normalizePhone('+1 (415) 555-0101'), '+14155550101');
  assert.equal(normalizePhone('14155550101'), null);
  assert.equal(normalizePhone('+1+415+5550101'), null);
  assert.equal(normalizePhone('+0123456789'), null);
  assert.equal(normalizePhone({ a: 1 }), null);
  assert.ok(redirectUriAllowed(CALLBACK));
  assert.ok(redirectUriAllowed('http://localhost:33418/callback'));
  assert.ok(redirectUriAllowed('http://127.0.0.1:9/cb'));
  assert.ok(!redirectUriAllowed('https://evil.example/cb'));
  assert.ok(!redirectUriAllowed('http://claude.ai/cb'));
  assert.ok(!redirectUriAllowed('javascript:alert(1)'));
  assert.ok(!redirectUriAllowed('https://claude.ai/cb#frag'));
  assert.ok(!redirectUriAllowed('https://user:pw@claude.ai/cb'));
  assert.ok(redirectUriAllowed('https://evil.example/cb', { policy: 'permissive' }));
  assert.ok(!redirectUriAllowed('javascript:alert(1)', { policy: 'permissive' }));
  assert.equal(verifyPkce('short', 'x'), false);
});

test('dynamic registration validates redirect URIs and sizes', async () => {
  const s = await startServer();
  try {
    for (const uris of [['https://evil.example/cb'], ['javascript:alert(1)'], [], 'str', Array(6).fill(CALLBACK), [CALLBACK, 'http://evil.example/']]) {
      const r = await postJson(`${s.base}/register`, { redirect_uris: uris });
      assert.equal(r.status, 400, JSON.stringify(uris));
    }
    const ok = await postJson(`${s.base}/register`, { client_name: 'x'.repeat(500) + '\n', redirect_uris: [CALLBACK, 'http://localhost:1234/cb'] });
    assert.equal(ok.status, 201);
    assert.equal((await ok.json()).client_name.length, 100);
  } finally { await s.close(); }
});

test('full OAuth flow: register -> authorize -> OTP -> token -> refresh', async () => {
  const s = await startServer();
  try {
    const f = await oauthFlow(s);
    assert.equal(f.status, 200);
    assert.ok(f.tokens.access_token && f.tokens.refresh_token);
    assert.equal(s.sent[0].phone, PHONE);
    const r = await postForm(`${s.base}/token`, { grant_type: 'refresh_token', refresh_token: f.tokens.refresh_token, client_id: f.client_id });
    assert.equal(r.status, 200);
    assert.ok((await r.json()).access_token);
    // tokens are hashed at rest
    const stored = s.db.prepare('SELECT token_hash FROM access_tokens').all().map((x) => x.token_hash);
    assert.ok(!stored.includes(f.tokens.access_token));
    assert.equal(s.db.prepare('SELECT code FROM auth_codes').get().code.length, 64);
  } finally { await s.close(); }
});

test('authorize: bad client, unregistered redirect_uri, plain PKCE, short challenge all rejected on every step', async () => {
  const s = await startServer();
  try {
    const client_id = await registerClient(s);
    const { challenge } = pkcePair();
    const base = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    assert.equal((await fetch(`${s.base}/authorize?${form(base)}`)).status, 200);
    for (const bad of [{ client_id: 'nope' }, { redirect_uri: 'https://claude.ai/other' }, { code_challenge_method: 'plain' }, { code_challenge: 'short' }, { response_type: 'token' }]) {
      assert.equal((await fetch(`${s.base}/authorize?${form({ ...base, ...bad })}`)).status, 400, JSON.stringify(bad));
      // hidden fields can be tampered with at later steps, so those steps validate again
      assert.equal((await postForm(`${s.base}/authorize/send-otp`, { ...base, ...bad, phone_number: PHONE })).status, 400);
      assert.equal((await postForm(`${s.base}/authorize/verify-otp`, { ...base, ...bad, phone_number: PHONE, code: '123456' })).status, 400);
    }
    assert.equal(s.sent.length, 0, 'no call may be placed for an invalid authorize request');
    // array-valued query params do not crash
    assert.equal((await fetch(`${s.base}/authorize?client_id=a&client_id=b&response_type=code`)).status, 400);
  } finally { await s.close(); }
});

test('authorize rejects a client registered before the redirect policy that points at a foreign host', async () => {
  const s = await startServer();
  try {
    s.db.prepare('INSERT INTO oauth_clients VALUES (?, ?, ?, ?)').run('oldevil', 'x', JSON.stringify(['https://evil.example/cb']), Date.now());
    const { challenge } = pkcePair();
    const r = await fetch(`${s.base}/authorize?${form({ response_type: 'code', client_id: 'oldevil', redirect_uri: 'https://evil.example/cb', code_challenge: challenge, code_challenge_method: 'S256' })}`);
    assert.equal(r.status, 400);
  } finally { await s.close(); }
});

test('token: PKCE, redirect_uri, client mismatch, replay revokes issued tokens', async () => {
  const s = await startServer();
  try {
    const f = await oauthFlow(s);
    // replay of the spent code
    const replay = await postForm(`${s.base}/token`, { grant_type: 'authorization_code', code: f.code, redirect_uri: CALLBACK, client_id: f.client_id, code_verifier: f.verifier });
    assert.equal(replay.status, 400);
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM access_tokens').get().n, 0, 'replay must revoke tokens minted from that code');
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM refresh_tokens').get().n, 0);
  } finally { await s.close(); }

  const s2 = await startServer();
  try {
    const client_id = await registerClient(s2);
    const { verifier, challenge } = pkcePair();
    const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    const newCode = async () => {
      await postForm(`${s2.base}/authorize/send-otp`, { ...params, phone_number: PHONE2 });
      const v = await postForm(`${s2.base}/authorize/verify-otp`, { ...params, phone_number: PHONE2, code: s2.lastCode() });
      return new URL(v.headers.get('location')).searchParams.get('code');
    };
    const exchange = (over) => postForm(`${s2.base}/token`, { grant_type: 'authorization_code', redirect_uri: CALLBACK, client_id, code_verifier: verifier, ...over });
    let code = await newCode();
    assert.equal((await exchange({ code, code_verifier: pkcePair().verifier })).status, 400, 'wrong verifier');
    assert.equal((await exchange({ code, code_verifier: undefined })).status, 400, 'missing verifier');
    assert.equal((await exchange({ code, redirect_uri: 'https://claude.ai/x' })).status, 400, 'wrong redirect');
    assert.equal((await exchange({ code, client_id: 'other' })).status, 400, 'wrong client');
    assert.equal((await exchange({ code })).status, 200, 'still redeemable after failed attempts');
    assert.equal((await exchange({ code: 'garbage' })).status, 400);
    assert.equal((await postForm(`${s2.base}/token`, { grant_type: 'password' })).status, 400);
  } finally { await s2.close(); }
});

test('OTP: single use, 5 attempts per challenge, lockout across fresh challenges, per-phone send cap', async () => {
  const s = await startServer({ env: { OTP_MAX_SENDS_PER_HOUR: '3', OTP_MAX_FAILS_PER_HOUR: '8' } });
  try {
    const client_id = await registerClient(s);
    const { challenge } = pkcePair();
    const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    const send = () => postForm(`${s.base}/authorize/send-otp`, { ...params, phone_number: PHONE });
    const verify = (code) => postForm(`${s.base}/authorize/verify-otp`, { ...params, phone_number: PHONE, code });

    await send();
    const good = s.lastCode();
    const wrong = good === '111111' ? '222222' : '111111';
    for (let i = 0; i < 5; i++) assert.match(await (await verify(wrong)).text(), /Wrong code/);
    // 6th guess, even with the right code, is refused: attempts exhausted on this challenge
    const sixth = await verify(good);
    assert.equal(sixth.status, 200);
    assert.ok(!sixth.headers.get('location'));

    await send(); // fresh challenge, 3 more wrong guesses reach the 8-failure lockout
    for (let i = 0; i < 3; i++) await verify(wrong);
    await send(); // third send allowed
    const locked = await verify(s.lastCode());
    assert.ok(!locked.headers.get('location'), 'locked out even with the correct code');
    assert.match(await locked.text(), /Too many wrong codes/);

    const fourth = await send(); // fourth send in the hour exceeds the cap of 3: no call placed
    assert.match(await fourth.text(), /Too many attempts for this number/);
    assert.equal(s.sent.length, 3);
  } finally { await s.close(); }

  const s2 = await startServer();
  try {
    const f = await oauthFlow(s2);
    // the OTP used by oauthFlow is consumed: replaying it cannot mint another code
    const p = f.params;
    const again = await postForm(`${s2.base}/authorize/verify-otp`, { ...p, phone_number: PHONE, code: s2.lastCode() });
    assert.ok(!again.headers.get('location'));
  } finally { await s2.close(); }
});

test('OTP: global daily cap and destination allowlist stop toll fraud', async () => {
  const s = await startServer({ env: { OTP_GLOBAL_DAILY_CAP: '2', OTP_ALLOWED_COUNTRY_PREFIXES: '+1' } });
  try {
    const client_id = await registerClient(s);
    const { challenge } = pkcePair();
    const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    const send = (phone) => postForm(`${s.base}/authorize/send-otp`, { ...params, phone_number: phone });
    await send('+442071234567');
    assert.equal(s.sent.length, 0, 'non-allowlisted country is never called');
    await send(PHONE); await send(PHONE2);
    await send('+14155550103');
    assert.equal(s.sent.length, 2, 'global cap holds');
  } finally { await s.close(); }
});

test('Twilio failure does not crash the server and does not leak the number into logs', async () => {
  const s = await startServer();
  try {
    s.behaviour.failDelivery = true;
    const client_id = await registerClient(s);
    const { challenge } = pkcePair();
    const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, code_challenge: challenge, code_challenge_method: 'S256' };
    const r = await postForm(`${s.base}/authorize/send-otp`, { ...params, phone_number: PHONE });
    assert.equal(r.status, 200);
    assert.match(await r.text(), /could not place the call/);
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200);
    assert.ok(!s.logs.join('\n').includes('4155550101'));
    assert.equal(s.db.prepare('SELECT COUNT(*) n FROM otp_challenges').get().n, 0);
  } finally { await s.close(); }
});

test('errors never leak stack traces; oversized and malformed bodies are rejected', async () => {
  const s = await startServer();
  try {
    const bad = await fetch(`${s.base}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
    assert.equal(bad.status, 400);
    assert.ok(!(await bad.text()).includes('node_modules'));
    const big = await fetch(`${s.base}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CALLBACK], pad: 'x'.repeat(40_000) }) });
    assert.equal(big.status, 413);
  } finally { await s.close(); }
});

test('IP rate limiting still applies (per route)', async () => {
  const s = await startServer({ env: { IP_LIMIT_SCALE: '1' } });
  try {
    let last;
    for (let i = 0; i < 12; i++) last = await postJson(`${s.base}/register`, { redirect_uris: [CALLBACK] });
    assert.equal(last.status, 429);
  } finally { await s.close(); }
});
