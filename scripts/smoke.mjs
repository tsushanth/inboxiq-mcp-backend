// Local smoke test: starts the real server.js on a random port with a temporary SQLite
// file and console OTP delivery (no Twilio, no network), then walks the whole API:
// register -> authorize -> OTP -> token -> link -> relay -> conflict -> unlink -> expiry.
// Usage: node scripts/smoke.mjs   (or scripts/smoke.sh)
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import Database from 'better-sqlite3';
import WebSocket from 'ws';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inboxiq-smoke-'));
const dbPath = path.join(dir, 'smoke.db');
const port = await new Promise((resolve) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const base = `http://127.0.0.1:${port}`;
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
const PHONE = '+14155550199';
const RELAY = crypto.randomBytes(32).toString('base64url');
const RELAY_OTHER = crypto.randomBytes(32).toString('base64url');

let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  ${detail}`}`); if (!ok) failures++; };
const env = { ...process.env, PORT: String(port), DB_PATH: dbPath, ISSUER_URL: base, NODE_ENV: 'development', OTP_DELIVERY: 'console', IP_LIMIT_SCALE: '50' };
for (const k of ['FLY_APP_NAME', 'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER', 'PHONE_HASH_SECRET']) delete env[k];

// 0. the console OTP seam must refuse to start in production
const prod = spawnSync('node', ['server.js'], { cwd: root, env: { ...env, NODE_ENV: 'production' }, encoding: 'utf8', timeout: 15000 });
check('OTP_DELIVERY=console refused when NODE_ENV=production', prod.status !== 0 && /refused/.test(prod.stderr));

let out = '';
const child = spawn('node', ['server.js'], { cwd: root, env });
child.stdout.on('data', (d) => { out += d; });
child.stderr.on('data', (d) => { out += d; });
const stop = () => { try { child.kill(); } catch { /* */ } fs.rmSync(dir, { recursive: true, force: true }); };
process.on('exit', stop);

for (let i = 0; i < 50 && !/listening/.test(out); i++) await new Promise((r) => setTimeout(r, 100));
check('server started', /listening/.test(out), out);

const j = async (p, opts) => { const r = await fetch(base + p, opts); return { status: r.status, body: await r.json().catch(() => null), headers: r.headers }; };
const post = (p, body, headers = {}) => j(p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const postForm = (p, body) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body), redirect: 'manual' });
const lastOtp = () => [...out.matchAll(/\[otp-console\] (\S+) (\d{6})/g)].pop()?.[2];

try {
  check('healthz', (await j('/healthz')).body?.ok === true);
  const meta = await j('/.well-known/oauth-authorization-server');
  check('oauth metadata', meta.body?.issuer === base && meta.body?.code_challenge_methods_supported?.[0] === 'S256');

  const reg = await post('/register', { client_name: 'smoke', redirect_uris: [CALLBACK] });
  check('register', reg.status === 201 && !!reg.body.client_id);
  check('register rejects foreign redirect', (await post('/register', { redirect_uris: ['https://evil.example/cb'] })).status === 400);
  const client_id = reg.body.client_id;

  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const params = { response_type: 'code', client_id, redirect_uri: CALLBACK, state: 's', code_challenge: challenge, code_challenge_method: 'S256' };
  check('authorize page', (await fetch(`${base}/authorize?${new URLSearchParams(params)}`)).status === 200);

  // legacy link (what app 0.4.x sends), then the app connects its WebSocket
  check('legacy link (first use)', (await post('/phone/link', { phone_number: PHONE, relay_token: RELAY })).status === 200);
  check('legacy link idempotent', (await post('/phone/link', { phone_number: PHONE, relay_token: RELAY })).status === 200);
  const hijack = await post('/phone/link', { phone_number: PHONE, relay_token: RELAY_OTHER });
  check('hijack attempt rejected with 409', hijack.status === 409 && hijack.body.otp_required === true);

  const ws = new WebSocket(`${base.replace('http', 'ws')}/phone-ws`, { headers: { Authorization: `Bearer ${RELAY}` } });
  ws.on('message', (raw) => { const e = JSON.parse(raw); ws.send(JSON.stringify({ correlationId: e.correlationId, payload: { jsonrpc: '2.0', id: e.payload.id, result: { pong: true } } })); });
  await new Promise((r, x) => { ws.on('open', r); ws.on('error', x); });
  const wsClosed = new Promise((r) => ws.on('close', r));

  await postForm('/authorize/send-otp', { ...params, phone_number: PHONE });
  check('OTP printed by console delivery', /^\d{6}$/.test(lastOtp() || ''));
  const wrong = await postForm('/authorize/verify-otp', { ...params, phone_number: PHONE, code: lastOtp() === '000000' ? '111111' : '000000' });
  check('wrong OTP does not issue a code', !wrong.headers.get('location'));
  const v = await postForm('/authorize/verify-otp', { ...params, phone_number: PHONE, code: lastOtp() });
  const code = new URL(v.headers.get('location')).searchParams.get('code');
  check('OTP verified -> redirect with code', !!code);
  const tok = await post('/token', { grant_type: 'authorization_code', code, redirect_uri: CALLBACK, client_id, code_verifier: verifier });
  check('token exchange (PKCE)', tok.status === 200 && !!tok.body.access_token && !!tok.body.refresh_token);
  check('code replay rejected', (await post('/token', { grant_type: 'authorization_code', code, redirect_uri: CALLBACK, client_id, code_verifier: verifier })).status === 400);

  // replay revoked the first grant (RFC 6749 4.1.2); do a fresh flow
  await postForm('/authorize/send-otp', { ...params, phone_number: PHONE });
  const v2 = await postForm('/authorize/verify-otp', { ...params, phone_number: PHONE, code: lastOtp() });
  const code2 = new URL(v2.headers.get('location')).searchParams.get('code');
  const t2 = (await post('/token', { grant_type: 'authorization_code', code: code2, redirect_uri: CALLBACK, client_id, code_verifier: verifier })).body;

  const relayed = await post('/mcp', { jsonrpc: '2.0', id: 42, method: 'ping' }, { Authorization: `Bearer ${t2.access_token}` });
  check('/mcp relays to the linked phone', relayed.status === 200 && relayed.body?.result?.pong === true, JSON.stringify(relayed));
  check('/mcp without token is 401', (await post('/mcp', {})).status === 401);

  const rf = await post('/token', { grant_type: 'refresh_token', refresh_token: t2.refresh_token, client_id });
  check('refresh', rf.status === 200 && !!rf.body.access_token);

  // expiry path: age the refresh token directly in the temp DB
  const raw = new Database(dbPath);
  raw.prepare('UPDATE refresh_tokens SET expires_at = ?').run(Date.now() - 1000);
  raw.close();
  check('expired refresh token rejected', (await post('/token', { grant_type: 'refresh_token', refresh_token: t2.refresh_token, client_id })).status === 400);

  // OTP-based re-link (new client flow)
  const start = await post('/phone/link/start', { phone_number: PHONE });
  check('link/start places the (console) call', start.status === 200 && !!start.body.challenge_id);
  const relinked = await post('/phone/link', { phone_number: PHONE, relay_token: RELAY_OTHER, challenge_id: start.body.challenge_id, otp_code: lastOtp() });
  check('OTP re-link replaces the link', relinked.status === 200 && relinked.body.replaced === true);
  check('old socket closed with 4401', (await wsClosed) === 4401);

  // unlink
  const del = await j('/phone/link', { method: 'DELETE', headers: { Authorization: `Bearer ${RELAY_OTHER}` } });
  check('unlink', del.status === 200);
  check('unlink with stale token is 401', (await j('/phone/link', { method: 'DELETE', headers: { Authorization: `Bearer ${RELAY}` } })).status === 401);
  check('malformed JSON error has no stack trace', !JSON.stringify((await j('/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' })).body).includes('node_modules'));
} catch (err) {
  check('smoke run completed', false, String(err));
}

stop();
console.log(failures === 0 ? '\nsmoke: ALL PASSED' : `\nsmoke: ${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
