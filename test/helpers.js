import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';
import WebSocket from 'ws';
import { openDb } from '../db.js';
import { createApp, loadConfig } from '../app.js';

export const PHONE = '+14155550101';
export const PHONE2 = '+14155550102';
export const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
export const RELAY_TOKEN = 'A'.repeat(43);
export const RELAY_TOKEN2 = 'B'.repeat(43);

export function tmpDbPath() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'inboxiq-test-')), 'test.db');
}

/** Starts the real app on a random port with a temp SQLite file and a stub OTP delivery (no Twilio, no network). */
export async function startServer({ env = {}, dbPath = tmpDbPath(), setupDb } = {}) {
  if (setupDb) setupDb(dbPath);
  const db = openDb(dbPath);
  const sent = [];
  const logs = [];
  const behaviour = { failDelivery: false };
  const delivery = {
    mode: 'stub',
    configured: true,
    async deliver(phone, code) {
      if (behaviour.failDelivery) throw Object.assign(new Error(`Invalid 'To' Phone Number: ${phone}`), { code: 21211 });
      sent.push({ phone, code });
    },
  };
  const capture = (level) => (...a) => logs.push(`${level} ${a.join(' ')}`);
  const logger = { log: capture('log'), warn: capture('warn'), error: capture('error') };
  const config = loadConfig({ IP_LIMIT_SCALE: '1000', ...env });
  const built = createApp({ db, delivery, config, logger });
  const server = await new Promise((resolve) => { const s = built.app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const sockets = new Set();
  return {
    ...built, db, sent, logs, behaviour, base, dbPath,
    lastCode: () => sent[sent.length - 1].code,
    track: (ws) => { sockets.add(ws); return ws; },
    async close() {
      for (const ws of sockets) try { ws.terminate(); } catch { /* */ }
      await new Promise((r) => server.close(r));
      server.closeAllConnections?.();
      db.close();
    },
  };
}

export const form = (obj) => new URLSearchParams(obj).toString();
export const postForm = (url, obj, opts = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form(obj), redirect: 'manual', ...opts });
export const postJson = (url, obj, headers = {}) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(obj) });

export function pkcePair() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

export async function registerClient(s, redirect = CALLBACK) {
  const r = await postJson(`${s.base}/register`, { client_name: 'Claude', redirect_uris: [redirect] });
  return (await r.json()).client_id;
}

/** Runs register -> authorize -> OTP -> token. Returns the token response plus ids. */
export async function oauthFlow(s, phone = PHONE, { redirect = CALLBACK } = {}) {
  const client_id = await registerClient(s, redirect);
  const { verifier, challenge } = pkcePair();
  const params = { response_type: 'code', client_id, redirect_uri: redirect, state: 'st', code_challenge: challenge, code_challenge_method: 'S256' };
  const page = await fetch(`${s.base}/authorize?${form(params)}`);
  if (page.status !== 200) throw new Error(`authorize ${page.status}`);
  await postForm(`${s.base}/authorize/send-otp`, { ...params, phone_number: phone });
  const v = await postForm(`${s.base}/authorize/verify-otp`, { ...params, phone_number: phone, code: s.lastCode() });
  const location = v.headers.get('location');
  if (!location) throw new Error(`verify did not redirect (${v.status})`);
  const code = new URL(location).searchParams.get('code');
  const t = await postForm(`${s.base}/token`, { grant_type: 'authorization_code', code, redirect_uri: redirect, client_id, code_verifier: verifier });
  return { client_id, code, verifier, params, tokens: await t.json(), status: t.status };
}

/** Connects a fake phone. `handler(payload)` produces the reply payload. */
export async function connectPhone(s, relayToken, handler = (p) => ({ echoed: p })) {
  const ws = s.track(new WebSocket(`${s.base.replace('http', 'ws')}/phone-ws`, { headers: { Authorization: `Bearer ${relayToken}` } }));
  const closed = new Promise((resolve) => ws.on('close', (code) => resolve(code)));
  ws.received = [];
  ws.on('message', (raw) => {
    const env = JSON.parse(raw);
    ws.received.push(env.payload);
    const reply = handler(env.payload, env);
    if (reply !== undefined) ws.send(JSON.stringify({ correlationId: env.correlationId, payload: reply }));
  });
  const outcome = await new Promise((resolve) => {
    ws.on('open', () => resolve('open'));
    ws.on('error', () => resolve('error'));
    ws.on('close', (code) => resolve(`closed:${code}`));
  });
  return { ws, outcome, closed };
}

export const mcp = (s, token, body = { jsonrpc: '2.0', id: 1, method: 'ping' }) =>
  postJson(`${s.base}/mcp`, body, token ? { Authorization: `Bearer ${token}` } : {});

export async function linkLegacy(s, phone, token) {
  return postJson(`${s.base}/phone/link`, { phone_number: phone, relay_token: token });
}

export async function linkWithOtp(s, phone, token) {
  const st = await postJson(`${s.base}/phone/link/start`, { phone_number: phone });
  const { challenge_id } = await st.json();
  return postJson(`${s.base}/phone/link`, { phone_number: phone, relay_token: token, challenge_id, otp_code: s.lastCode() });
}

/** Builds a database exactly as the PRE-hardening db.js created it, filled with sample rows. */
export function createLegacyDb(dbPath, { phone = PHONE } = {}) {
  const raw = new Database(dbPath);
  raw.pragma('journal_mode = WAL');
  raw.exec(fs.readFileSync(new URL('./fixtures/legacy-schema.sql', import.meta.url), 'utf8'));
  const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');
  const now = Date.now();
  raw.prepare('INSERT INTO oauth_clients VALUES (?, ?, ?, ?)').run('legacyclient', 'Claude', JSON.stringify([CALLBACK]), now - 5 * 86400e3);
  raw.prepare('INSERT INTO phone_links VALUES (?, ?, ?, ?)').run(phone, sha('L'.repeat(43)), now - 7 * 86400e3, now - 3600e3);
  raw.prepare('INSERT INTO access_tokens VALUES (?, ?, ?, ?, ?)').run(sha('legacy-access'), 'legacyclient', phone, now - 600e3, now + 3000e3);
  raw.prepare('INSERT INTO access_tokens VALUES (?, ?, ?, ?, ?)').run(sha('legacy-access-expired'), 'legacyclient', phone, now - 9e6, now - 5e6);
  raw.prepare('INSERT INTO refresh_tokens VALUES (?, ?, ?, ?)').run(sha('legacy-refresh'), 'legacyclient', phone, now - 5 * 86400e3);
  raw.prepare('INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run('rawcode', 'legacyclient', CALLBACK, 'c'.repeat(43), 'S256', phone, now - 9e6, 1);
  raw.prepare('INSERT INTO otp_challenges VALUES (?, ?, ?, ?, ?)').run('oldotp', phone, sha('123456'), 0, now - 9e6);
  raw.close();
  return { legacyRelayToken: 'L'.repeat(43), legacyAccess: 'legacy-access', legacyRefresh: 'legacy-refresh' };
}
