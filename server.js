import express from 'express';
import expressWs from 'express-ws';
import rateLimit from 'express-rate-limit';
import twilio from 'twilio';
import { db } from './db.js';
import { randomToken, sha256, verifyPkce, randomOtp, normalizePhone } from './util.js';

const PORT = process.env.PORT || 8080;
const ISSUER = process.env.ISSUER_URL || `http://localhost:${PORT}`;
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

const twilioClient = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN
  ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
  : null;

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const OTP_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const RELAY_TIMEOUT_MS = 30 * 1000;
const MAX_OTP_ATTEMPTS = 5;

const app = express();
const wsInstance = expressWs(app);
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 60_000, limit: 5, standardHeaders: true, legacyHeaders: false });
const mcpLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false });

// phone_number -> live WebSocket connection from the InboxIQ app.
const phoneConnections = new Map();
// correlationId -> { resolve, reject, timeout }, for matching relay responses.
const pendingRelayCalls = new Map();

// ---------- OAuth discovery + dynamic client registration ----------

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    registration_endpoint: `${ISSUER}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  });
});

app.post('/register', authLimiter, (req, res) => {
  const { client_name, redirect_uris } = req.body || {};
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' });
  }
  const client_id = randomToken(16);
  db.prepare('INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)')
    .run(client_id, client_name || 'Unnamed client', JSON.stringify(redirect_uris), Date.now());
  res.status(201).json({
    client_id,
    client_name: client_name || 'Unnamed client',
    redirect_uris,
    token_endpoint_auth_method: 'none',
  });
});

// ---------- /authorize: phone number -> OTP -> auth code ----------

function renderPhoneForm(oauthParams, error) {
  const hidden = Object.entries(oauthParams).map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v || '')}">`).join('\n');
  return `<!doctype html><html><body style="font-family:sans-serif;max-width:420px;margin:40px auto">
    <h2>Connect InboxIQ</h2>
    <p>Enter the phone number of the InboxIQ app you want to connect. We'll text you a code.</p>
    ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/authorize/send-otp">
      ${hidden}
      <input type="tel" name="phone_number" placeholder="+14155551234" required style="width:100%;padding:8px;font-size:16px">
      <button type="submit" style="margin-top:12px;padding:8px 16px">Send code</button>
    </form>
  </body></html>`;
}

function renderOtpForm(oauthParams, phoneNumber, error) {
  const hidden = Object.entries(oauthParams).map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v || '')}">`).join('\n');
  return `<!doctype html><html><body style="font-family:sans-serif;max-width:420px;margin:40px auto">
    <h2>Enter the code we texted you</h2>
    <p>Sent to ${escapeHtml(phoneNumber)}.</p>
    ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/authorize/verify-otp">
      ${hidden}
      <input type="hidden" name="phone_number" value="${escapeHtml(phoneNumber)}">
      <input type="text" name="code" inputmode="numeric" placeholder="123456" required style="width:100%;padding:8px;font-size:16px">
      <button type="submit" style="margin-top:12px;padding:8px 16px">Verify</button>
    </form>
  </body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function oauthParamsFrom(query) {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = query;
  return { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope };
}

app.get('/authorize', authLimiter, (req, res) => {
  const params = oauthParamsFrom(req.query);
  if (params.response_type !== 'code' || !params.client_id || !params.redirect_uri || !params.code_challenge) {
    return res.status(400).send('Invalid authorization request');
  }
  const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(params.client_id);
  if (!client || !JSON.parse(client.redirect_uris).includes(params.redirect_uri)) {
    return res.status(400).send('Unknown client or redirect_uri');
  }
  res.send(renderPhoneForm(params));
});

app.post('/authorize/send-otp', otpLimiter, async (req, res) => {
  const params = oauthParamsFrom(req.body);
  const phone = normalizePhone(req.body.phone_number);
  if (!phone) return res.send(renderPhoneForm(params, 'Enter a valid phone number in +1XXXXXXXXXX format.'));
  if (!twilioClient) return res.status(500).send('SMS delivery is not configured.');

  const code = randomOtp();
  const id = randomToken(16);
  db.prepare('INSERT INTO otp_challenges (id, phone_number, code_hash, attempts, expires_at) VALUES (?, ?, ?, 0, ?)')
    .run(id, phone, sha256(code), Date.now() + OTP_TTL_MS);

  await twilioClient.messages.create({
    to: phone,
    from: TWILIO_PHONE_NUMBER,
    body: `Your InboxIQ connection code is ${code}. Expires in 5 minutes.`,
  });

  res.send(renderOtpForm(params, phone));
});

app.post('/authorize/verify-otp', otpLimiter, (req, res) => {
  const params = oauthParamsFrom(req.body);
  const phone = normalizePhone(req.body.phone_number);
  const code = String(req.body.code || '').trim();
  const challenge = db.prepare('SELECT * FROM otp_challenges WHERE phone_number = ? ORDER BY expires_at DESC LIMIT 1').get(phone);

  if (!challenge || challenge.expires_at < Date.now()) {
    return res.send(renderPhoneForm(params, 'That code expired — enter your number again.'));
  }
  if (challenge.attempts >= MAX_OTP_ATTEMPTS) {
    return res.send(renderPhoneForm(params, 'Too many attempts — enter your number again.'));
  }
  db.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(challenge.id);
  if (sha256(code) !== challenge.code_hash) {
    return res.send(renderOtpForm(params, phone, 'Wrong code, try again.'));
  }

  const authCode = randomToken(24);
  db.prepare(`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, phone_number, expires_at, used)
              VALUES (?, ?, ?, ?, ?, ?, ?, 0)`)
    .run(authCode, params.client_id, params.redirect_uri, params.code_challenge, params.code_challenge_method || 'S256', phone, Date.now() + AUTH_CODE_TTL_MS);

  const redirect = new URL(params.redirect_uri);
  redirect.searchParams.set('code', authCode);
  if (params.state) redirect.searchParams.set('state', params.state);
  res.redirect(redirect.toString());
});

// ---------- /token ----------

app.post('/token', authLimiter, (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === 'authorization_code') {
    const { code, redirect_uri, client_id, code_verifier } = req.body;
    const row = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(code);
    if (!row || row.used || row.expires_at < Date.now()) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    if (row.client_id !== client_id || row.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    if (!code_verifier || !verifyPkce(code_verifier, row.code_challenge)) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    }
    db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(code);

    return res.json(issueTokens(client_id, row.phone_number));
  }

  if (grant_type === 'refresh_token') {
    const { refresh_token, client_id } = req.body;
    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(sha256(refresh_token || ''));
    if (!row || row.client_id !== client_id) {
      return res.status(400).json({ error: 'invalid_grant' });
    }
    return res.json(issueTokens(client_id, row.phone_number, { reuseRefreshToken: refresh_token }));
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

function issueTokens(clientId, phoneNumber, opts = {}) {
  const accessToken = randomToken();
  const expiresAt = Date.now() + ACCESS_TOKEN_TTL_MS;
  db.prepare('INSERT INTO access_tokens (token_hash, client_id, phone_number, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(sha256(accessToken), clientId, phoneNumber, Date.now(), expiresAt);

  const refreshToken = opts.reuseRefreshToken || randomToken();
  if (!opts.reuseRefreshToken) {
    db.prepare('INSERT INTO refresh_tokens (token_hash, client_id, phone_number, created_at) VALUES (?, ?, ?, ?)')
      .run(sha256(refreshToken), clientId, phoneNumber, Date.now());
  }

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
    refresh_token: refreshToken,
  };
}

// ---------- Phone linking + WebSocket relay ----------

// The InboxIQ app calls this once, with a relay token it generated itself, to link its
// phone number to that token. Mirrors the on-device pairing bearer-token pattern.
app.post('/phone/link', authLimiter, (req, res) => {
  const phone = normalizePhone(req.body.phone_number);
  const relayToken = req.body.relay_token;
  if (!phone || !relayToken) return res.status(400).json({ error: 'phone_number and relay_token are required' });

  db.prepare(`INSERT INTO phone_links (phone_number, relay_token_hash, linked_at, last_connected_at)
              VALUES (?, ?, ?, NULL)
              ON CONFLICT(phone_number) DO UPDATE SET relay_token_hash = excluded.relay_token_hash, linked_at = excluded.linked_at`)
    .run(phone, sha256(relayToken), Date.now());

  res.json({ ok: true });
});

app.ws('/phone-ws', (ws, req) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const link = token ? db.prepare('SELECT * FROM phone_links WHERE relay_token_hash = ?').get(sha256(token)) : null;
  if (!link) {
    ws.close(4401, 'unauthorized');
    return;
  }

  const phone = link.phone_number;
  phoneConnections.set(phone, ws);
  db.prepare('UPDATE phone_links SET last_connected_at = ? WHERE phone_number = ?').run(Date.now(), phone);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const pending = pendingRelayCalls.get(msg.correlationId);
    if (pending) {
      clearTimeout(pending.timeout);
      pendingRelayCalls.delete(msg.correlationId);
      pending.resolve(msg.payload);
    }
  });

  ws.on('close', () => {
    if (phoneConnections.get(phone) === ws) phoneConnections.delete(phone);
  });
});

function relayToPhone(phoneNumber, payload) {
  const ws = phoneConnections.get(phoneNumber);
  if (!ws || ws.readyState !== ws.OPEN) return Promise.reject(new Error('phone_not_connected'));

  const correlationId = randomToken(8);
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pendingRelayCalls.delete(correlationId);
      reject(new Error('relay_timeout'));
    }, RELAY_TIMEOUT_MS);
    pendingRelayCalls.set(correlationId, { resolve, reject, timeout });
    ws.send(JSON.stringify({ correlationId, payload }));
  });
}

// ---------- /mcp: what Claude actually calls after OAuth ----------

app.post('/mcp', mcpLimiter, async (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  const row = db.prepare('SELECT * FROM access_tokens WHERE token_hash = ?').get(sha256(token));
  if (!row || row.expires_at < Date.now()) return res.status(401).json({ error: 'invalid_or_expired_token' });

  try {
    const result = await relayToPhone(row.phone_number, req.body);
    res.json(result);
  } catch (err) {
    const status = err.message === 'phone_not_connected' ? 503 : 504;
    res.status(status).json({ error: err.message });
  }
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`inboxiq-mcp-backend listening on ${PORT}`));
