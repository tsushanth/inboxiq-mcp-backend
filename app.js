import express from 'express';
import expressWs from 'express-ws';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { randomToken, sha256, safeEqual, verifyPkce, randomOtp, normalizePhone, makePhoneKeyFn, redirectUriAllowed } from './util.js';
import { backfillPhoneKeys, scrubPlaintextPhones } from './db.js';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

export function loadConfig(env = process.env) {
  const int = (v, d) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : d);
  const list = (v) => String(v || '').split(',').map((s) => s.trim()).filter(Boolean);
  const port = env.PORT || 8080;
  return {
    port,
    issuer: env.ISSUER_URL || `http://localhost:${port}`,
    // Legacy (app <= 0.4.1) clients link without an OTP. On: first link of a number is trusted
    // on first use and can never be overwritten without an OTP. Off: OTP is mandatory.
    legacyLinkCompat: (env.LEGACY_LINK_COMPAT ?? '1') !== '0',
    // Optional: let a legacy client take over a legacy/tofu link whose app has not connected for N days (0 = never).
    legacyRelinkStaleDays: int(env.LEGACY_RELINK_STALE_DAYS, 0),
    legacyNewLinksPerIpPerHour: int(env.LEGACY_NEW_LINKS_PER_IP_HOUR, 10),
    phoneHashSecret: env.PHONE_HASH_SECRET || '',
    scrubPlaintextPhones: env.SCRUB_PLAINTEXT_PHONES === '1',
    accessTtlMs: HOUR,
    refreshTtlMs: int(env.REFRESH_TTL_DAYS, 90) * DAY, // sliding
    refreshMaxMs: int(env.REFRESH_MAX_DAYS, 365) * DAY, // absolute, from first issue
    refreshRotation: (env.REFRESH_ROTATION ?? '0') === '1',
    refreshRotationGraceMs: int(env.REFRESH_ROTATION_GRACE_MIN, 1440) * MIN,
    redirectPolicy: env.REDIRECT_URI_POLICY === 'permissive' ? 'permissive' : 'strict',
    extraRedirectHosts: list(env.EXTRA_REDIRECT_HOSTS),
    otpMaxSendsPerHour: int(env.OTP_MAX_SENDS_PER_HOUR, 4),
    otpMaxFailsPerHour: int(env.OTP_MAX_FAILS_PER_HOUR, 10),
    otpGlobalDailyCap: int(env.OTP_GLOBAL_DAILY_CAP, 300),
    otpAllowedPrefixes: list(env.OTP_ALLOWED_COUNTRY_PREFIXES),
    maxPendingPerPhone: int(env.MAX_PENDING_RELAY_PER_PHONE, 16),
    trustFlyClientIp: !!env.FLY_APP_NAME,
    ipLimitScale: int(env.IP_LIMIT_SCALE, 1), // tests only
  };
}

const AUTH_CODE_TTL_MS = 5 * MIN;
const OTP_TTL_MS = 5 * MIN;
const RELAY_TIMEOUT_MS = 30 * 1000;
const MAX_OTP_ATTEMPTS = 5;

const str = (v, max = 2048) => (typeof v === 'string' && v.length <= max ? v : '');

/**
 * Builds the Express app. `db` is an opened+migrated database, `delivery` is the OTP
 * delivery object from otp-delivery.js. Nothing here reads message bodies into storage:
 * /mcp request bodies and WebSocket replies are held in memory only for the one relay call.
 */
export function createApp({ db, delivery, config = loadConfig(), logger = console }) {
  const phoneKey = makePhoneKeyFn(config.phoneHashSecret);
  const hashed = !!config.phoneHashSecret;
  const secretCheck = hashed ? crypto.createHmac('sha256', config.phoneHashSecret).update('secret-check').digest('hex') : '';
  backfillPhoneKeys(db, phoneKey, { hashed, secretCheck });
  if (config.scrubPlaintextPhones) {
    if (!hashed) logger.warn('SCRUB_PLAINTEXT_PHONES=1 ignored: PHONE_HASH_SECRET is not set.');
    else { scrubPlaintextPhones(db); logger.log('plaintext phone numbers scrubbed from the database'); }
  }
  // Value written to the legacy phone_number column of new rows (hashed mode never writes plaintext).
  const legacyCol = (key) => key;

  const app = express();
  const wsInstance = expressWs(app, undefined, { wsOptions: { maxPayload: 1024 * 1024 } });
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Behind Fly's proxy the client address comes from Fly-Client-IP (set by the edge, not
  // client-controllable); elsewhere fall back to req.ip.
  const clientIp = (req) => (config.trustFlyClientIp && str(req.headers['fly-client-ip'], 64)) || req.ip || 'unknown';
  const limiter = (limit, windowMs = MIN) => rateLimit({
    windowMs,
    limit: limit * config.ipLimitScale,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: clientIp,
    handler: (req, res) => res.status(429).json({ error: 'rate_limited' }),
  });

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'none'");
    res.setHeader('Strict-Transport-Security', 'max-age=15552000');
    next();
  });
  // Request log: method, path (no query string, no body), status, duration. Never message content or phone numbers.
  app.use((req, res, next) => {
    if (req.path === '/healthz') return next();
    const t = Date.now();
    res.on('finish', () => logger.log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - t}ms`));
    next();
  });
  const smallJson = express.json({ limit: '16kb' });
  const mcpJson = express.json({ limit: '256kb' });
  app.use((req, res, next) => (req.path === '/mcp' ? mcpJson : smallJson)(req, res, next));
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));
  const noStore = (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); };

  // phoneKey -> live WebSocket connection from the InboxIQ app.
  const phoneConnections = new Map();
  // correlationId -> { phoneKey, ws, resolve, reject, timeout }.
  const pendingRelayCalls = new Map();

  // ---------- helpers: counters, throttles ----------

  const q = {
    getCounter: db.prepare('SELECT window_start, count FROM rate_counters WHERE key = ?'),
    setCounter: db.prepare('INSERT INTO rate_counters (key, window_start, count) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET window_start = excluded.window_start, count = excluded.count'),
  };
  function counterValue(key, windowMs) {
    const r = q.getCounter.get(key);
    return r && Date.now() - r.window_start < windowMs ? r.count : 0;
  }
  function bump(key, windowMs) {
    const r = q.getCounter.get(key);
    const now = Date.now();
    if (!r || now - r.window_start >= windowMs) { q.setCounter.run(key, now, 1); return 1; }
    q.setCounter.run(key, r.window_start, r.count + 1);
    return r.count + 1;
  }
  /** Consumes one unit; false when the limit for the window is already reached. */
  function hit(key, windowMs, limit) {
    if (counterValue(key, windowMs) >= limit) return false;
    bump(key, windowMs);
    return true;
  }

  // ---------- purge ----------

  function purgeExpired() {
    const now = Date.now();
    const refreshCutoff = (c) => `(COALESCE(expires_at, created_at + ${config.refreshTtlMs}) < ${now} OR COALESCE(family_started_at, created_at) + ${config.refreshMaxMs} < ${now})${c}`;
    const out = {};
    out.auth_codes = db.prepare('DELETE FROM auth_codes WHERE expires_at < ?').run(now - HOUR).changes;
    out.access_tokens = db.prepare('DELETE FROM access_tokens WHERE expires_at < ?').run(now - HOUR).changes;
    out.refresh_tokens = db.prepare(`DELETE FROM refresh_tokens WHERE ${refreshCutoff('')} OR (rotated_at IS NOT NULL AND rotated_at < ${now - config.refreshRotationGraceMs})`).run().changes;
    out.otp_challenges = db.prepare('DELETE FROM otp_challenges WHERE expires_at < ?').run(now - HOUR).changes;
    out.rate_counters = db.prepare('DELETE FROM rate_counters WHERE window_start < ?').run(now - 2 * DAY).changes;
    // Clients that registered but never produced a code/token within 90 days.
    out.oauth_clients = db.prepare(`DELETE FROM oauth_clients WHERE created_at < ? AND client_id NOT IN (SELECT client_id FROM refresh_tokens) AND client_id NOT IN (SELECT client_id FROM access_tokens) AND client_id NOT IN (SELECT client_id FROM auth_codes)`).run(now - 90 * DAY).changes;
    return out;
  }

  // ---------- OAuth discovery + dynamic client registration ----------

  app.get('/.well-known/oauth-authorization-server', (req, res) => {
    res.json({
      issuer: config.issuer,
      authorization_endpoint: `${config.issuer}/authorize`,
      token_endpoint: `${config.issuer}/token`,
      registration_endpoint: `${config.issuer}/register`,
      revocation_endpoint: `${config.issuer}/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
    });
  });

  app.post('/register', noStore, limiter(10), (req, res) => {
    const body = req.body || {};
    const redirectUris = body.redirect_uris;
    const bad = (description) => res.status(400).json({ error: 'invalid_client_metadata', error_description: description });
    if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 5) return bad('redirect_uris is required (1-5 entries)');
    const policy = { policy: config.redirectPolicy, extraHosts: config.extraRedirectHosts };
    if (!redirectUris.every((u) => redirectUriAllowed(u, policy))) return bad('redirect_uri is not allowed');
    const clientName = typeof body.client_name === 'string' ? body.client_name.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 100) : '';
    if (!hit('register:global', HOUR, 200)) return res.status(429).json({ error: 'rate_limited' });

    const client_id = randomToken(16);
    db.prepare('INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, ?, ?, ?)')
      .run(client_id, clientName || 'Unnamed client', JSON.stringify(redirectUris), Date.now());
    res.status(201).json({
      client_id,
      client_name: clientName || 'Unnamed client',
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
    });
  });

  // ---------- /authorize: phone number -> OTP -> auth code ----------

  function hiddenInputs(params) {
    return Object.entries(params).map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v || '')}">`).join('\n');
  }
  function redirectHost(params) {
    try { return new URL(params.redirect_uri).host; } catch { return ''; }
  }

  function renderPhoneForm(params, error) {
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="font-family:sans-serif;max-width:420px;margin:40px auto">
    <h2>Connect InboxIQ</h2>
    <p>This will give <strong>${escapeHtml(redirectHost(params))}</strong> access to the messages in your InboxIQ app. Enter the phone number of the InboxIQ app you want to connect. We'll call you and read out a code.</p>
    ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/authorize/send-otp">
      ${hiddenInputs(params)}
      <input type="tel" name="phone_number" placeholder="+14155551234" required style="width:100%;padding:8px;font-size:16px">
      <button type="submit" style="margin-top:12px;padding:8px 16px">Call me with a code</button>
    </form>
  </body></html>`;
  }

  function renderOtpForm(params, phoneNumber, error) {
    return `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="font-family:sans-serif;max-width:420px;margin:40px auto">
    <h2>Enter the code from the call</h2>
    <p>We just called ${escapeHtml(phoneNumber)} and read out a 6-digit code — answer and listen for it.</p>
    ${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/authorize/verify-otp">
      ${hiddenInputs(params)}
      <input type="hidden" name="phone_number" value="${escapeHtml(phoneNumber)}">
      <input type="text" name="code" inputmode="numeric" placeholder="123456" required style="width:100%;padding:8px;font-size:16px">
      <button type="submit" style="margin-top:12px;padding:8px 16px">Verify</button>
    </form>
  </body></html>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function oauthParamsFrom(src) {
    const s = src || {};
    return {
      response_type: str(s.response_type), client_id: str(s.client_id), redirect_uri: str(s.redirect_uri),
      state: str(s.state), code_challenge: str(s.code_challenge), code_challenge_method: str(s.code_challenge_method), scope: str(s.scope),
    };
  }

  /** Returns an error string, or null when the request is acceptable. Re-run on every step. */
  function checkAuthorizeParams(params) {
    if (params.response_type !== 'code' || !params.client_id || !params.redirect_uri) return 'Invalid authorization request';
    if (!/^[A-Za-z0-9_-]{43}$/.test(params.code_challenge)) return 'Invalid authorization request';
    if (params.code_challenge_method && params.code_challenge_method !== 'S256') return 'Invalid authorization request';
    const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(params.client_id);
    let uris = [];
    try { uris = client ? JSON.parse(client.redirect_uris) : []; } catch { /* corrupt row: treated as unknown */ }
    if (!client || !uris.includes(params.redirect_uri)) return 'Unknown client or redirect_uri';
    if (!redirectUriAllowed(params.redirect_uri, { policy: config.redirectPolicy, extraHosts: config.extraRedirectHosts })) {
      logger.warn(`authorize rejected: redirect host not allowed (${redirectHost(params)})`);
      return 'Unknown client or redirect_uri';
    }
    return null;
  }

  function destinationAllowed(phone) {
    return config.otpAllowedPrefixes.length === 0 || config.otpAllowedPrefixes.some((p) => phone.startsWith(p));
  }

  /**
   * Creates an OTP challenge and delivers it. Enforces per-phone and global send limits.
   * Returns { id } or { error: 'rate_limited' | 'delivery_failed' | 'destination_not_allowed' }.
   */
  async function sendOtp(phone, purpose) {
    if (!destinationAllowed(phone)) return { error: 'destination_not_allowed' };
    const pk = phoneKey(phone);
    if (!hit(`otpsend:${pk}`, HOUR, config.otpMaxSendsPerHour)) return { error: 'rate_limited' };
    if (!hit('otpsend:global', DAY, config.otpGlobalDailyCap)) return { error: 'rate_limited' };

    const code = randomOtp();
    const id = randomToken(16);
    // Only the newest challenge per phone+purpose is ever valid.
    db.prepare('DELETE FROM otp_challenges WHERE phone_key = ? AND purpose = ?').run(pk, purpose);
    db.prepare('INSERT INTO otp_challenges (id, phone_number, phone_key, purpose, code_hash, attempts, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?)')
      .run(id, legacyCol(pk), pk, purpose, sha256(code), Date.now() + OTP_TTL_MS);
    try {
      await delivery.deliver(phone, code);
    } catch (err) {
      db.prepare('DELETE FROM otp_challenges WHERE id = ?').run(id);
      logger.error(`otp delivery failed (${err?.code || err?.name || 'error'})`);
      return { error: 'delivery_failed' };
    }
    return { id };
  }

  /** Checks a submitted code. Returns { ok: true } or { ok: false, reason }. A correct code is consumed. */
  function verifyOtp(phone, purpose, code, challengeId) {
    const pk = phoneKey(phone);
    if (counterValue(`otpfail:${pk}`, HOUR) >= config.otpMaxFailsPerHour) return { ok: false, reason: 'locked' };
    const challenge = challengeId
      ? db.prepare('SELECT * FROM otp_challenges WHERE id = ? AND phone_key = ? AND purpose = ?').get(challengeId, pk, purpose)
      : db.prepare('SELECT * FROM otp_challenges WHERE phone_key = ? AND purpose = ? ORDER BY expires_at DESC LIMIT 1').get(pk, purpose);
    if (!challenge || challenge.expires_at < Date.now()) return { ok: false, reason: 'expired' };
    if (challenge.attempts >= MAX_OTP_ATTEMPTS) return { ok: false, reason: 'attempts' };
    db.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(challenge.id);
    const submitted = String(code ?? '').trim();
    if (!/^\d{6}$/.test(submitted) || !safeEqual(sha256(submitted), challenge.code_hash)) {
      bump(`otpfail:${pk}`, HOUR);
      return { ok: false, reason: 'wrong' };
    }
    db.prepare('DELETE FROM otp_challenges WHERE id = ?').run(challenge.id); // single use
    return { ok: true };
  }

  app.get('/authorize', noStore, limiter(20), (req, res) => {
    const params = oauthParamsFrom(req.query);
    const err = checkAuthorizeParams(params);
    if (err) return res.status(400).send(err);
    res.send(renderPhoneForm(params));
  });

  const sendMessage = {
    rate_limited: 'Too many attempts for this number — please try again later.',
    delivery_failed: 'We could not place the call. Check the number and try again later.',
    destination_not_allowed: 'Calls to this number are not supported.',
  };

  app.post('/authorize/send-otp', noStore, limiter(5), async (req, res, next) => {
    try {
      const params = oauthParamsFrom(req.body);
      const err = checkAuthorizeParams(params);
      if (err) return res.status(400).send(err);
      const phone = normalizePhone(req.body?.phone_number);
      if (!phone) return res.send(renderPhoneForm(params, 'Enter a valid phone number in +1XXXXXXXXXX format.'));
      if (!delivery.configured) return res.status(500).send('Verification delivery is not configured.');
      const sent = await sendOtp(phone, 'auth');
      if (sent.error) return res.send(renderPhoneForm(params, sendMessage[sent.error]));
      res.send(renderOtpForm(params, phone));
    } catch (e) { next(e); }
  });

  app.post('/authorize/verify-otp', noStore, limiter(10), (req, res) => {
    const params = oauthParamsFrom(req.body);
    const err = checkAuthorizeParams(params);
    if (err) return res.status(400).send(err);
    const phone = normalizePhone(req.body?.phone_number);
    if (!phone) return res.send(renderPhoneForm(params, 'Enter a valid phone number in +1XXXXXXXXXX format.'));

    const v = verifyOtp(phone, 'auth', req.body.code);
    if (!v.ok) {
      if (v.reason === 'wrong') return res.send(renderOtpForm(params, phone, 'Wrong code, try again.'));
      if (v.reason === 'locked') return res.send(renderPhoneForm(params, 'Too many wrong codes for this number — try again in an hour.'));
      return res.send(renderPhoneForm(params, v.reason === 'attempts' ? 'Too many attempts — enter your number again.' : 'That code expired — enter your number again.'));
    }

    const pk = phoneKey(phone);
    const authCode = randomToken(24);
    db.prepare(`INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, phone_number, phone_key, expires_at, used)
                VALUES (?, ?, ?, ?, 'S256', ?, ?, ?, 0)`)
      .run(sha256(authCode), params.client_id, params.redirect_uri, params.code_challenge, legacyCol(pk), pk, Date.now() + AUTH_CODE_TTL_MS);

    const redirect = new URL(params.redirect_uri);
    redirect.searchParams.set('code', authCode);
    if (params.state) redirect.searchParams.set('state', params.state);
    res.redirect(redirect.toString());
  });

  // ---------- /token ----------

  function issueTokens(clientId, pk, { grantId = null, refresh = null } = {}) {
    const now = Date.now();
    const accessToken = randomToken();
    db.prepare('INSERT INTO access_tokens (token_hash, client_id, phone_number, phone_key, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(sha256(accessToken), clientId, legacyCol(pk), pk, grantId, now, now + config.accessTtlMs);

    let refreshToken = refresh?.reuse;
    if (refreshToken) {
      const started = refresh.familyStartedAt;
      db.prepare('UPDATE refresh_tokens SET expires_at = ?, last_used_at = ?, family_started_at = COALESCE(family_started_at, ?) WHERE token_hash = ?')
        .run(Math.min(now + config.refreshTtlMs, started + config.refreshMaxMs), now, started, sha256(refreshToken));
    } else {
      refreshToken = randomToken();
      const started = refresh?.familyStartedAt ?? now;
      db.prepare('INSERT INTO refresh_tokens (token_hash, client_id, phone_number, phone_key, grant_id, created_at, expires_at, family_started_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(sha256(refreshToken), clientId, legacyCol(pk), pk, grantId, now, Math.min(now + config.refreshTtlMs, started + config.refreshMaxMs), started, now);
    }
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: Math.floor(config.accessTtlMs / 1000),
      refresh_token: refreshToken,
    };
  }

  const revokeGrant = (clientId, pk) => {
    db.prepare('DELETE FROM refresh_tokens WHERE phone_key = ? AND client_id = ?').run(pk, clientId);
    db.prepare('DELETE FROM access_tokens WHERE phone_key = ? AND client_id = ?').run(pk, clientId);
  };
  const revokePhoneTokens = (pk) => {
    db.prepare('DELETE FROM refresh_tokens WHERE phone_key = ?').run(pk);
    db.prepare('DELETE FROM access_tokens WHERE phone_key = ?').run(pk);
  };
  // Rows written before phone_key existed are backfilled at startup; this is only a safety net.
  const rowKey = (row) => row.phone_key || phoneKey(row.phone_number);

  app.post('/token', noStore, limiter(20), (req, res) => {
    const body = req.body || {};
    const grant_type = str(body.grant_type, 64);
    const invalid = (extra) => res.status(400).json({ error: 'invalid_grant', ...extra });

    if (grant_type === 'authorization_code') {
      const code = str(body.code, 256);
      const codeHash = sha256(code);
      // Codes are stored hashed.
      const row = db.prepare('SELECT * FROM auth_codes WHERE code = ?').get(codeHash);
      if (!code || !row) return invalid();
      if (row.used) {
        // Replay of a spent code: revoke whatever it already produced (RFC 6749 4.1.2).
        db.prepare('DELETE FROM access_tokens WHERE grant_id = ?').run(codeHash);
        db.prepare('DELETE FROM refresh_tokens WHERE grant_id = ?').run(codeHash);
        return invalid();
      }
      if (row.expires_at < Date.now()) return invalid();
      if (row.client_id !== str(body.client_id) || row.redirect_uri !== str(body.redirect_uri)) return invalid();
      if (!verifyPkce(body.code_verifier, row.code_challenge)) return invalid({ error_description: 'PKCE verification failed' });
      db.prepare('UPDATE auth_codes SET used = 1 WHERE code = ?').run(row.code);
      return res.json(issueTokens(row.client_id, rowKey(row), { grantId: codeHash }));
    }

    if (grant_type === 'refresh_token') {
      const refreshToken = str(body.refresh_token, 256);
      const clientId = str(body.client_id);
      const row = refreshToken ? db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(sha256(refreshToken)) : null;
      if (!row || row.client_id !== clientId) return invalid();

      const now = Date.now();
      const started = row.family_started_at ?? row.created_at;
      const expires = row.expires_at ?? row.created_at + config.refreshTtlMs;
      if (now > expires || now > started + config.refreshMaxMs) {
        db.prepare('DELETE FROM refresh_tokens WHERE token_hash = ?').run(row.token_hash);
        return invalid();
      }
      const pk = rowKey(row);
      if (config.refreshRotation) {
        if (row.rotated_at && now - row.rotated_at > config.refreshRotationGraceMs) {
          revokeGrant(clientId, pk); // a rotated-out token came back late: treat as theft
          return invalid();
        }
        if (!row.rotated_at) db.prepare('UPDATE refresh_tokens SET rotated_at = ? WHERE token_hash = ?').run(now, row.token_hash);
        return res.json(issueTokens(clientId, pk, { grantId: row.grant_id, refresh: { familyStartedAt: started } }));
      }
      return res.json(issueTokens(clientId, pk, { grantId: row.grant_id, refresh: { reuse: refreshToken, familyStartedAt: started } }));
    }

    res.status(400).json({ error: 'unsupported_grant_type' });
  });

  // RFC 7009 token revocation. Always 200, whether or not the token existed.
  app.post('/revoke', noStore, limiter(20), (req, res) => {
    const token = str(req.body?.token, 256);
    const clientId = str(req.body?.client_id);
    if (token) {
      const h = sha256(token);
      const r = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(h);
      if (r && r.client_id === clientId) revokeGrant(clientId, rowKey(r));
      const a = db.prepare('SELECT * FROM access_tokens WHERE token_hash = ?').get(h);
      if (a && a.client_id === clientId) db.prepare('DELETE FROM access_tokens WHERE token_hash = ?').run(h);
    }
    res.status(200).json({});
  });

  // ---------- Phone linking ----------

  const RELAY_TOKEN_RE = /^[A-Za-z0-9_-]{32,256}$/;

  function closeSocket(pk, code = 4401, reason = 'unauthorized') {
    const ws = phoneConnections.get(pk);
    if (ws) { try { ws.close(code, reason); } catch { /* already closing */ } phoneConnections.delete(pk); }
    failPending(pk, 'phone_not_connected');
  }
  function failPending(pk, message) {
    for (const [id, p] of pendingRelayCalls) {
      if (p.phoneKey === pk) { clearTimeout(p.timeout); pendingRelayCalls.delete(id); p.reject(new Error(message)); }
    }
  }
  function relayAuth(req) {
    const auth = str(req.headers['authorization'], 512);
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    return token ? db.prepare('SELECT * FROM phone_links WHERE relay_token_hash = ?').get(sha256(token)) : null;
  }

  // Step 1 of an OTP-verified link: call the phone number with a code. Not used by app <= 0.4.1.
  app.post('/phone/link/start', noStore, limiter(5), async (req, res, next) => {
    try {
      const phone = normalizePhone(req.body?.phone_number);
      if (!phone) return res.status(400).json({ error: 'invalid_phone_number' });
      if (!delivery.configured) return res.status(503).json({ error: 'otp_delivery_unavailable' });
      const sent = await sendOtp(phone, 'link');
      if (sent.error === 'rate_limited') return res.status(429).json({ error: 'rate_limited' });
      if (sent.error === 'destination_not_allowed') return res.status(400).json({ error: 'destination_not_allowed' });
      if (sent.error) return res.status(502).json({ error: 'delivery_failed' });
      res.json({ challenge_id: sent.id, expires_in: OTP_TTL_MS / 1000 });
    } catch (e) { next(e); }
  });

  // The InboxIQ app links its phone number to a relay token it generated itself.
  //  - with otp_code (+ challenge_id): proof of number ownership; creates or replaces the link.
  //  - without (legacy app <= 0.4.1): only while LEGACY_LINK_COMPAT is on, and only trust-on-first-use:
  //    an existing link can be re-confirmed with the same token but never overwritten.
  app.post('/phone/link', noStore, limiter(10), (req, res) => {
    const body = req.body || {};
    const phone = normalizePhone(body.phone_number);
    const relayToken = body.relay_token;
    if (!phone || typeof relayToken !== 'string' || !RELAY_TOKEN_RE.test(relayToken)) {
      return res.status(400).json({ error: 'phone_number and relay_token are required' });
    }
    const pk = phoneKey(phone);
    if (!hit(`link:${pk}`, 15 * MIN, 10)) return res.status(429).json({ error: 'rate_limited' });
    const tokenHash = sha256(relayToken);
    const existing = db.prepare('SELECT * FROM phone_links WHERE phone_key = ?').get(pk);
    const now = Date.now();

    if (body.otp_code !== undefined) {
      const v = verifyOtp(phone, 'link', body.otp_code, str(body.challenge_id, 64) || undefined);
      if (!v.ok) {
        if (v.reason === 'locked') return res.status(429).json({ error: 'rate_limited' });
        return res.status(401).json({ error: v.reason === 'wrong' ? 'otp_invalid' : 'otp_expired' });
      }
      const replaced = !!existing && !safeEqual(existing.relay_token_hash, tokenHash);
      db.prepare(`INSERT INTO phone_links (phone_number, phone_key, relay_token_hash, link_proof, linked_at, last_connected_at)
                  VALUES (?, ?, ?, 'otp', ?, NULL)
                  ON CONFLICT(phone_key) DO UPDATE SET relay_token_hash = excluded.relay_token_hash, link_proof = 'otp', linked_at = excluded.linked_at`)
        .run(legacyCol(pk), pk, tokenHash, now);
      if (replaced) closeSocket(pk, 4401, 'replaced');
      return res.json({ ok: true, link_proof: 'otp', replaced });
    }

    if (!config.legacyLinkCompat) return res.status(403).json({ error: 'otp_required' });

    if (existing) {
      if (safeEqual(existing.relay_token_hash, tokenHash)) {
        return res.json({ ok: true, link_proof: existing.link_proof || 'legacy' });
      }
      const staleMs = config.legacyRelinkStaleDays * DAY;
      const lastSeen = existing.last_connected_at ?? existing.linked_at;
      if (existing.link_proof !== 'otp' && staleMs > 0 && now - lastSeen > staleMs) {
        db.prepare("UPDATE phone_links SET relay_token_hash = ?, link_proof = 'tofu', linked_at = ?, last_connected_at = NULL WHERE phone_key = ?").run(tokenHash, now, pk);
        closeSocket(pk, 4401, 'replaced');
        return res.json({ ok: true, link_proof: 'tofu' });
      }
      return res.status(409).json({ error: 'link_conflict', otp_required: true });
    }

    if (!hit(`legacylink:${clientIp(req)}`, HOUR, config.legacyNewLinksPerIpPerHour * config.ipLimitScale)) {
      return res.status(429).json({ error: 'rate_limited' });
    }
    db.prepare(`INSERT INTO phone_links (phone_number, phone_key, relay_token_hash, link_proof, linked_at, last_connected_at)
                VALUES (?, ?, ?, 'tofu', ?, NULL)`).run(legacyCol(pk), pk, tokenHash, now);
    res.json({ ok: true, link_proof: 'tofu' });
  });

  // Unlink: removes the link and revokes every OAuth grant for the number. Authenticated by the relay token.
  const failedRelayAuth = limiter(10);
  app.delete('/phone/link', noStore, failedRelayAuth, (req, res) => {
    const link = relayAuth(req);
    if (!link) return res.status(401).json({ error: 'unauthorized' });
    const pk = rowKey(link);
    db.transaction(() => {
      revokePhoneTokens(pk);
      db.prepare('DELETE FROM phone_links WHERE relay_token_hash = ?').run(link.relay_token_hash);
    })();
    closeSocket(pk, 4401, 'unlinked');
    res.json({ ok: true });
  });

  // Revoke every Claude (OAuth) grant for this number but keep the link.
  app.delete('/phone/tokens', noStore, failedRelayAuth, (req, res) => {
    const link = relayAuth(req);
    if (!link) return res.status(401).json({ error: 'unauthorized' });
    revokePhoneTokens(rowKey(link));
    res.json({ ok: true });
  });

  // ---------- WebSocket relay ----------

  app.ws('/phone-ws', (ws, req) => {
    const link = relayAuth(req);
    if (!link) {
      ws.close(4401, 'unauthorized');
      return;
    }

    const pk = rowKey(link);
    const previous = phoneConnections.get(pk);
    phoneConnections.set(pk, ws);
    if (previous && previous !== ws) { try { previous.terminate(); } catch { /* gone */ } }
    db.prepare('UPDATE phone_links SET last_connected_at = ? WHERE phone_key = ?').run(Date.now(), pk);

    let alive = true;
    ws.on('pong', () => { alive = true; });
    const heartbeat = setInterval(() => {
      if (!alive) return ws.terminate();
      alive = false;
      try { ws.ping(); } catch { /* closing */ }
    }, 30_000);
    heartbeat.unref?.();

    ws.on('error', () => { /* connection-level errors end in 'close' */ });
    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch { return; }
      if (!msg || typeof msg !== 'object') return;
      const pending = pendingRelayCalls.get(msg.correlationId);
      // A reply only counts if it comes from the socket the request was sent to.
      if (pending && pending.ws === ws) {
        clearTimeout(pending.timeout);
        pendingRelayCalls.delete(msg.correlationId);
        pending.resolve(msg.payload);
      }
    });

    ws.on('close', () => {
      clearInterval(heartbeat);
      if (phoneConnections.get(pk) === ws) phoneConnections.delete(pk);
      for (const [id, p] of pendingRelayCalls) {
        if (p.ws === ws) { clearTimeout(p.timeout); pendingRelayCalls.delete(id); p.reject(new Error('phone_not_connected')); }
      }
    });
  });

  function relayToPhone(pk, payload) {
    const ws = phoneConnections.get(pk);
    if (!ws || ws.readyState !== ws.OPEN) return Promise.reject(new Error('phone_not_connected'));
    let inFlight = 0;
    for (const p of pendingRelayCalls.values()) if (p.phoneKey === pk) inFlight++;
    if (inFlight >= config.maxPendingPerPhone) return Promise.reject(new Error('too_many_requests'));

    const correlationId = randomToken(16);
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pendingRelayCalls.delete(correlationId);
        reject(new Error('relay_timeout'));
      }, RELAY_TIMEOUT_MS);
      pendingRelayCalls.set(correlationId, { phoneKey: pk, ws, resolve, reject, timeout });
      ws.send(JSON.stringify({ correlationId, payload }));
    });
  }

  // ---------- /mcp: what Claude actually calls after OAuth ----------

  app.post('/mcp', limiter(120), async (req, res) => {
    const auth = str(req.headers['authorization'], 512);
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const unauthorized = (error) => {
      res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
      return res.status(401).json({ error });
    };
    if (!token) return unauthorized('missing_token');

    const row = db.prepare('SELECT * FROM access_tokens WHERE token_hash = ?').get(sha256(token));
    if (!row || row.expires_at < Date.now()) return unauthorized('invalid_or_expired_token');
    if (!req.body || typeof req.body !== 'object') return res.status(400).json({ error: 'invalid_request' });

    try {
      const result = await relayToPhone(rowKey(row), req.body);
      res.json(result === undefined ? {} : result);
    } catch (err) {
      const map = { phone_not_connected: 503, too_many_requests: 429, relay_timeout: 504 };
      const status = map[err.message] || 502;
      res.status(status).json({ error: map[err.message] ? err.message : 'relay_failed' });
    }
  });

  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // Last-resort handlers: never leak stack traces or internals.
  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large' });
    if (err?.type === 'entity.parse.failed' || err?.status === 400) return res.status(400).json({ error: 'invalid_request' });
    logger.error(`unhandled error (${err?.code || err?.name || 'error'})`);
    res.status(500).json({ error: 'server_error' });
  });

  return { app, wsInstance, purgeExpired, phoneConnections, pendingRelayCalls, config };
}
