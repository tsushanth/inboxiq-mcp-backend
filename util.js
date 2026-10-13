import crypto from 'crypto';

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** Constant-time string comparison (hashes both sides first so lengths never leak). */
export function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// PKCE S256 verification per RFC 7636.
export function verifyPkce(codeVerifier, codeChallenge) {
  if (typeof codeVerifier !== 'string' || !/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) return false;
  const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return safeEqual(computed, codeChallenge);
}

export function randomOtp() {
  return String(crypto.randomInt(100000, 999999));
}

/** "482913" -> "4. 8. 2. 9. 1. 3." — spoken with <Say>, gives each digit its own pause
 *  instead of being read as a six-digit number, which is hard to catch by ear. */
export function spellOutDigits(code) {
  return code.split('').join('. ') + '.';
}

/** Returns a strict E.164 number ("+" and 8-15 digits, no leading 0) or null. Cosmetic
 *  separators (space, dash, dot, parentheses) are tolerated. */
export function normalizePhone(input) {
  if (typeof input !== 'string' || input.length > 32) return null;
  const compact = input.replace(/[\s\-.()]/g, '');
  return /^\+[1-9]\d{7,14}$/.test(compact) ? compact : null;
}

/**
 * How a phone number is keyed in the database. With a secret, the key is a keyed hash
 * (HMAC-SHA256), so a copy of the database does not reveal phone numbers. Without one it
 * is the number itself (identical to the pre-hardening behaviour, which keeps a rollback
 * to the previous release safe).
 */
export function makePhoneKeyFn(secret) {
  if (!secret) return (phone) => phone;
  return (phone) => crypto.createHmac('sha256', secret).update(`inboxiq-phone-v1:${phone}`).digest('hex');
}

const DEFAULT_REDIRECT_HOSTS = ['claude.ai', 'www.claude.ai', 'claude.com', 'www.claude.com'];
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const FORBIDDEN_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:']);

/**
 * redirect_uri policy for dynamic client registration and /authorize.
 * strict (default): https on an allowed host (claude.ai / claude.com + extra hosts), or
 *   http on a loopback address (RFC 8252 native/CLI clients).
 * permissive: additionally any https host and private-use custom schemes.
 * Fragments and embedded credentials are always rejected.
 */
export function redirectUriAllowed(uri, { policy = 'strict', extraHosts = [] } = {}) {
  if (typeof uri !== 'string' || uri.length > 2000) return false;
  let u;
  try { u = new URL(uri); } catch { return false; }
  if (u.hash || u.username || u.password) return false;
  if (FORBIDDEN_SCHEMES.has(u.protocol)) return false;
  if (u.protocol === 'http:') return LOOPBACK_HOSTS.has(u.hostname);
  if (u.protocol === 'https:') {
    if (DEFAULT_REDIRECT_HOSTS.includes(u.hostname) || extraHosts.includes(u.hostname)) return true;
    return policy === 'permissive';
  }
  return policy === 'permissive' && /^[a-z][a-z0-9+.-]*:$/.test(u.protocol);
}
