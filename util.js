import crypto from 'crypto';

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// PKCE S256 verification per RFC 7636.
export function verifyPkce(codeVerifier, codeChallenge) {
  const computed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return computed === codeChallenge;
}

export function randomOtp() {
  return String(crypto.randomInt(100000, 999999));
}

export function normalizePhone(input) {
  const digits = String(input).replace(/[^\d+]/g, '');
  if (!digits.startsWith('+')) return null;
  if (digits.length < 8 || digits.length > 16) return null;
  return digits;
}
