# Security review: InboxIQ MCP relay backend

Scope: `server.js`, `db.js`, `util.js` as of `main` (commit `83eef41`), plus the Android client in
`InboxIQ/app/.../mcp/` for protocol compatibility. Findings are ranked by real exploitability against
the live service. File:line references are to the code **before** this branch (`git show 83eef41:server.js`).
This document describes what was fixed and what risk remains; it deliberately omits exploit recipes for
anything that is still open.

Message bodies: confirmed memory-only. `/mcp` request bodies and WebSocket replies live in a `Map` entry
for the duration of one relay call (max 30 s) and are never written to SQLite or logs. This is now enforced
by a test (`test/relay.test.js`, "message bodies pass through memory only") that scans every table, the
DB file, the WAL and captured logs. The request log records method, path (no query string), status and
duration only. Phone numbers are not logged.

## Findings

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | High | `/phone/link` is unauthenticated and overwrites any number's link | Fixed (residual: see R1, R2) |
| 2 | High | Open client registration + unrestricted `redirect_uri` + steps that trust hidden form fields | Fixed |
| 3 | High | A Twilio error or a malformed WebSocket frame can crash the whole process | Fixed |
| 4 | Medium | OTP: per-IP limits only, unlimited fresh challenges per number, OTP not consumed, toll-fraud exposure | Fixed |
| 5 | Medium | Refresh tokens never expire; no revoke, no unlink | Fixed |
| 6 | Medium | Relay: reply accepted from any socket, no per-phone cap, no frame size cap, no heartbeat | Fixed |
| 7 | Medium | Phone numbers in plaintext; expired rows never purged | Fixed (hashing is opt-in, needs a secret) |
| 8 | Low | PKCE/auth-code weaknesses (method not enforced, raw codes at rest, no replay revocation) | Fixed |
| 9 | Low | Error leakage (Express stack traces because `NODE_ENV` unset) | Fixed |
| 10 | Low | Missing headers (clickjacking of the authorize form, `no-store`) | Fixed |
| 11 | Low | Loose input handling (`extended` urlencoded, array params, lax phone regex) | Fixed |
| 12 | Info | SQL injection, SSRF, CORS, token entropy, trust proxy | No issue / noted below |

### 1. Unauthenticated phone link overwrite (High)
Evidence: `server.js:230-241`. `POST /phone/link` took `phone_number` + `relay_token` from the body and ran
`INSERT ... ON CONFLICT(phone_number) DO UPDATE SET relay_token_hash = excluded.relay_token_hash`.
Nothing proved the caller owned the number (the Android app sends whatever number the user typed,
`CloudConnectSection.kt`). Anyone who knew a linked number could replace the legitimate app's credential;
the next `/phone-ws` connection from the attacker's token became that number's socket (`server.js:243-254`),
so the victim's Claude would send tool calls (search queries, draft text content) to the attacker and the
attacker could answer with fabricated message data.
Fix: see "Link binding" below. An existing link can no longer be replaced without proof of the number
(a fresh Twilio voice OTP); legacy clients get trust-on-first-use.

### 2. Dynamic registration / redirect_uri / hidden-field trust (High)
Evidence: `server.js:54-68` (any `redirect_uris`, no scheme or host check, unbounded size, no cap on rows),
`server.js:144-170` (`/authorize/verify-otp` took `client_id`/`redirect_uri` from hidden form fields without
re-checking them against the registered client), `server.js:72-84` (consent page named no requester).
Impact: anyone could register a client pointing at their own server, lure a user into the standard flow, and
receive an authorization code for the victim's number once the victim typed the OTP they were called with
(PKCE does not help when the attacker is the client).
Fix: `redirect_uri` policy (https on `claude.ai`/`claude.com` or loopback http by default, configurable),
enforced at registration **and** on every authorize step (so clients registered earlier with a foreign
redirect are also refused); registration limits (1-5 URIs, 2000 chars, name 100 chars, 200 registrations
per hour globally); the consent page now shows the redirect host; every step re-validates the whole
parameter set. Residual R4.

### 3. Process crash (High, availability)
Evidence: `server.js:139` awaits `twilioClient.calls.create(...)` in an async Express 4 handler with no
`try/catch`; a Twilio rejection (bad or unreachable number, account issue) becomes an unhandled rejection,
which terminates the process on Node 20 (service-wide outage until Fly restarts the machine, dropping every
live WebSocket). `server.js:259`: `JSON.parse(raw)` returning `null` makes `msg.correlationId` throw inside
an event handler (uncaught exception) - reachable by any authenticated phone socket.
These are from code reading; they were not reproduced against production.
Fix: delivery errors are caught and surfaced as a generic message (Twilio error text, which can contain the
number, is not logged); frames are type-checked; `unhandledRejection` is logged rather than fatal.
`uncaughtException` is intentionally *not* swallowed.

### 4. OTP abuse (Medium)
Evidence: limits were per IP only (`server.js:31`, 5/min shared by send and verify). Each `send-otp` created
a new challenge with a fresh 5-guess budget and no cap per number (`server.js:122-142`), so guesses were
bounded only by how many calls could be placed; a correct OTP was not consumed (`server.js:157-170`) and
could mint several auth codes in its 5-minute life; `send-otp` would call any E.164 number worldwide
(harassment of a victim, premium-rate/toll-fraud cost on the owner's Twilio account).
Fix: per-number send cap (4/hour), per-number failed-verify lockout (10/hour, persisted in SQLite so it
survives restarts), per-challenge 5 attempts, only the newest challenge per number and purpose is valid,
the OTP is deleted on success, constant-time comparison, strict `^\d{6}$`, a global daily call cap
(300/day) as a spend circuit breaker, and an optional destination prefix allowlist
(`OTP_ALLOWED_COUNTRY_PREFIXES`). Trade-off: a lockout or send cap can be triggered against a known number
by a third party (R3).

### 5. Refresh tokens / revocation (Medium)
Evidence: `server.js:194-201`, `db.js` `refresh_tokens` had no expiry and no revoke; there was no unlink.
Fix: sliding 90-day expiry (`REFRESH_TTL_DAYS`) with a 365-day absolute cap (`REFRESH_MAX_DAYS`); optional
rotation with a grace window and reuse detection (`REFRESH_ROTATION=1`, **off by default for the first
deploy**, see DEPLOY.md); `POST /revoke` (RFC 7009); `DELETE /phone/link` (unlink, revokes all grants and
closes the socket); `DELETE /phone/tokens` (revoke all Claude grants, keep the link). Replay of a spent
authorization code now revokes the tokens it produced.

### 6. Relay matching and resource limits (Medium)
Routing itself was correct: `/mcp` resolves access token -> `phone_number` -> that number's socket, and
`/phone-ws` resolves the relay-token hash -> link. Problems: `pendingRelayCalls` was keyed by correlation id
only, so any connected phone replying with a matching id would resolve another phone's call (ids are 64-bit
random, so this needed a leak, but it is a missing check); unlimited in-flight calls per phone; `ws` default
`maxPayload` (100 MiB) on a 256 MB machine; no ping/pong so dead sockets lingered; a closed socket left its
pending calls to time out.
Fix: replies are accepted only from the socket the request was sent to; 128-bit correlation ids; 16 in-flight
calls per phone (429); 1 MiB frame cap; 30 s ping/pong heartbeat; pending calls fail immediately (503) when
the socket closes; `/mcp` body limit 256 KB (others 16 KB).

### 7. Plaintext phone numbers, no purge (Medium)
Evidence: `db.js` stores `phone_number` in five tables; nothing deleted expired rows.
Fix: a purge job runs at start and hourly (expired auth codes, access tokens, refresh tokens, OTP
challenges, counters, and registered clients that never produced a grant in 90 days). Links are never
purged. Phone numbers are only ever used for equality lookups, so with `PHONE_HASH_SECRET` set they are
stored as HMAC-SHA256 keys and new rows contain no plaintext. Existing rows are backfilled additively;
the plaintext columns are only overwritten by an explicit, irreversible `SCRUB_PLAINTEXT_PHONES=1` boot
(because that makes rollback to the old image impossible). The server refuses to start if a hashed
database is opened without the secret, or with a different one.
Residual R5.

### 8-11. Lower severity
- PKCE (`server.js:164,186`): method defaulted silently and `plain` was stored; now only `S256` is accepted,
  challenge and verifier formats are validated (43-128 unreserved chars), comparison is constant-time, auth
  codes are stored hashed.
- Errors: `NODE_ENV` was unset in the image, so Express returned stack traces for e.g. malformed JSON. The
  image now sets `NODE_ENV=production` and a final error handler returns generic JSON.
- Headers added: `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`,
  HSTS, `Cache-Control: no-store` on OAuth and link endpoints; `X-Powered-By` removed.
- Input: `express.urlencoded({extended:false})`, string coercion of every field (array/object parameters no
  longer reach the logic), strict E.164 (`^\+[1-9]\d{7,14}$`; the old regex accepted strings like `+1+415...`),
  relay tokens must be 32-256 chars of base64url.

### 12. Checked, no issue
- SQL injection: every statement is parameterized; the only interpolated SQL is table/column names from
  constants and purge cut-off numbers computed server-side.
- SSRF: the service makes no outbound request to user-controlled URLs. Its only outbound call is the Twilio
  API (destination number is user-supplied; see 4).
- CORS: not enabled, so browsers cannot read responses cross-origin; all clients (Claude backend, Android
  app) are non-browser. Left as is.
- Token entropy: access/refresh/auth-code/relay tokens are 192-256 bits from `crypto.randomBytes`; stored as
  SHA-256 hashes; the lookup is by hash so there is no timing channel on the token itself.
- Trust proxy: `trust proxy = 1` is correct for Fly (one proxy hop). Rate limiting now keys on `Fly-Client-IP`
  when running on Fly (set by the edge, not client-controllable) and on `req.ip` elsewhere. Limiter state is
  in memory (single machine, fine); the per-number and global limits are persisted in SQLite.
- WebSocket auth: Bearer relay token in the `Authorization` header (browsers cannot set it; no Origin check
  is needed). Unknown tokens are closed with 4401.

## Link binding (the design)

Goal: only the legitimate app instance may (re)link a number, existing app versions 0.4.0/0.4.1 keep working,
and a reinstall / new phone has a safe path.

- **New clients** call `POST /phone/link/start` (a voice call with a 6-digit code, same Twilio delivery as
  `/authorize`) and then `POST /phone/link` with `challenge_id` + `otp_code`. A valid OTP proves control of
  the number and may create or **replace** the link (the replaced device's socket is closed with 4401).
  Link rows record `link_proof = 'otp'`.
- **Legacy clients (<= 0.4.1)** send only `phone_number` + `relay_token`, with no OTP. While
  `LEGACY_LINK_COMPAT=1` (default): the first token seen for a number becomes its owner (`link_proof = 'tofu'`);
  the same token re-sent is a no-op `200`; a different token gets `409 link_conflict` and never overwrites.
  Legacy responses keep the `{"ok": true}` shape (extra fields are ignored by the old app, which only checks
  the HTTP status).
- **Existing production rows** keep their `relay_token_hash`; they have `link_proof = NULL` (treated as
  legacy). The installed app keeps reconnecting its WebSocket with the same persistent token, so nothing
  changes for linked users. The first token to be re-sent for them is theirs (the app stores its token in
  SharedPreferences and re-sends it every time the toggle is enabled).
- **Trade-off for legacy users:** an old-app user who reinstalls (new relay token) will get `409` until they
  update the app and re-verify by OTP. `LEGACY_RELINK_STALE_DAYS=N` (default 0 = off) optionally lets a legacy
  client take over a non-OTP link whose app has been silent for N days, which covers reinstalls at the price
  of a takeover window; it can never override an OTP-verified link.
- **Turning compat off** (`LEGACY_LINK_COMPAT=0`) makes OTP mandatory for every link and `/phone/link`
  without OTP returns `403 otp_required`. Proposed trigger: the app release that implements the OTP flow
  has been at 100% on Play for at least 30 days and the live-connection count of legacy-proof links is
  zero or acceptable. The date is an owner decision (DEPLOY.md, decision 3).

## Residual risks

- **R1. Pre-deploy hijacks are undetectable.** If a number was already hijacked before this deploy, that
  attacker's token is the one now protected. Nothing in the data distinguishes it. Mitigation: the owner
  re-verifies their own link by OTP with the updated app (this replaces any attacker's link and closes
  their socket). Production currently has one machine and a small number of rows; the owner may want to
  check `phone_links` (`last_connected_at`, `linked_at`) over `fly ssh` read-only before and after deploy.
- **R2. Trust-on-first-use squatting.** Until compat is turned off, a legacy-style request can claim a
  number nobody has linked yet. The real owner recovers by OTP (which wins over TOFU), but an old-app owner
  cannot until they update. Claims are limited to 10 new numbers per IP per hour and 10 attempts per
  number per 15 minutes. `409` versus `200` also reveals whether a number is linked (rate-limited).
- **R3. Lockout and quota are triggerable by a third party.** Anyone who knows a number can burn its hourly
  send cap or failed-code budget and delay that user's authorization by up to an hour. Chosen over
  allowing brute force or call spam.
- **R4. Consent is thin.** The page names the redirect host but there is no separate approval screen, and
  the voice call does not name the requesting application (the call text was deliberately not changed).
  With the default policy only `claude.ai`, `claude.com` and loopback redirects can be registered.
- **R5. Hashing limits.** Phone numbers have low entropy, so hashed keys protect against a copied database
  only while the secret stays secret; the secret cannot be rotated without re-keying. Fly volume snapshots
  taken before a scrub keep plaintext until they expire. Phone numbers also appear in `rate_counters`
  keys only when hashing is off (purged after 2 days).
- **R6. Rate limits per IP are per IPv6 address.** An attacker with a /64 can rotate addresses; per-number
  and global limits still apply to OTP and calls.
- **R7. Relay token has no rotation or expiry.** It is a 256-bit device credential; it is replaced only by an
  OTP re-link or removed by unlink. Access tokens last 1 hour.
- **R8. Not verified:** behavior against the real Claude connector (refresh rotation handling, redirect URI
  actually registered, `WWW-Authenticate` / protected-resource metadata expectations), the real Android
  client, real Twilio, and a Docker build of the image. See DEPLOY.md for the checks to do after deploy.
- Two devices sharing one relay token will fight over the socket (the newest wins); unchanged behavior.
