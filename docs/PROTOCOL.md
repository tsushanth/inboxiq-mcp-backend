# API contract (after the security-fixes branch)

Base URL: `https://mcp.kreativekoala.llc`. JSON bodies unless noted. All responses carry
`X-Content-Type-Options: nosniff`; OAuth and link endpoints send `Cache-Control: no-store`.
Marker legend: **[old]** = used by the installed app 0.4.0/0.4.1 and unchanged; **[new]** = new, ignored
by old clients (they never call it); **[compat]** = behavior that exists only while `LEGACY_LINK_COMPAT=1`.

Generic error body: `{"error": "<code>"}`. Unhandled failures are `500 {"error":"server_error"}` with no detail.
Rate limited requests: `429 {"error":"rate_limited"}`.

## Phone link (Android app)

Phone numbers are strict E.164: `+` then 8-15 digits, first digit 1-9. Spaces, dashes, dots and parentheses
are stripped. `relay_token`: 32-256 characters of `[A-Za-z0-9_-]` (the app's 43-char base64url token is fine).

### POST /phone/link/start  [new]
Request: `{"phone_number": "+14155550123"}`
Places a voice call reading a 6-digit code (same Twilio voice delivery as `/authorize`).
- `200 {"challenge_id": "<id>", "expires_in": 300}`
- `400 invalid_phone_number | destination_not_allowed`
- `429 rate_limited` (4 calls/number/hour, 300 calls/day globally)
- `502 delivery_failed`, `503 otp_delivery_unavailable`

### POST /phone/link  [old] and [new]
Old shape [old]: `{"phone_number", "relay_token"}`. Response `200 {"ok": true, "link_proof": "tofu"|"otp"|"legacy"}`
(old clients only check the HTTP status).
New shape [new]: add `"challenge_id"` (from `/phone/link/start`) and `"otp_code"` (6 digits).

| Case | Result |
|------|--------|
| valid OTP | `200 {"ok":true,"link_proof":"otp","replaced":<bool>}`. Creates or replaces the link; a replaced device's WebSocket is closed with code 4401 |
| wrong / expired OTP | `401 {"error":"otp_invalid"}` or `{"error":"otp_expired"}` |
| too many wrong codes for the number | `429 rate_limited` (lockout, up to 1 hour) |
| no OTP, number not linked [compat] | `200`, first-use link (`link_proof":"tofu"`) |
| no OTP, same token as the existing link [compat] | `200` (idempotent) |
| no OTP, different token than the existing link [compat] | `409 {"error":"link_conflict","otp_required":true}`. **The old app shows its generic "Couldn't connect" message** |
| no OTP, compat off | `403 {"error":"otp_required"}` |
| bad phone / token format | `400` |

What a new client must do: call `/phone/link/start`, let the user type the code, then `/phone/link` with
`phone_number`, `relay_token`, `challenge_id`, `otp_code`. On `409 link_conflict` or `403 otp_required`, run
that flow. Send the same `relay_token` the app already uses for its WebSocket (generated once on device).

### DELETE /phone/link  [new]
Header `Authorization: Bearer <relay_token>`. Deletes the link, revokes **all** OAuth grants for the number,
closes the live socket (4401). `200 {"ok":true}`; `401 unauthorized`. After this the number can be linked
again from scratch.

### DELETE /phone/tokens  [new]
Same auth. Revokes every Claude (OAuth) grant for the number but keeps the link. `200 {"ok":true}`.

## WebSocket relay  [old, unchanged]
`GET /phone-ws` upgrade with `Authorization: Bearer <relay_token>`. Unknown token: the upgrade completes and
the server immediately closes with code 4401 (as before). Messages from the server:
`{"correlationId": "<id>", "payload": <JSON-RPC request>}`; reply on the same socket:
`{"correlationId": "<same id>", "payload": <JSON-RPC response>}`. Changes that old clients ignore or already
satisfy: the server pings every 30 s (OkHttp answers automatically), frames larger than 1 MiB are refused,
a reply is only honored from the socket that received the request, a new connection for the same number
replaces the old one, and close code 4401 now also means "replaced by an OTP re-link" or "unlinked"
(`reason` is `replaced` or `unlinked`). A client receiving 4401 should stop reconnecting with that token
and prompt the user to re-link.

## OAuth (Claude connector)

### GET /.well-known/oauth-authorization-server  [old]
Adds `revocation_endpoint`. Everything else unchanged (`S256` only, public clients).

### POST /register  [old]
Request `{"client_name"?, "redirect_uris": [..1-5..]}`. `201 {client_id, client_name, redirect_uris, token_endpoint_auth_method:"none"}`.
New validation: each URI must be `https` on `claude.ai`/`claude.com` (plus `EXTRA_REDIRECT_HOSTS`) or `http`
on `localhost`/`127.0.0.1`/`[::1]`, no fragment or userinfo; `400 invalid_client_metadata` otherwise.

### GET /authorize, POST /authorize/send-otp, POST /authorize/verify-otp  [old]
HTML flow, unchanged for users. Requirements now enforced at every step: registered `client_id`, exact
registered `redirect_uri` that passes the policy, `response_type=code`, `code_challenge` 43 chars base64url,
`code_challenge_method` absent or `S256` (anything else is `400`). The consent page shows the redirect host.
OTP limits: 4 calls/number/hour, 5 guesses/challenge, 10 wrong guesses/number/hour, OTP single-use.

### POST /token  [old]
`application/x-www-form-urlencoded` or JSON.
- `authorization_code`: `code`, `redirect_uri`, `client_id`, `code_verifier` (43-128 chars). Replaying a used
  code returns `400 invalid_grant` and revokes the tokens that code produced.
- `refresh_token`: `refresh_token`, `client_id`. Refresh tokens now expire (90 days sliding, 365 absolute);
  with `REFRESH_ROTATION=1` the response contains a **new** `refresh_token` that the client must store.
  Response shape unchanged: `{access_token, token_type:"Bearer", expires_in:3600, refresh_token}`.
- Errors: `400 invalid_grant | unsupported_grant_type`.

### POST /revoke  [new]
RFC 7009: `token`, `client_id`. Always `200 {}`. Revokes the grant for a refresh token (and its access tokens).

### POST /mcp  [old]
`Authorization: Bearer <access_token>`, JSON-RPC body (max 256 KB), relayed to the number's live socket.
`401 missing_token | invalid_or_expired_token` (now with `WWW-Authenticate: Bearer error="invalid_token"`),
`400 invalid_request`, `413 payload_too_large`, `429 too_many_requests` (16 in-flight per number),
`503 phone_not_connected`, `504 relay_timeout` (30 s), `502 relay_failed`.

### GET /healthz  [old]
`200 {"ok":true}`.

## Server configuration (environment)

| Variable | Default | Meaning |
|----------|---------|---------|
| `LEGACY_LINK_COMPAT` | `1` | `0` makes OTP mandatory for linking |
| `LEGACY_RELINK_STALE_DAYS` | `0` (off) | let a legacy client replace a non-OTP link silent for N days |
| `LEGACY_NEW_LINKS_PER_IP_HOUR` | `10` | cap on first-use claims per IP |
| `REFRESH_TTL_DAYS` / `REFRESH_MAX_DAYS` | `90` / `365` | sliding / absolute refresh lifetime |
| `REFRESH_ROTATION` | `0` | `1` enables rotation with reuse detection |
| `REFRESH_ROTATION_GRACE_MIN` | `1440` | how long a rotated-out token is still accepted |
| `REDIRECT_URI_POLICY` | `strict` | `permissive` also allows any https host and custom schemes |
| `EXTRA_REDIRECT_HOSTS` | empty | comma-separated extra https hosts |
| `OTP_MAX_SENDS_PER_HOUR` / `OTP_MAX_FAILS_PER_HOUR` / `OTP_GLOBAL_DAILY_CAP` | `4` / `10` / `300` | OTP abuse limits |
| `OTP_ALLOWED_COUNTRY_PREFIXES` | empty (any) | e.g. `+1` to call only NANP numbers |
| `PHONE_HASH_SECRET` | unset | enables HMAC-keyed phone numbers (see DEPLOY.md before setting) |
| `SCRUB_PLAINTEXT_PHONES` | unset | `1` irreversibly overwrites plaintext numbers (requires the secret) |
| `OTP_DELIVERY` | `twilio` | `console` is for local tests only and is refused on Fly / production |
