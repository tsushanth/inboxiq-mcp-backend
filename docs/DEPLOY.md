# Deploy plan (coordinator)

Nothing in this branch has been deployed. Service: Fly app `inboxiq-mcp`, one machine in `sjc`
(`d8d2471c3e3ee8`, release v5, image `inboxiq-mcp:deployment-01M069X3HM5X0N6G0E1RYTJBJT`), volume
`inboxiq_mcp_data` (1 GB) mounted at `/data`, secrets `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`,
`TWILIO_PHONE_NUMBER`. Production runs Node 20 (Dockerfile). **Use Node 20 or 22 locally**: `better-sqlite3`
has no prebuilt binary for Node 26 and `npm ci` fails there.

## 0. Before deploying
1. Review the branch (`git log main..security-fixes`), run `npm ci && npm test && npm run smoke` on Node 20.
2. Take a safety copy of the live database **on the machine/volume side only** (do not download it): create a Fly
   volume snapshot (`flyctl volumes snapshots create vol_42k5xgqpzx98ln94 -a inboxiq-mcp`). The release is additive, so
   this is belt and braces.
3. Optionally inspect `phone_links` read-only via `flyctl ssh console -C "sqlite3 /data/inboxiq-mcp.db 'select linked_at,last_connected_at from phone_links'"`
   (the image has no sqlite3 CLI; skip if unavailable). Purpose: spot a link that was never connected (possible
   pre-deploy hijack, residual R1).

## 1. Deploy (phase 1: no new secrets, rollback-safe)
```
cd <worktree>            # branch security-fixes, clean tree
flyctl deploy -a inboxiq-mcp --strategy immediate   # one machine + volume: no blue/green possible
```
Expected: a short outage (tens of seconds) while the machine is replaced; the volume detaches/reattaches. Live
WebSockets drop and the Android app reconnects on its own (`RECONNECT_DELAY_MS`). In-flight Claude calls fail once.
Defaults on first deploy: `LEGACY_LINK_COMPAT=1`, `REFRESH_ROTATION=0`, `REDIRECT_URI_POLICY=strict`,
hashing off (no `PHONE_HASH_SECRET`), so the stored data format is still readable by the previous release.

## 2. Smoke tests (against production)
```
curl -fsS https://mcp.kreativekoala.llc/healthz                       # {"ok":true}
curl -fsS https://mcp.kreativekoala.llc/.well-known/oauth-authorization-server | jq .revocation_endpoint
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://mcp.kreativekoala.llc/mcp -H 'content-type: application/json' -d '{}'   # 401
curl -s -X POST https://mcp.kreativekoala.llc/register -H 'content-type: application/json' -d '{"redirect_uris":["https://evil.example/cb"]}'   # 400 invalid_client_metadata
curl -s -X DELETE https://mcp.kreativekoala.llc/phone/link   # 401
```
Do **not** call `/phone/link` or `/authorize/send-otp` in production smoke tests with a real number (OTP calls cost money
and the link would be created).
Functional checks with the owner's own phone (the real client): (a) the app's toggle still connects (`/phone/link`
returns 200 with the same token), the foreground service shows connected; (b) in claude.ai, an existing Connector still
answers a tool call, and (c) if time permits, remove and re-add the Connector to verify the full OAuth + voice OTP flow with
the real redirect URI (this is the one check that would catch the strict redirect policy rejecting the real Claude callback;
if it does, set `EXTRA_REDIRECT_HOSTS=<host>` and redeploy/restart, or `REDIRECT_URI_POLICY=permissive` as a stop-gap).

## 3. What to watch in logs (`flyctl logs -a inboxiq-mcp`)
- `inboxiq-mcp-backend listening on 8080 (otp=twilio, legacyLinkCompat=true)`: confirms real Twilio delivery is active.
  `otp=console` in production means a misconfiguration; the process refuses to start that way unless `ALLOW_CONSOLE_OTP=1`.
- Request lines: `POST /phone/link 409` (a different token tried to take over a linked number: expected from old-app
  reinstalls, suspicious otherwise); `POST /phone/link 200` spikes; `429` bursts on `/authorize/send-otp`.
- `authorize rejected: redirect host not allowed (<host>)`: a legitimate client being blocked by the policy.
- `otp delivery failed (<twilio code>)`, `purged expired rows: {...}`, `unhandledRejection (...)`.
- No message content, phone numbers, tokens or OTPs are logged.

## 4. Rollback
- Fast: `flyctl releases -a inboxiq-mcp` then redeploy the previous image:
  `flyctl deploy -a inboxiq-mcp --image registry.fly.io/inboxiq-mcp:deployment-01M069X3HM5X0N6G0E1RYTJBJT --strategy immediate`
  (confirm the exact image tag in `flyctl releases -a inboxiq-mcp --image`).
- Data compatibility: the migration only adds nullable columns, tables and indexes. The previous release's SQL keeps
  working on the migrated file (covered by the test "rollback safety"). **Exception**: once `PHONE_HASH_SECRET` is
  enabled for a while, rows created in hashed mode are not matched by the old release; and after
  `SCRUB_PLAINTEXT_PHONES=1` the old release cannot read any link. Do not enable either until you accept that.
- A rollback also removes the link-binding fix; links made or replaced in the meantime stay as they are.

## 5. Later phases (separate, deliberate steps)
1. **Observe** for several days: no unexpected `409`s, no `redirect host not allowed` for legitimate use.
2. **Rotation**: `flyctl secrets set REFRESH_ROTATION=1 -a inboxiq-mcp` (any env var; secrets work, or `[env]` in fly.toml) once the
   Claude connector has been confirmed to refresh against the deployed server. Turn back off with `REFRESH_ROTATION=0`.
3. **Hashing**: generate a 32+ byte random value, store it in a password manager *and* as the Fly secret `PHONE_HASH_SECRET`
   (losing it makes the database unreadable: the server refuses to start rather than silently losing links). Restart; rows
   are backfilled additively. Later, `SCRUB_PLAINTEXT_PHONES=1` for one boot, then unset it. Volume snapshots taken earlier still
   contain plaintext until they expire.
4. **Android update**: implement the `/phone/link/start` + OTP flow, `DELETE /phone/link` on "disable and forget", and
   handling of close code 4401 and `409/403` (docs/PROTOCOL.md).
5. **Turn compat off** (`LEGACY_LINK_COMPAT=0`) after the update has been the live Play release for the agreed period.

## Decisions needed from a human
1. **Redirect policy**: confirm only `claude.ai` / `claude.com` (+ loopback) should be allowed, or add hosts via `EXTRA_REDIRECT_HOSTS`.
   Verified only by unit tests, not against the real connector.
2. **Refresh rotation** on or off (shipped off), and when.
3. **Compat window**: the date or condition for `LEGACY_LINK_COMPAT=0`; and whether to enable `LEGACY_RELINK_STALE_DAYS`
   (reinstall convenience for old apps vs. a takeover window for silent links).
4. **PHONE_HASH_SECRET**: create and store it; decide when to scrub plaintext (irreversible for rollback and affects snapshots).
5. **OTP destinations**: set `OTP_ALLOWED_COUNTRY_PREFIXES` (e.g. `+1`) if the user base is US/Canada only; confirm the 300 calls/day
   global cap and the Twilio account's own spend limit.
6. **Existing links**: whether to ask the owner to re-verify their own number once the Android update ships (it clears any
   pre-deploy hijack, residual R1).
7. Approve running the deploy: this branch is local only, not pushed (the repo is public; the review doc describes fixed issues
   and residual risks without exploit steps, and should be pushed after the deploy).
