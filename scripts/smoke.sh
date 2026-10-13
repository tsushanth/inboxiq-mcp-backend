#!/usr/bin/env bash
# Starts the server locally with a temp DB and console OTP delivery (never Twilio) and exercises the API.
set -euo pipefail
cd "$(dirname "$0")/.."
exec node scripts/smoke.mjs
