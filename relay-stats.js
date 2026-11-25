/**
 * Outcome counts for relay calls over the last 24 hours, in memory (they restart with the process). Counts only: no phone
 * number, token or message ever goes in.
 */
const HOUR = 60 * 60 * 1000;
const KINDS = ['ok', 'phone_not_connected', 'relay_timeout', 'too_many_requests', 'failed'];

export function createRelayStats(now = () => Date.now()) {
  const hours = new Map(); // hour index -> { kind: n }
  const prune = (h) => { for (const k of hours.keys()) if (k <= h - 24) hours.delete(k); };
  return {
    record(kind) {
      const h = Math.floor(now() / HOUR);
      prune(h);
      const b = hours.get(h) ?? Object.fromEntries(KINDS.map((k) => [k, 0]));
      b[KINDS.includes(kind) ? kind : 'failed'] += 1;
      hours.set(h, b);
    },
    last24h() {
      prune(Math.floor(now() / HOUR));
      const sum = Object.fromEntries(KINDS.map((k) => [k, 0]));
      for (const b of hours.values()) for (const k of KINDS) sum[k] += b[k];
      return { calls: KINDS.reduce((n, k) => n + sum[k], 0), ok: sum.ok, notConnected: sum.phone_not_connected, timedOut: sum.relay_timeout, limited: sum.too_many_requests, failed: sum.failed };
    },
  };
}
