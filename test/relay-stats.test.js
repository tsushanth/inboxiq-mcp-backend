import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, linkLegacy, oauthFlow, connectPhone, mcp, PHONE, RELAY_TOKEN } from './helpers.js';
import { createRelayStats } from '../relay-stats.js';

const spy = () => { const calls = []; return { calls, backendError: (...a) => calls.push(['backendError', ...a]), failure: (...a) => calls.push(['failure', ...a]), crash: async () => {} }; };
const HOUR = 60 * 60 * 1000;

test('outcome counts cover a rolling 24 hours', () => {
  let t = 0;
  const s = createRelayStats(() => t);
  s.record('ok');
  s.record('phone_not_connected');
  s.record('something-else');
  assert.deepEqual(s.last24h(), { calls: 3, ok: 1, notConnected: 1, timedOut: 0, limited: 0, failed: 1 });
  t = 23 * HOUR;
  s.record('relay_timeout');
  assert.equal(s.last24h().calls, 4);
  t = 25 * HOUR;
  assert.deepEqual(s.last24h(), { calls: 1, ok: 0, notConnected: 0, timedOut: 1, limited: 0, failed: 0 });
});

test('calls for a long-silent phone say what to do, are counted, and alert once a day without a phone number', async () => {
  const m = spy();
  const s = await startServer({ monitor: m });
  const realNow = Date.now;
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const f = await oauthFlow(s, PHONE);
    let r = await mcp(s, f.tokens.access_token);
    assert.equal(r.status, 503);
    assert.equal(r.headers.get('retry-after'), '900');
    assert.match((await r.json()).message, /Open InboxIQ/);
    assert.equal(m.calls.length, 0, 'a phone linked moments ago is not an alert');

    s.db.prepare('UPDATE phone_links SET linked_at = ?, last_connected_at = ?').run(realNow() - 41 * 24 * HOUR, realNow() - 41 * 24 * HOUR);
    await mcp(s, f.tokens.access_token);
    await mcp(s, f.tokens.access_token);
    assert.equal(m.calls.length, 1);
    assert.deepEqual(m.calls[0].slice(0, 2), ['failure', 'relay-phone-offline']);
    assert.deepEqual(m.calls[0][3], { daysOffline: '41' });
    assert.ok(!JSON.stringify(m.calls).includes('415555'));

    let deep = await (await fetch(`${s.base}/healthz/deep`)).json();
    assert.deepEqual(deep.relay, { phonesConnected: 0, last24h: { calls: 3, ok: 0, notConnected: 3, timedOut: 0, limited: 0, failed: 0 } });

    await connectPhone(s, RELAY_TOKEN, (p) => ({ echo: p }));
    assert.equal((await mcp(s, f.tokens.access_token)).status, 200);
    deep = await (await fetch(`${s.base}/healthz/deep`)).json();
    assert.equal(deep.relay.phonesConnected, 1);
    assert.equal(deep.relay.last24h.ok, 1);
  } finally { await s.close(); }
});
