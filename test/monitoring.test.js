import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, postJson, PHONE } from './helpers.js';
import { createMonitor, classifyDeliveryError } from '../monitor.js';

const spy = () => { const calls = []; return { calls, backendError: (...a) => calls.push(['backendError', ...a]), failure: (...a) => calls.push(['failure', ...a]), crash: async (...a) => calls.push(['crash', ...a]) }; };
const twilioErr = (code, message = `Unable to create record: To ${PHONE}`) => Object.assign(new Error(message), { code, status: 400 });

test('classifyDeliveryError: caller-side Twilio codes do not alert; account and provider failures do', () => {
  assert.equal(classifyDeliveryError(twilioErr(21211)).alert, false);
  assert.equal(classifyDeliveryError(twilioErr(21614)).alert, false);
  const auth = classifyDeliveryError(twilioErr(20003));
  assert.equal(auth.alert, true);
  assert.deepEqual(auth.context, { twilioCode: '20003', status: '400' });
  assert.equal(classifyDeliveryError(new Error('otp_delivery_not_configured')).context.cls, 'not-configured');
  assert.equal(classifyDeliveryError(Object.assign(new Error('getaddrinfo ENOTFOUND api.twilio.com'), { name: 'FetchError' })).alert, true);
});

test('Twilio auth failure on /phone/link/start alerts once, with the code only and no phone number', async () => {
  const m = spy();
  const s = await startServer({ monitor: m });
  try {
    s.behaviour.deliveryError = twilioErr(20003);
    const r = await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE });
    assert.equal(r.status, 502);
    assert.equal(m.calls.length, 1);
    assert.equal(m.calls[0][0], 'failure');
    assert.equal(m.calls[0][1], 'otp-delivery');
    assert.ok(!JSON.stringify(m.calls).includes('415555'), 'no phone digits reach the reporter');
  } finally { await s.close(); }
});

test('a mistyped number (Twilio 21211) does not alert', async () => {
  const m = spy();
  const s = await startServer({ monitor: m });
  try {
    s.behaviour.failDelivery = true;
    const r = await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE });
    assert.equal(r.status, 502);
    assert.equal(m.calls.length, 0);
  } finally { await s.close(); }
});

test('unconfigured delivery alerts', async () => {
  const m = spy();
  const s = await startServer({ monitor: m });
  try {
    s.behaviour.configured = false;
    const r = await postJson(`${s.base}/phone/link/start`, { phone_number: PHONE });
    assert.equal(r.status, 503);
    assert.deepEqual(m.calls[0].slice(0, 2), ['failure', 'otp-delivery']);
  } finally { await s.close(); }
});

test('/healthz/deep: ok, then 503 when the purge dead-man goes stale or delivery is unconfigured', async () => {
  const s = await startServer({ monitor: spy() });
  try {
    let r = await fetch(`${s.base}/healthz/deep`);
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true, db: 'ok', purge: 'ok', otp: 'ok' });
    s.behaviour.configured = false;
    r = await fetch(`${s.base}/healthz/deep`);
    assert.equal(r.status, 503);
    assert.equal((await r.json()).otp, 'unconfigured');
    s.behaviour.configured = true;
    const realNow = Date.now;
    Date.now = () => realNow() + 4 * 60 * 60 * 1000;
    try { r = await fetch(`${s.base}/healthz/deep`); } finally { Date.now = realNow; }
    assert.equal(r.status, 503);
    assert.equal((await r.json()).purge, 'stale');
    s.purgeExpired();
    assert.equal((await fetch(`${s.base}/healthz/deep`)).status, 200);
  } finally { await s.close(); }
});

test('monitor: silent under NODE_ENV=test and without a key; posts codes only when enabled', async () => {
  const sent = [];
  const fetchImpl = async (u, init) => { sent.push(JSON.parse(init.body)); return { ok: true }; };
  createMonitor({ env: { FAILURE_REPORTER_KEY: 'k', NODE_ENV: 'test' }, fetchImpl }).failure('x', 'm');
  createMonitor({ env: { NODE_ENV: 'production' }, fetchImpl }).failure('x', 'm');
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(sent.length, 0);
  const m = createMonitor({ env: { FAILURE_REPORTER_KEY: 'k', NODE_ENV: 'production' }, fetchImpl });
  m.backendError('POST', '/mcp', twilioErr(500, `boom ${PHONE}`), 500);
  m.backendError('POST', '/mcp', new Error('x'), 404);
  m.failure('purge', 'InboxIQ relay hourly purge failed', { cls: 'SQLITE_FULL' });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(sent.length, 2);
  assert.equal(sent[0].flow, 'POST /mcp');
  assert.ok(!JSON.stringify(sent).includes('415555'));
});

test('a throwing reporter fetch never throws to the caller', async () => {
  const m = createMonitor({ env: { FAILURE_REPORTER_KEY: 'k', NODE_ENV: 'production' }, fetchImpl: async () => { throw new Error('net'); } });
  assert.doesNotThrow(() => m.failure('f', 'm'));
  await m.crash('c', new Error('x'));
});
