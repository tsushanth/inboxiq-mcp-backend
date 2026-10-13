import { openDb } from './db.js';
import { createApp, loadConfig } from './app.js';
import { createOtpDelivery } from './otp-delivery.js';

const config = loadConfig();
const DB_PATH = process.env.DB_PATH || '/data/inboxiq-mcp.db';

const db = openDb(DB_PATH);
const delivery = createOtpDelivery();
const { app, purgeExpired } = createApp({ db, delivery, config });

// A rejected promise (e.g. a failed outbound call) must never take the relay down for every user.
process.on('unhandledRejection', (err) => console.error(`unhandledRejection (${err?.code || err?.name || 'error'})`));

const PURGE_INTERVAL_MS = 60 * 60 * 1000;
const runPurge = () => {
  try {
    const removed = purgeExpired();
    const total = Object.values(removed).reduce((a, b) => a + b, 0);
    if (total > 0) console.log(`purged expired rows: ${JSON.stringify(removed)}`);
  } catch (err) { console.error(`purge failed (${err?.code || err?.name || 'error'})`); }
};
runPurge();
setInterval(runPurge, PURGE_INTERVAL_MS).unref();

app.listen(config.port, '0.0.0.0', () => console.log(`inboxiq-mcp-backend listening on ${config.port} (otp=${delivery.mode}, legacyLinkCompat=${config.legacyLinkCompat})`));
