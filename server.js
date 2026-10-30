import { openDb } from './db.js';
import { createApp, loadConfig } from './app.js';
import { createOtpDelivery } from './otp-delivery.js';
import { createMonitor } from './monitor.js';

const config = loadConfig();
const DB_PATH = process.env.DB_PATH || '/data/inboxiq-mcp.db';

const db = openDb(DB_PATH);
const delivery = createOtpDelivery();
const monitor = createMonitor();
const { app, purgeExpired } = createApp({ db, delivery, config, monitor });

// A rejected promise (e.g. a failed outbound call) must never take the relay down for every user.
process.on('unhandledRejection', (err) => {
  console.error(`unhandledRejection (${err?.code || err?.name || 'error'})`);
  monitor.failure('unhandledRejection', 'InboxIQ relay unhandled promise rejection', { cls: String(err?.code || err?.name || 'error').slice(0, 40) });
});
process.on('uncaughtException', async (err) => {
  console.error(`uncaughtException (${err?.code || err?.name || 'error'})`);
  await monitor.crash('uncaughtException', err);
  process.exit(1);
});

const PURGE_INTERVAL_MS = 60 * 60 * 1000;
const runPurge = () => {
  try {
    const removed = purgeExpired();
    const total = Object.values(removed).reduce((a, b) => a + b, 0);
    if (total > 0) console.log(`purged expired rows: ${JSON.stringify(removed)}`);
  } catch (err) {
    console.error(`purge failed (${err?.code || err?.name || 'error'})`);
    // e.g. SQLITE_FULL on the 256 MB volume: the purge is also the only thing that frees space.
    monitor.failure('purge', 'InboxIQ relay hourly purge failed', { cls: String(err?.code || err?.name || 'error').slice(0, 40) });
  }
};
runPurge();
setInterval(runPurge, PURGE_INTERVAL_MS).unref();

app.listen(config.port, '0.0.0.0', () => console.log(`inboxiq-mcp-backend listening on ${config.port} (otp=${delivery.mode}, legacyLinkCompat=${config.legacyLinkCompat})`));
