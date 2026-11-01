/**
 * Failure reporting for the relay: sends to the unified app-failure-reporter Worker (it dedupes and emails).
 * Fire-and-forget, never throws. Off unless FAILURE_REPORTER_KEY is set (Fly secret), and always off
 * under NODE_ENV=test or FAILURE_REPORTER_DISABLED=1. Needs an `inboxiq-mcp#backend` entry in APP_KEYS.
 *
 * PRIVACY: this relay carries phone numbers, OTP codes and SMS content. Nothing from those may reach the
 * reporter. Messages are stable strings; context is a numeric provider error code or a count. Error
 * messages from Twilio contain phone numbers, so they are NEVER forwarded (only `code`/`name`).
 */
const endpoint = (env) => env.FAILURE_REPORTER_URL || 'https://app-failure-reporter.t-sushanth.workers.dev/v1/report';

// Twilio codes caused by the person typing a number (invalid / unreachable / unverified trial destination),
// not by our account or Twilio. These must not page the owner.
const TWILIO_CALLER_SIDE = new Set([21201, 21211, 21213, 21214, 21217, 21219, 21401, 21421, 21614, 13224, 13225]);

/** Returns { alert:boolean, message, context } for an OTP delivery failure, using only error codes. */
export function classifyDeliveryError(err) {
  if (err?.message === 'otp_delivery_not_configured') {
    return { alert: true, message: 'InboxIQ relay OTP delivery is not configured', context: { cls: 'not-configured' } };
  }
  const code = Number(err?.code);
  if (Number.isFinite(code) && code > 0) {
    if (TWILIO_CALLER_SIDE.has(code)) return { alert: false };
    return { alert: true, message: 'InboxIQ relay OTP call failed at Twilio', context: { twilioCode: String(code), status: String(err?.status ?? '') } };
  }
  return { alert: true, message: 'InboxIQ relay OTP call failed (network or unknown)', context: { cls: String(err?.name || 'error').slice(0, 40) } };
}

export function createMonitor({ env = process.env, fetchImpl = (...a) => fetch(...a), version } = {}) {
  const enabled = () => Boolean(env.FAILURE_REPORTER_KEY) && env.FAILURE_REPORTER_DISABLED !== '1' && env.NODE_ENV !== 'test';
  const ver = version || env.FLY_IMAGE_REF || 'unknown';
  async function post(kind, flow, message, context, timeoutMs, err) {
    if (!enabled()) return;
    try {
      await fetchImpl(endpoint(env), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Report-Key': env.FAILURE_REPORTER_KEY },
        // No stack: frames are our own code, but the message/stack text of provider errors can embed numbers.
        body: JSON.stringify({ kind, platform: 'backend', version: ver, flow, message: String(message).slice(0, 200), stack: err?.stack ? String(err.stack).split('\n').filter((l) => l.trim().startsWith('at ')).join('\n').slice(0, 2000) : '', context }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch { /* reporting must never cause a failure of its own */ }
  }
  return {
    enabled,
    /** Handled 5xx. Pass the route template (req.route.path), never the concrete path. */
    backendError(method, routeTemplate, err, status = 500) {
      if (status < 500) return;
      void post('backend_error', `${method} ${routeTemplate}`, `InboxIQ relay server error (${err?.code || err?.name || 'error'})`, { status: String(status) }, 5000, err);
    },
    failure(flow, message, context = {}) { void post('failure', flow, message, context, 5000); },
    crash(flow, err) { return post('crash', flow, `InboxIQ relay crashed (${err?.code || err?.name || 'error'})`, {}, 2500, err); },
  };
}
