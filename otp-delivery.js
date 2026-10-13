import twilio from 'twilio';
import { spellOutDigits } from './util.js';

/**
 * Builds the function that delivers a one-time code to a phone number.
 *
 * Production behaviour (default): a Twilio outbound VOICE call that speaks the code twice
 * (voice, not SMS: SMS through Twilio needs A2P 10DLC / toll-free verification).
 *
 * OTP_DELIVERY=console prints the code to stdout instead of calling anyone. It exists for
 * local smoke tests only and is refused unless NODE_ENV is "test" or "development", or
 * ALLOW_CONSOLE_OTP=1 is set explicitly; it is always refused on Fly (FLY_APP_NAME set)
 * unless ALLOW_CONSOLE_OTP=1, so it cannot silently replace real delivery in production.
 */
export function createOtpDelivery(env = process.env) {
  const mode = env.OTP_DELIVERY || 'twilio';

  if (mode === 'console') {
    const explicit = env.ALLOW_CONSOLE_OTP === '1';
    const devEnv = env.NODE_ENV === 'test' || env.NODE_ENV === 'development';
    if (!explicit && (!devEnv || env.FLY_APP_NAME)) {
      throw new Error('OTP_DELIVERY=console is refused outside NODE_ENV=test|development (set ALLOW_CONSOLE_OTP=1 to override).');
    }
    return {
      mode,
      configured: true,
      async deliver(phone, code) {
        console.log(`[otp-console] ${phone} ${code}`);
      },
    };
  }

  if (mode !== 'twilio') throw new Error(`Unknown OTP_DELIVERY "${mode}".`);

  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER } = env;
  const client = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN ? twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;
  return {
    mode,
    configured: !!client,
    async deliver(phone, code) {
      if (!client) throw new Error('otp_delivery_not_configured');
      // <Say> spells the code out digit-by-digit, twice, at a deliberate pace.
      const spoken = spellOutDigits(code);
      const twiml = `<Response><Say voice="Polly.Joanna">Your InboxIQ connection code is: <break time="300ms"/>${spoken}<break time="700ms"/>I'll repeat that: <break time="300ms"/>${spoken}</Say></Response>`;
      await client.calls.create({ to: phone, from: TWILIO_PHONE_NUMBER, twiml });
    },
  };
}
