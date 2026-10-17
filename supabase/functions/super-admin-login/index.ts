// supabase/functions/super-admin-login/index.ts
//
// The ONLY way to check a Platform Administrator PIN. Uses the SERVICE ROLE key server-side, so the
// app never queries platform_admins directly.
//
// v5: on success it ALSO returns a short-lived signed platform token ({sub,name,exp} + HMAC), which
// the `platform-rest` function requires for every platform-level read/write. Wrong PINs are now
// rate limited (10 failures in 10 minutes locks the login for 5 minutes).
// v6 (build 94): attempts are counted inside the database (race-proof, see supabase/rate_limits.sql), per caller
// address as well as overall, and the PIN is stored scrambled (keyed hash), compared via pin_hash().
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const TOKEN_TTL_S = 2 * 60 * 60;
const MAX_FAILS = 10, WINDOW_MS = 10 * 60 * 1000, LOCK_MS = 5 * 60 * 1000;
const enc = new TextEncoder();

// Only the official app address may call this from a browser (same rule as shop-auth), so a copy of the
// app hosted anywhere else cannot even try Platform Administrator PINs. Override with the ALLOWED_ORIGINS
// secret, comma separated, if the address ever changes.
const ALLOWED_ORIGINS = (Deno.env.get('ALLOWED_ORIGINS') || 'https://muturifrancis25-dev.github.io').split(',').map(x => x.trim()).filter(Boolean);
function corsHeaders(origin: string | null) {
  return {
    'Access-Control-Allow-Origin': origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    'Vary': 'Origin',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };
}
const b64url = (buf: ArrayBuffer | Uint8Array) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ''; u.forEach(c => s += String.fromCharCode(c));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
async function sign(payloadB64: string) {
  const k = await crypto.subtle.importKey('raw', enc.encode(SERVICE_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', k, enc.encode('platform-admin:' + payloadB64)));
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin');
  const cors = corsHeaders(origin);
  const json = (b: unknown, status = 200) =>
    new Response(JSON.stringify(b), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return json({ ok: false, error: 'This copy of the app is not allowed' }, 403);
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  try {
    const { pin } = await req.json();
    if (!pin || typeof pin !== 'string') return json({ ok: false, error: 'A PIN is required' }, 400);

    if (pin.length > 64) return json({ ok: false, error: 'Incorrect PIN' }, 401);
    const now = Date.now();
    const ip = (req.headers.get('cf-connecting-ip') || req.headers.get('x-real-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0] || 'unknown').trim().slice(0, 64);
    // Counted before the PIN is checked, per address and overall; a good sign-in clears this address's counter.
    // The overall cap is higher, so one person on their own cannot lock the real administrator out.
    const hit = async (key: string, limit: number) => {
      const { data, error } = await admin.rpc('auth_attempt_hit', { p_key: key, p_window_s: WINDOW_MS / 1000, p_limit: limit, p_lock_s: LOCK_MS / 1000 });
      if (error) throw new Error('rate limit: ' + error.message);
      return !!(data as { allowed?: boolean })?.allowed;
    };
    const ipKey = 'platform-login:' + ip;
    if (!(await hit(ipKey, MAX_FAILS)) || !(await hit('platform-login', 60))) {
      return json({ ok: false, error: 'Too many wrong attempts — try again in a few minutes' }, 429);
    }

    const { data: ph, error: he } = await admin.rpc('pin_hash', { p_pin: pin });
    if (he || !ph) return json({ ok: false, error: 'Could not check the PIN' }, 500);
    // The plain form is still accepted only until supabase/rate_limits.sql has scrambled the stored PIN.
    let { data, error } = await admin.from('platform_admins').select('id, name, email, phone, active').eq('pin', ph).maybeSingle();
    if (!error && !data) ({ data, error } = await admin.from('platform_admins').select('id, name, email, phone, active').eq('pin', pin).maybeSingle());
    if (error || !data || data.active === false) return json({ ok: false, error: 'Incorrect PIN' }, 401);
    await admin.rpc('auth_attempt_clear', { p_key: ipKey });

    const exp = Math.floor(now / 1000) + TOKEN_TTL_S;
    const payloadB64 = b64url(enc.encode(JSON.stringify({ sub: data.id, name: data.name, exp })));
    const token = payloadB64 + '.' + await sign(payloadB64);
    return json({ ok: true, id: data.id, name: data.name, token, exp });
  } catch (e) {
    return json({ ok: false, error: String(e) }, 500);
  }
});
