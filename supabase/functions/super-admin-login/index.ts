// supabase/functions/super-admin-login/index.ts
//
// The ONLY way to check a Platform Administrator PIN. Uses the SERVICE ROLE key server-side, so the
// app never queries platform_admins directly.
//
// v5: on success it ALSO returns a short-lived signed platform token ({sub,name,exp} + HMAC), which
// the `platform-rest` function requires for every platform-level read/write. Wrong PINs are now
// rate limited (10 failures in 10 minutes locks the login for 5 minutes).
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const TOKEN_TTL_S = 2 * 60 * 60;
const MAX_FAILS = 10, WINDOW_MS = 10 * 60 * 1000, LOCK_MS = 5 * 60 * 1000;
const enc = new TextEncoder();

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };
}
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...corsHeaders(), 'Content-Type': 'application/json' } });
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
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() });
  try {
    const { pin } = await req.json();
    if (!pin || typeof pin !== 'string') return json({ ok: false, error: 'A PIN is required' }, 400);

    const key = 'platform-login';
    const { data: ls } = await admin.from('shop_auth_attempts').select('*').eq('key', key).maybeSingle();
    const now = Date.now();
    if (ls?.locked_until && new Date(ls.locked_until).getTime() > now) {
      return json({ ok: false, error: 'Too many wrong attempts — try again in a few minutes' }, 429);
    }

    const { data, error } = await admin.from('platform_admins').select('id, name, email, phone, active').eq('pin', pin).maybeSingle();
    if (error || !data || data.active === false) {
      let fails = 1, window_start = new Date(now).toISOString(), locked_until: string | null = null;
      if (ls && now - new Date(ls.window_start).getTime() < WINDOW_MS) { fails = ls.fails + 1; window_start = ls.window_start; }
      if (fails >= MAX_FAILS) { locked_until = new Date(now + LOCK_MS).toISOString(); fails = 0; window_start = new Date(now).toISOString(); }
      await admin.from('shop_auth_attempts').upsert({ key, fails, window_start, locked_until });
      return json({ ok: false, error: 'Incorrect PIN' }, 401);
    }
    await admin.from('shop_auth_attempts').upsert({ key, fails: 0, window_start: new Date(now).toISOString(), locked_until: null });

    const exp = Math.floor(now / 1000) + TOKEN_TTL_S;
    const payloadB64 = b64url(enc.encode(JSON.stringify({ sub: data.id, name: data.name, exp })));
    const token = payloadB64 + '.' + await sign(payloadB64);
    return json({ ok: true, id: data.id, name: data.name, token, exp });
  } catch (e) {
    return json({ ok: false, error: String(e) }, 500);
  }
});
