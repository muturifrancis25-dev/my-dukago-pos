// supabase/functions/platform-rest/index.ts
//
// The gate for every Platform Administrator read/write. The app sends { token, method, path, body?, prefer? };
// this checks the signed platform token from super-admin-login, checks the request against an allow-list,
// then runs it against the database with the service role and returns the result unchanged.
// Anyone holding only the app's public key cannot use this.
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const enc = new TextEncoder();

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
const b64url = (buf: ArrayBuffer) => {
  const u = new Uint8Array(buf); let s = ''; u.forEach(c => s += String.fromCharCode(c));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
async function sign(payloadB64: string) {
  const k = await crypto.subtle.importKey('raw', enc.encode(SERVICE_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', k, enc.encode('platform-admin:' + payloadB64)));
}
function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function verify(token: string) {
  const [p, sig] = String(token || '').split('.');
  if (!p || !sig || !safeEqual(sig, await sign(p))) return null;
  try {
    const raw = atob(p.replace(/-/g, '+').replace(/_/g, '/'));
    const payload = JSON.parse(raw);
    if (!payload.exp || payload.exp < Date.now() / 1000) return null;
    return payload as { sub: string; name: string; exp: number };
  } catch { return null; }
}

const TABLES = new Set(['shops', 'shop_payments', 'shop_settings', 'staff', 'platform_business_types']);
const METHODS = new Set(['GET', 'POST', 'PATCH']);
// Which columns a platform write may touch, per table (reads are unrestricted within the allowed tables).
const WRITE_COLS: Record<string, Set<string>> = {
  shops: new Set(['active', 'license_status', 'license_note', 'plan', 'license_expires_at', 'shop_code', 'name']),
  shop_payments: new Set(['shop_id', 'amount', 'months', 'plan', 'reference', 'recorded_by', 'extends_to']),
  shop_settings: new Set(['shop_id', 'key', 'value', 'updated_at']),
  staff: new Set(['pin', 'updated_at']),
  platform_business_types: new Set(['id', 'label', 'emoji', 'description', 'cats', 'colors', 'created_by']),
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  try {
    const b = await req.json().catch(() => ({}));
    const who = await verify(b.token);
    if (!who) return json({ message: 'Platform Administrator sign-in needed' }, 401);

    const method = String(b.method || 'GET').toUpperCase();
    const path = String(b.path || '');
    const table = (path.match(/^([a-z_]+)(\?|$)/) || [])[1];
    if (!table || !TABLES.has(table) || !METHODS.has(method) || /[\r\n]|\.\./.test(path)) {
      return json({ message: 'Not allowed' }, 403);
    }
    let bodyText: string | undefined;
    if (method !== 'GET') {
      const rows = Array.isArray(b.body) ? b.body : [b.body];
      for (const r of rows) {
        if (!r || typeof r !== 'object') return json({ message: 'Bad body' }, 400);
        for (const k of Object.keys(r)) if (!WRITE_COLS[table].has(k)) return json({ message: `Column not allowed: ${k}` }, 403);
      }
      // A PATCH must target specific rows, never the whole table.
      if (method === 'PATCH' && !/[?&](id|shop_id)=eq\./.test(path)) return json({ message: 'PATCH needs an id filter' }, 400);
      bodyText = JSON.stringify(b.body);
    }
    const headers: Record<string, string> = {
      apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json',
    };
    if (b.prefer && /^[a-z=,\-]+$/i.test(String(b.prefer))) headers['Prefer'] = String(b.prefer);

    const up = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { method, headers, body: bodyText });
    const text = await up.text();
    return new Response(text, { status: up.status, headers: { ...CORS, 'Content-Type': up.headers.get('content-type') || 'application/json' } });
  } catch (e) {
    return json({ message: String(e) }, 500);
  }
});
