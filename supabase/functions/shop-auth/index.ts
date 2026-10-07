// supabase/functions/shop-auth/index.ts
//
// Verifies a Shop Code / shop id + PIN on the SERVER and hands the device a real Supabase Auth
// session whose token carries {shop_id, staff_id, role} in app_metadata. Row-level-security policies
// (supabase/lockdown_policies.sql) use those claims so a device can only touch its own shop's rows.
//
// Actions (POST JSON):
//   shop_by_code { code }                    -> { ok, shop:{id,name,active} } | { ok:false, code:'not_found' }
//   pin_unique { pin, excludeStaffId? }      -> { ok, unique }
//   login { pin, shopCode? , shopId? }       -> { ok, staff, shop, session } | { ok:false, code, ... }
//        codes: bad_request | not_found | prefix | other_shop | suspended | locked
//
// Brute-force guard: 10 failed PINs for one shop within 10 minutes locks that shop's logins for 5 minutes.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const MAX_FAILS = 10, WINDOW_MS = 10 * 60 * 1000, LOCK_MS = 5 * 60 * 1000;
const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
async function sha256Hex(s: string) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
async function hmacHex(key: string, msg: string) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
const emailFor = async (staffId: string) => `s_${(await sha256Hex(staffId)).slice(0, 32)}@staff.invalid`;
const passwordFor = (staffId: string) => hmacHex(SERVICE_KEY, 'staff-pw:' + staffId);

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

async function lockState(key: string) {
  const { data } = await admin.from('shop_auth_attempts').select('*').eq('key', key).maybeSingle();
  return data as { fails: number; window_start: string; locked_until: string | null } | null;
}
async function noteFail(key: string) {
  const row = await lockState(key);
  const now = Date.now();
  let fails = 1, window_start = new Date(now).toISOString(), locked_until: string | null = null;
  if (row && now - new Date(row.window_start).getTime() < WINDOW_MS) { fails = row.fails + 1; window_start = row.window_start; }
  if (fails >= MAX_FAILS) { locked_until = new Date(now + LOCK_MS).toISOString(); fails = 0; window_start = new Date(now).toISOString(); }
  await admin.from('shop_auth_attempts').upsert({ key, fails, window_start, locked_until });
}
async function clearFails(key: string) {
  await admin.from('shop_auth_attempts').upsert({ key, fails: 0, window_start: new Date().toISOString(), locked_until: null });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  try {
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || 'login');

    if (action === 'shop_by_code') {
      const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (code.length !== 5) return json({ ok: false, code: 'bad_request' }, 400);
      const { data } = await admin.from('shops').select('id,name,active,license_status').eq('shop_code', code).maybeSingle();
      if (!data) return json({ ok: false, code: 'not_found' }, 404);
      return json({ ok: true, shop: { id: data.id, name: data.name, active: data.active !== false } });
    }

    if (action === 'pin_unique') {
      // Is this PIN free to use? Clashes = same PIN, or one PIN being the start of another, on any shop.
      // Answers only yes/no (never whose PIN it is), and is rate limited so it cannot be used to map PINs.
      const pin = String(body.pin || '');
      if (!/^(\d{4}|\d{6})$/.test(pin)) return json({ ok: false, code: 'bad_request' }, 400);
      const qk = 'pinq';
      const qs = await lockState(qk);
      if (qs?.locked_until && new Date(qs.locked_until).getTime() > Date.now()) return json({ ok: false, code: 'locked' }, 429);
      const now = Date.now();
      let n = 1, ws = new Date(now).toISOString(), lu: string | null = null;
      if (qs && now - new Date(qs.window_start).getTime() < WINDOW_MS) { n = qs.fails + 1; ws = qs.window_start; }
      if (n >= 120) { lu = new Date(now + LOCK_MS).toISOString(); n = 0; ws = new Date(now).toISOString(); }
      await admin.from('shop_auth_attempts').upsert({ key: qk, fails: n, window_start: ws, locked_until: lu });
      let q = admin.from('staff').select('id').eq('active', true);
      const conds = [`pin.eq.${pin}`];
      if (pin.length === 4) conds.push(`pin.like.${pin}*`); else conds.push(`pin.eq.${pin.slice(0, 4)}`);
      q = q.or(conds.join(','));
      if (body.excludeStaffId) q = q.neq('id', String(body.excludeStaffId));
      const { data: clash, error } = await q.limit(1);
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      return json({ ok: true, unique: !(clash && clash.length) });
    }

    if (action !== 'login') return json({ ok: false, code: 'bad_request' }, 400);

    const pin = String(body.pin || '');
    if (!/^(\d{4}|\d{6})$/.test(pin)) return json({ ok: false, code: 'bad_request' }, 400);

    // Which shop is this device asking about?
    let shopId: string | null = null;
    if (body.shopCode) {
      const code = String(body.shopCode).toUpperCase().replace(/[^A-Z0-9]/g, '');
      const { data } = await admin.from('shops').select('id').eq('shop_code', code).maybeSingle();
      shopId = data ? data.id : null;
    } else if (body.shopId) {
      shopId = String(body.shopId);
    }
    if (!shopId || !/^[0-9a-f-]{36}$/i.test(shopId)) return json({ ok: false, code: 'not_found' }, 404);

    const key = 'shop:' + shopId;
    const ls = await lockState(key);
    if (ls?.locked_until && new Date(ls.locked_until).getTime() > Date.now()) {
      return json({ ok: false, code: 'locked', retry_seconds: Math.ceil((new Date(ls.locked_until).getTime() - Date.now()) / 1000) }, 429);
    }

    const { data: shop } = await admin.from('shops').select('id,name,active,license_status,license_note').eq('id', shopId).maybeSingle();
    if (!shop) return json({ ok: false, code: 'not_found' }, 404);
    if (shop.active === false || shop.license_status === 'suspended' || shop.license_status === 'cancelled') {
      return json({ ok: false, code: 'suspended', note: shop.license_note || null }, 403);
    }

    const { data: staff } = await admin.from('staff').select('*').eq('shop_id', shopId).eq('pin', pin).eq('active', true).maybeSingle();
    if (!staff) {
      await noteFail(key);
      // Helpful, narrow hints only: is this the start of a longer PIN in THIS shop, or a PIN that exists elsewhere?
      if (pin.length === 4) {
        const { data: longer } = await admin.from('staff').select('id').eq('shop_id', shopId).eq('active', true).like('pin', pin + '%').limit(1);
        if (longer && longer.length) return json({ ok: false, code: 'prefix' }, 401);
      }
      const { data: elsewhere } = await admin.from('staff').select('id').eq('pin', pin).eq('active', true).neq('shop_id', shopId).limit(1);
      if (elsewhere && elsewhere.length) return json({ ok: false, code: 'other_shop' }, 401);
      return json({ ok: false, code: 'not_found' }, 401);
    }

    // Make sure this staff member has an Auth user whose claims are current, then sign in as them.
    const meta = { shop_id: staff.shop_id, staff_id: staff.id, role: staff.role };
    const email = await emailFor(staff.id);
    const password = await passwordFor(staff.id);
    const { data: map } = await admin.from('staff_auth').select('auth_user_id').eq('staff_id', staff.id).maybeSingle();
    if (map) {
      const { error } = await admin.auth.admin.updateUserById(map.auth_user_id, { password, app_metadata: meta, ban_duration: 'none' });
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
    } else {
      const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, app_metadata: meta });
      if (error || !created?.user) return json({ ok: false, code: 'server_error', detail: error?.message || 'create failed' }, 500);
      await admin.from('staff_auth').insert({ staff_id: staff.id, auth_user_id: created.user.id });
    }
    const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
    const { data: sess, error: sErr } = await anon.auth.signInWithPassword({ email, password });
    if (sErr || !sess?.session) return json({ ok: false, code: 'server_error', detail: sErr?.message || 'sign-in failed' }, 500);

    await clearFails(key);
    return json({
      ok: true,
      staff,
      shop: { id: shop.id, name: shop.name },
      session: {
        access_token: sess.session.access_token,
        refresh_token: sess.session.refresh_token,
        expires_at: sess.session.expires_at,
      },
    });
  } catch (e) {
    return json({ ok: false, code: 'server_error', detail: String(e) }, 500);
  }
});
