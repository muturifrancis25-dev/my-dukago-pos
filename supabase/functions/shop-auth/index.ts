// supabase/functions/shop-auth/index.ts
//
// Verifies a Shop Code / shop id + PIN on the SERVER and hands the device a real Supabase Auth
// session whose token carries {shop_id, staff_id, role} in app_metadata. Row-level-security policies
// (supabase/lockdown_policies.sql) use those claims so a device can only touch its own shop's rows.
//
// Actions (POST JSON):
//   shop_by_code { code }                    -> { ok, shop:{id,name,active} } | { ok:false, code:'not_found' }
//   pin_unique { pin, excludeStaffId? }      -> { ok, unique }
//   business_types {}                        -> { ok, rows }
//   c2b_list {} / c2b_match { trans_id }      -> (needs staff token) this shop's unmatched M-Pesa payments (account number =
//                                               Shop Code) / mark one used (code already_matched if another till got it first)
//   rpc { fn, args }                          -> { ok, data }  (licence/device functions that take an Admin PIN, rate limited)
//   register_shop { shopId, adminId, pin, email? } -> { ok, staff, shop, session }  (first-time setup of a new shop)
//   shop_name { name }                       -> (Admin token) rename own shop
//   login { pin, shopCode? , shopId?, deviceId?, deviceLabel? } -> { ok, staff, shop, session } | { ok:false, code, ... }
//        codes: bad_request | not_found | prefix | other_shop | suspended | locked | device_blocked (plan's device limit reached)
//
// PINs are stored scrambled (keyed HMAC, key held in Supabase Vault) - see supabase/pin_hashing_a.sql / _b.sql.
// Brute-force guard: more than 10 sign-in attempts for one shop within 10 minutes (a right PIN resets the count) locks
// that shop's online sign-in for 5 minutes; 40 wrong PINs from one address lock that address. Counted in the database
// (supabase/rate_limits.sql), so requests sent at the same moment cannot slip past.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

const TRIAL_DAYS = 14;
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

// Only the official app address may call this function from a browser. Browsers always send an Origin header
// on these requests, so a copy of the app hosted anywhere else is refused here even if someone gets past the
// client-side host lock. (Override with the ALLOWED_ORIGINS secret, comma separated, if the address ever changes.)
const ALLOWED_ORIGINS = (Deno.env.get('ALLOWED_ORIGINS') || 'https://muturifrancis25-dev.github.io').split(',').map(x => x.trim()).filter(Boolean);
const CORS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGINS[0],
  'Vary': 'Origin',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

// Counts one attempt against a key inside the database (row locked, so requests sent at the same moment are all
// counted - see supabase/rate_limits.sql). Counted BEFORE the PIN is checked; a good sign-in clears it again.
async function hit(key: string, limit = MAX_FAILS, windowMs = WINDOW_MS, lockMs = LOCK_MS) {
  const { data, error } = await admin.rpc('auth_attempt_hit', { p_key: key, p_window_s: Math.round(windowMs / 1000), p_limit: limit, p_lock_s: Math.round(lockMs / 1000) });
  if (error) throw new Error('rate limit: ' + error.message);
  const d = data as { allowed: boolean; retry_seconds: number };
  return { allowed: !!d?.allowed, retry: Number(d?.retry_seconds || 0) };
}
async function clearFails(key: string) {
  await admin.rpc('auth_attempt_clear', { p_key: key });
}
async function lockedFor(key: string) {
  const { data } = await admin.from('shop_auth_attempts').select('locked_until').eq('key', key).maybeSingle();
  const t = data?.locked_until ? new Date(data.locked_until).getTime() - Date.now() : 0;
  return t > 0 ? Math.ceil(t / 1000) : 0;
}
// Per-address limits are kept generous: many phones on one mobile network can share an address.
const IP_FAILS = 40;
// The caller's address, for per-address limits (one person cannot spread guesses over many shops).
function clientIp(req: Request) {
  return (req.headers.get('cf-connecting-ip') || req.headers.get('x-real-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0] || 'unknown').trim().slice(0, 64);
}
async function staffClaims(req: Request) {
  const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!tok || tok === ANON_KEY) return null;
  const { data: u } = await admin.auth.getUser(tok);
  const md = (u?.user?.app_metadata || {}) as { shop_id?: string; role?: string };
  return u?.user && md.shop_id ? md : null;
}

// What register_device would answer for a phone, without saving anything (used before anyone has signed in).
async function devicePreview(shopId: string, deviceId: string) {
  const { data: shop } = await admin.from('shops').select('plan').eq('id', shopId).maybeSingle();
  if (!shop) return { ok: false, code: 'no_shop' };
  const plan = shop.plan || 'small';
  const { data: limit } = await admin.rpc('plan_device_limit', { p_plan: plan });
  const since = new Date(Date.now() - 30 * 86400000).toISOString();
  const { data: rows } = await admin.from('shop_devices').select('device_id,status,last_seen').eq('shop_id', shopId);
  const mine = (rows || []).find(r => r.device_id === deviceId.slice(0, 80));
  const count = (rows || []).filter(r => r.status === 'active' && r.last_seen > since && r.device_id !== deviceId).length;
  if (mine && mine.status === 'active' && mine.last_seen > since) return { ok: true, count, limit, plan, preview: true };
  if (mine && mine.status === 'removed') return { ok: false, code: 'needs_admin', count, limit, plan };
  if (count < Number(limit)) return { ok: true, count: count + 1, limit, plan, preview: true };
  if (plan === 'large') {
    const { data: price } = await admin.rpc('plan_monthly_price', { p_plan: 'xl' });
    return { ok: false, code: 'needs_upgrade', count, limit, plan, price };
  }
  return { ok: false, code: 'limit', count, limit, plan };
}

type StaffRow = { id: string; shop_id: string; role: string; [k: string]: unknown };
// Makes sure this staff member has an Auth user whose claims are current, signs in as them, returns the session.
async function issueSession(staff: StaffRow) {
  const meta = { shop_id: staff.shop_id, staff_id: staff.id, role: staff.role };
  const email = await emailFor(staff.id);
  const password = await passwordFor(staff.id);
  const { data: map } = await admin.from('staff_auth').select('auth_user_id').eq('staff_id', staff.id).maybeSingle();
  if (map) {
    const { error } = await admin.auth.admin.updateUserById(map.auth_user_id, { password, app_metadata: meta, ban_duration: 'none' });
    if (error) return { error: error.message };
  } else {
    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, app_metadata: meta });
    if (error || !created?.user) return { error: error?.message || 'create failed' };
    await admin.from('staff_auth').insert({ staff_id: staff.id, auth_user_id: created.user.id });
  }
  const anon = createClient(SUPABASE_URL, ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: sess, error: sErr } = await anon.auth.signInWithPassword({ email, password });
  if (sErr || !sess?.session) return { error: sErr?.message || 'sign-in failed' };
  return { session: { access_token: sess.session.access_token, refresh_token: sess.session.refresh_token, expires_at: sess.session.expires_at } };
}

Deno.serve(async (req) => {
  const origin = req.headers.get('origin');
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return json({ ok: false, code: 'forbidden_origin' }, 403);
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  try {
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || 'login');

    if (action === 'shop_by_code') {
      const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (code.length !== 5) return json({ ok: false, code: 'bad_request' }, 400);
      // Rate limited per address so Shop Codes cannot be found by trying them one after another.
      if (!(await hit('code:' + clientIp(req), 60)).allowed) return json({ ok: false, code: 'locked' }, 429);
      const { data } = await admin.from('shops').select('id,name,active,license_status').eq('shop_code', code).maybeSingle();
      if (!data) return json({ ok: false, code: 'not_found' }, 404);
      return json({ ok: true, shop: { id: data.id, name: data.name, active: data.active !== false } });
    }

    if (action === 'pin_unique') {
      // Is this PIN free to use? Clashes = same PIN, or one PIN being the start of another, on any shop.
      // Answers only yes/no (never whose PIN it is), and is rate limited so it cannot be used to map PINs.
      const pin = String(body.pin || '');
      if (!/^(\d{4}|\d{6})$/.test(pin)) return json({ ok: false, code: 'bad_request' }, 400);
      // Signed-in staff are limited per shop; before sign-in (new shop setup) it is a tighter limit per address. It used to be
      // one counter for the whole platform, so one person could block it for everyone or use it to map which PINs exist.
      const who = await staffClaims(req);
      const qk = who ? 'pinq:shop:' + who.shop_id : 'pinq:ip:' + clientIp(req);
      if (!(await hit(qk, who ? 120 : 30)).allowed) return json({ ok: false, code: 'locked' }, 429);
      // PINs are stored scrambled (see supabase/pin_hashing_*.sql); the database does the comparison.
      const { data: inUse, error } = await admin.rpc('pin_in_use', { p_pin: pin, p_exclude: body.excludeStaffId ? String(body.excludeStaffId) : null });
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      return json({ ok: true, unique: !inUse });
    }


    if (action === 'business_types') {
      // Platform-wide list of business types (not shop data) — readable before anyone has signed in.
      const { data, error } = await admin.from('platform_business_types').select('*');
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      return json({ ok: true, rows: data || [] });
    }

    if (action === 'c2b_list' || action === 'c2b_match') {
      // Unmatched direct M-Pesa payments. Needs a signed-in staff token (the one shop-auth issued).
      const md = await staffClaims(req);
      if (!md) return json({ ok: false, code: 'unauthorized' }, 401);
      // Every shop receives on the same platform paybill, so a payment belongs to a shop only when the customer
      // typed that shop's Shop Code as the account number. A shop never sees or claims another shop's payments.
      const { data: own } = await admin.from('shops').select('shop_code').eq('id', md.shop_id).maybeSingle();
      const shopCode = String(own?.shop_code || '').toUpperCase();
      if (!shopCode) return json({ ok: false, code: 'unauthorized' }, 401);
      if (action === 'c2b_list') {
        const since = new Date(Date.now() - 20 * 60 * 1000).toISOString();
        const { data, error } = await admin.from('mpesa_c2b_payments').select('trans_id,trans_time,trans_amount,msisdn,first_name,created_at')
          .eq('matched', false).ilike('bill_ref_number', shopCode).gt('created_at', since).order('created_at', { ascending: false }).limit(15);
        if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
        return json({ ok: true, rows: data || [], account: shopCode });
      }
      const transId = String(body.trans_id || '');
      if (!transId) return json({ ok: false, code: 'bad_request' }, 400);
      // Only flips a row that is still unmatched, so if two tills pick the same payment only the first one wins.
      const { data: claimed, error } = await admin.from('mpesa_c2b_payments').update({ matched: true })
        .eq('trans_id', transId).eq('matched', false).ilike('bill_ref_number', shopCode).select('trans_id');
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      if (!claimed || !claimed.length) return json({ ok: false, code: 'already_matched' }, 409);
      return json({ ok: true });
    }

    if (action === 'rpc') {
      // Licence / device functions that take an Admin PIN. They are no longer callable straight from the
      // browser (that was a way to guess Admin PINs with no limit); they go through here instead, where
      // wrong PINs count against the same per-shop lock as the sign-in.
      const ALLOWED = ['register_device', 'remove_device', 'shop_devices_list', 'submit_license_payment'];
      const fn = String(body.fn || '');
      const args = (body.args && typeof body.args === 'object') ? body.args : {};
      if (!ALLOWED.includes(fn)) return json({ ok: false, code: 'bad_request' }, 400);
      const sid = String(args.p_shop_id || '');
      if (!/^[0-9a-f-]{36}$/i.test(sid)) return json({ ok: false, code: 'bad_request' }, 400);
      const key = 'shop:' + sid;
      const usesPin = args.p_pin != null || args.p_admin_pin != null;
      if (fn === 'register_device' && !usesPin) {
        // Linking a phone without the Admin PIN needs that shop's signed-in staff token. Before anyone has signed in
        // the phone only gets a look (is there a free place?) and nothing is saved: the PIN sign-in itself links the
        // phone and enforces the plan limit. Without this, anyone with a shop's id could fill all its device places.
        const md = await staffClaims(req);
        if (!md || md.shop_id !== sid) return json({ ok: true, data: await devicePreview(sid, String(args.p_device_id || '')) });
      }
      if (usesPin && !(await hit(key)).allowed) return json({ ok: true, data: { ok: false, code: 'too_many' } });
      const { data, error } = await admin.rpc(fn, args);
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      return json({ ok: true, data });
    }

    if (action === 'register_shop') {
      // First-time setup of a brand-new shop: creates the shop and its first Admin, then signs the Admin in.
      // (The browser can no longer write to the shops/staff tables directly once the database is locked.)
      const shopId = String(body.shopId || ''), adminId = String(body.adminId || ''), apin = String(body.pin || '');
      if (!/^[0-9a-f-]{36}$/i.test(shopId) || adminId !== 'u_admin_' + shopId || !/^\d{6}$/.test(apin)) return json({ ok: false, code: 'bad_request' }, 400);
      if (!(await hit('register:' + clientIp(req), 20)).allowed || !(await hit('register', 300)).allowed) return json({ ok: false, code: 'locked' }, 429);

      const { data: ex } = await admin.from('shops').select('id').eq('id', shopId).maybeSingle();
      if (ex) {
        const { data: st } = await admin.from('staff').select('id').eq('shop_id', shopId).limit(1);
        if (st && st.length) return json({ ok: false, code: 'exists' }, 409);
      }
      const { data: taken, error: te } = await admin.rpc('pin_in_use', { p_pin: apin, p_exclude: adminId });
      if (te) return json({ ok: false, code: 'server_error', detail: te.message }, 500);
      if (taken) return json({ ok: false, code: 'pin_taken' }, 409);
      // The shop picks a plan at setup and gets a free trial that starts now. After the trial the usual
      // 7-day grace applies, then the shop is suspended until a payment is confirmed (which sets it 'active').
      const PLANS = ['small', 'medium', 'large', 'xl'];
      const plan = PLANS.includes(String(body.plan || '')) ? String(body.plan) : 'small';
      const trialEnds = new Date(Date.now() + TRIAL_DAYS * 86400000).toISOString();
      if (!ex) {
        const { error } = await admin.from('shops').insert({ id: shopId, name: String(body.name || 'New shop').slice(0, 120), plan, license_status: 'trial', license_expires_at: trialEnds });
        if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      } else {
        // A shop row left behind by an earlier unfinished setup, with no licence dates yet: start its trial now.
        await admin.from('shops').update({ plan, license_status: 'trial', license_expires_at: trialEnds }).eq('id', shopId).is('license_expires_at', null);
      }
      const staffRow = { id: adminId, shop_id: shopId, name: 'Admin', role: 'admin', pin: apin, active: true, email: body.email ? String(body.email).slice(0, 200) : null };
      const { error: se } = await admin.from('staff').upsert(staffRow);
      if (se) return json({ ok: false, code: 'server_error', detail: se.message }, 500);
      const { data: shop } = await admin.from('shops').select('id,name,shop_code').eq('id', shopId).maybeSingle();
      const issued = await issueSession(staffRow);
      if (!issued.session) return json({ ok: false, code: 'server_error', detail: issued.error }, 500);
      return json({ ok: true, staff: staffRow, shop, session: issued.session });
    }

    if (action === 'shop_name') {
      // An Admin renames their own shop.
      const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
      const { data: u } = await admin.auth.getUser(tok);
      const md = (u?.user?.app_metadata || {}) as { shop_id?: string; role?: string };
      if (!u?.user || !md.shop_id || md.role !== 'admin') return json({ ok: false, code: 'unauthorized' }, 401);
      const nm = String(body.name || '').trim().slice(0, 120);
      if (!nm) return json({ ok: false, code: 'bad_request' }, 400);
      const { error } = await admin.from('shops').update({ name: nm }).eq('id', md.shop_id);
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      return json({ ok: true });
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

    // Every attempt is counted for the shop before the PIN is checked (cleared by a good sign-in); wrong PINs are also
    // counted for the caller's address, so one person cannot spread guesses over many shops.
    const key = 'shop:' + shopId, ipKey = 'ipfail:' + clientIp(req);
    const ipWait = await lockedFor(ipKey);
    if (ipWait) return json({ ok: false, code: 'locked', retry_seconds: ipWait }, 429);
    const att = await hit(key);
    if (!att.allowed) return json({ ok: false, code: 'locked', retry_seconds: att.retry }, 429);

    const { data: shop } = await admin.from('shops').select('id,name,active,license_status,license_note').eq('id', shopId).maybeSingle();
    if (!shop) return json({ ok: false, code: 'not_found' }, 404);
    if (shop.active === false || shop.license_status === 'suspended' || shop.license_status === 'cancelled') {
      return json({ ok: false, code: 'suspended', note: shop.license_note || null }, 403);
    }

    // PINs are stored scrambled. Match on the scrambled form (the plain form is also accepted only while old rows are
    // still being converted; once converted no plain PIN can exist, the database scrambles every write).
    const { data: ph, error: phe } = await admin.rpc('pin_hash', { p_pin: pin });
    if (phe || !ph) return json({ ok: false, code: 'server_error', detail: phe?.message || 'hash failed' }, 500);
    const { data: staffRow } = await admin.from('staff').select('*').eq('shop_id', shopId).eq('active', true).or(`pin.eq.${ph},pin.eq.${pin}`).limit(1).maybeSingle();
    if (!staffRow) {
      await hit(ipKey, IP_FAILS);
      // Helpful, narrow hints only: is this the start of a longer PIN in THIS shop, or a PIN that exists elsewhere?
      const { data: hint } = await admin.rpc('pin_login_hint', { p_shop: shopId, p_pin: pin });
      if (hint === 'prefix') return json({ ok: false, code: 'prefix' }, 401);
      if (hint === 'other_shop') return json({ ok: false, code: 'other_shop' }, 401);
      return json({ ok: false, code: 'not_found' }, 401);
    }
    await clearFails(key); // the PIN was right - a blocked device or a later hiccup must not count as a wrong guess
    // The device gets back the PIN it just typed (never the stored scrambled value) so it can sign this person in offline later.
    const staff = { ...staffRow, pin, pin_h: staffRow.pin };

    // Device limit: the PIN is right, but is this phone allowed on the shop's plan? A phone that is already
    // linked passes; a new one takes a free place; if the plan is full it gets no session at all.
    const devId = String(body.deviceId || '').slice(0, 80);
    if (devId) {
      const { data: dv, error: de } = await admin.rpc('register_device', {
        p_shop_id: shopId, p_device_id: devId, p_label: body.deviceLabel ? String(body.deviceLabel).slice(0, 80) : null,
        p_existing: false, p_admin_pin: null, p_accept_upgrade: false,
      });
      const d = dv as { ok?: boolean; code?: string; count?: number; limit?: number; plan?: string; price?: number } | null;
      if (!de && d && d.ok === false && ['limit', 'needs_upgrade', 'needs_admin', 'removed'].includes(String(d.code))) {
        return json({ ok: false, code: 'device_blocked', reason: d.code, count: d.count, limit: d.limit, plan: d.plan, price: d.price }, 403);
      }
    }

    // Make sure this staff member has an Auth user whose claims are current, then sign in as them.
    const issued = await issueSession(staff as StaffRow);
    if (!issued.session) return json({ ok: false, code: 'server_error', detail: issued.error }, 500);

    return json({
      ok: true,
      staff,
      shop: { id: shop.id, name: shop.name },
      session: issued.session,
    });
  } catch (e) {
    return json({ ok: false, code: 'server_error', detail: String(e) }, 500);
  }
});
