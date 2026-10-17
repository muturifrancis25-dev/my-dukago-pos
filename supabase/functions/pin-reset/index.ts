// supabase/functions/pin-reset/index.ts
//
// "Forgot PIN?" on the sign-in screen. A staff member (Admin, Supervisor or Cashier) whose email is saved on
// their staff record asks for a 6-digit code by email, then types the code and a new PIN. Kept apart from
// shop-auth so the everyday sign-in can never be affected by a problem here.
//
// Actions (POST JSON):
//   request { shopId? | shopCode?, email }          -> { ok:true, sent:true }   (same answer whether or not the
//                                                       email is on the shop, so it can't be used to find emails)
//        codes: bad_request | not_found (shop) | too_many | email_not_configured | send_failed
//   confirm { shopId? | shopCode?, email, code, newPin, staffId? }
//        -> { ok:true, name, role, shop:{id,name,shop_code} }
//        codes: bad_code (attempts_left) | expired | choose (people:[{id,name,role}] - one email on two staff) |
//               bad_pin (needs 4 or 6 digits) | pin_taken | too_many
//
// Email goes out through Brevo (https://www.brevo.com). Secrets:
//   BREVO_API_KEY   - Brevo > SMTP & API > API keys
//   MAIL_FROM       - a sender address verified in Brevo (Senders, domains & dedicated IPs)
//   MAIL_FROM_NAME  - optional, defaults to "My DukaGO POS"
// Automated tests only: while a row ('test_key', <long random value>) exists in public.pin_reset_config, a request
// carrying header x-reset-test with that exact value gets the code back in the reply instead of an email.
// Delete the row after testing (normal use has no row, so test mode is off).
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
const BREVO_KEY = Deno.env.get('BREVO_API_KEY') || '';
const MAIL_FROM = Deno.env.get('MAIL_FROM') || '';
const MAIL_FROM_NAME = Deno.env.get('MAIL_FROM_NAME') || 'My DukaGO POS';
async function testKey() {
  const { data } = await admin.from('pin_reset_config').select('v').eq('k', 'test_key').maybeSingle();
  return data && String(data.v).length >= 32 ? String(data.v) : '';
}

const CODE_MINUTES = 15, MAX_CODE_TRIES = 5;
const REQ_PER_EMAIL = 3, REQ_WINDOW_MS = 30 * 60 * 1000;   // 3 codes per email per shop per 30 min
const REQ_GLOBAL = 200, GLOBAL_WINDOW_MS = 10 * 60 * 1000; // whole-platform cap against abuse
const SHOP_CONFIRM_FAILS = 15;                               // wrong codes per shop per 10 min before a pause

const ALLOWED_ORIGINS = (Deno.env.get('ALLOWED_ORIGINS') || 'https://muturifrancis25-dev.github.io').split(',').map(x => x.trim()).filter(Boolean);
const corsFor = (origin: string | null) => ({
  'Access-Control-Allow-Origin': origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
  'Vary': 'Origin',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-reset-test',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
});

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha256Hex = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const codeHash = (shopId: string, email: string, code: string) => sha256Hex(`pin-reset:${SERVICE_KEY}:${shopId}:${email}:${code}`);
const sixDigits = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
const normEmail = (e: unknown) => String(e || '').trim().toLowerCase().slice(0, 200);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));

// Counter on the shop_auth_attempts table, counted inside the database so requests sent at the same moment are all
// counted (see supabase/rate_limits.sql). Returns false once the limit is passed.
async function bump(key: string, windowMs: number, limit: number, lockMs: number): Promise<boolean> {
  const { data, error } = await admin.rpc('auth_attempt_hit', { p_key: key, p_window_s: Math.round(windowMs / 1000), p_limit: limit, p_lock_s: Math.round(lockMs / 1000) });
  if (error) throw new Error('rate limit: ' + error.message);
  return !!(data as { allowed?: boolean })?.allowed;
}

async function findShop(body: Record<string, unknown>) {
  if (body.shopCode) {
    const code = String(body.shopCode).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length !== 5) return null;
    const { data } = await admin.from('shops').select('id,name,shop_code').eq('shop_code', code).maybeSingle();
    return data;
  }
  const id = String(body.shopId || '');
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  const { data } = await admin.from('shops').select('id,name,shop_code').eq('id', id).maybeSingle();
  return data;
}

async function staffWithEmail(shopId: string, email: string) {
  // ilike with the address escaped for LIKE wildcards = case-insensitive exact match.
  const pat = email.replace(/[\\%_]/g, m => '\\' + m);
  const { data } = await admin.from('staff').select('id,name,role,email,active').eq('shop_id', shopId).eq('active', true).ilike('email', pat);
  return (data || []).filter(s => normEmail(s.email) === email);
}

async function sendMail(to: string, subject: string, text: string, html: string) {
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: MAIL_FROM_NAME, email: MAIL_FROM }, to: [{ email: to }], subject, textContent: text, htmlContent: html }),
  });
  if (!r.ok) return { ok: false, detail: `${r.status} ${(await r.text().catch(() => '')).slice(0, 200)}` };
  return { ok: true };
}

const card = (inner: string) => `<div style="font-family:Arial,Helvetica,sans-serif;max-width:440px;margin:0 auto;padding:24px;border:1px solid #e6dccb;border-radius:12px;color:#2b2620">${inner}<p style="font-size:11px;color:#8a7f70;margin-top:24px">My DukaGO POS</p></div>`;

Deno.serve(async (req) => {
  const origin = req.headers.get('origin');
  const CORS = corsFor(origin);
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return json({ ok: false, code: 'forbidden_origin' }, 403);
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  const hdr = req.headers.get('x-reset-test');
  const testMode = !!hdr && hdr === await testKey();
  try {
    const body = await req.json().catch(() => ({})) as Record<string, unknown>;
    const action = String(body.action || '');
    const email = normEmail(body.email);
    if (!['request', 'confirm'].includes(action) || !EMAIL_RE.test(email)) return json({ ok: false, code: 'bad_request' }, 400);
    const shop = await findShop(body);
    if (!shop) return json({ ok: false, code: 'not_found' }, 404);
    const ekey = (await sha256Hex(email)).slice(0, 24);

    if (action === 'request') {
      if (!testMode && (!BREVO_KEY || !MAIL_FROM)) return json({ ok: false, code: 'email_not_configured' }, 503);
      if (!(await bump('reset_all', GLOBAL_WINDOW_MS, REQ_GLOBAL, 5 * 60 * 1000))) return json({ ok: false, code: 'too_many' }, 429);
      if (!(await bump(`reset_req:${shop.id}:${ekey}`, REQ_WINDOW_MS, REQ_PER_EMAIL, REQ_WINDOW_MS))) return json({ ok: false, code: 'too_many' }, 429);
      const people = await staffWithEmail(shop.id, email);
      if (!people.length) return json({ ok: true, sent: true });   // same answer as a real send
      const code = sixDigits();
      // A new code replaces any earlier unused one for this email.
      await admin.from('pin_resets').update({ used_at: new Date().toISOString() }).eq('shop_id', shop.id).eq('email', email).is('used_at', null);
      const { error } = await admin.from('pin_resets').insert({
        shop_id: shop.id, email, code_hash: await codeHash(shop.id, email, code), expires_at: new Date(Date.now() + CODE_MINUTES * 60000).toISOString(),
      });
      if (error) return json({ ok: false, code: 'server_error', detail: error.message }, 500);
      if (testMode) return json({ ok: true, sent: true, test_code: code });
      const who = people.length === 1 ? esc(people[0].name) : 'there';
      const sent = await sendMail(email, `Your PIN reset code: ${code}`,
        `Hi ${people.length === 1 ? people[0].name : 'there'},\n\nYour code to reset your PIN for ${shop.name} on My DukaGO POS is: ${code}\n\nIt works for ${CODE_MINUTES} minutes. If you didn't ask for this, ignore this email - your PIN stays the same.`,
        card(`<p>Hi ${who},</p><p>Your code to reset your PIN for <b>${esc(shop.name)}</b> is:</p><p style="font-size:30px;font-weight:700;letter-spacing:6px;margin:12px 0;font-family:monospace">${code}</p><p>It works for ${CODE_MINUTES} minutes. Type it on the sign-in screen, then choose your new PIN.</p><p style="color:#8a7f70;font-size:12px">Didn't ask for this? Ignore this email - your PIN stays the same.</p>`));
      if (!sent.ok) return json({ ok: false, code: 'send_failed', detail: sent.detail }, 502);
      return json({ ok: true, sent: true });
    }

    // confirm
    const shopFailKey = `reset_bad:${shop.id}`;
    if (!(await bump(shopFailKey, 10 * 60 * 1000, SHOP_CONFIRM_FAILS, 10 * 60 * 1000))) return json({ ok: false, code: 'too_many' }, 429);
    const code = String(body.code || '').replace(/\D/g, '');
    const newPin = String(body.newPin || '');
    if (code.length !== 6) return json({ ok: false, code: 'bad_code', attempts_left: null }, 400);
    const { data: rows } = await admin.from('pin_resets').select('*').eq('shop_id', shop.id).eq('email', email).is('used_at', null).order('created_at', { ascending: false }).limit(1);
    const rr = rows && rows[0];
    if (!rr) return json({ ok: false, code: 'expired' }, 400);
    // One try of this code is used up BEFORE comparing (in the database, so parallel guesses can't share a try);
    // a right code gives the try back. A spent or expired code is marked used.
    const { data: tries, error: te } = await admin.rpc('pin_reset_try', { p_id: rr.id, p_max: MAX_CODE_TRIES });
    if (te) return json({ ok: false, code: 'server_error', detail: te.message }, 500);
    if (tries == null) return json({ ok: false, code: 'expired' }, 400);
    if (rr.code_hash !== await codeHash(shop.id, email, code)) {
      const attempts = Number(tries);
      if (attempts >= MAX_CODE_TRIES) await admin.from('pin_resets').update({ used_at: new Date().toISOString() }).eq('id', rr.id);
      return json({ ok: false, code: attempts >= MAX_CODE_TRIES ? 'expired' : 'bad_code', attempts_left: Math.max(0, MAX_CODE_TRIES - attempts) }, 400);
    }
    await admin.rpc('pin_reset_try', { p_id: rr.id, p_max: MAX_CODE_TRIES, p_refund: true });
    await admin.rpc('auth_attempt_clear', { p_key: shopFailKey });
    // Code is right. Which person?
    const people = await staffWithEmail(shop.id, email);
    if (!people.length) return json({ ok: false, code: 'expired' }, 400);
    let person = people[0];
    if (people.length > 1) {
      person = people.find(p => p.id === String(body.staffId || '')) as typeof person;
      if (!person) return json({ ok: false, code: 'choose', people: people.map(p => ({ id: p.id, name: p.name, role: p.role })) });
    }
    if (!newPin) return json({ ok: true, code_ok: true, name: person.name, role: person.role }); // code check only
    const len = person.role === 'admin' ? 6 : 4;
    if (!new RegExp(`^\\d{${len}}$`).test(newPin)) return json({ ok: false, code: 'bad_pin', digits: len }, 400);
    const { data: inUse, error: ue } = await admin.rpc('pin_in_use', { p_pin: newPin, p_exclude: person.id });
    if (ue) return json({ ok: false, code: 'server_error', detail: ue.message }, 500);
    if (inUse) return json({ ok: false, code: 'pin_taken' }, 409);
    const { error: pe } = await admin.from('staff').update({ pin: newPin, updated_at: new Date().toISOString() }).eq('id', person.id).eq('shop_id', shop.id);
    if (pe) return json(/conflict/i.test(pe.message) ? { ok: false, code: 'pin_taken' } : { ok: false, code: 'server_error', detail: pe.message }, /conflict/i.test(pe.message) ? 409 : 500);
    await admin.from('pin_resets').update({ used_at: new Date().toISOString() }).eq('shop_id', shop.id).eq('email', email).is('used_at', null);
    // A fresh start for this shop's sign-in lock, so the person isn't still locked out from the guessing that
    // probably led them here.
    await admin.rpc('auth_attempt_clear', { p_key: 'shop:' + shop.id });
    if (!testMode && BREVO_KEY && MAIL_FROM) {
      await sendMail(email, 'Your My DukaGO POS PIN was changed',
        `Hi ${person.name},\n\nThe PIN for your ${person.role} account at ${shop.name} was just changed using a code sent to this email. If this wasn't you, tell your shop Admin straight away.`,
        card(`<p>Hi ${esc(person.name)},</p><p>The PIN for your <b>${esc(person.role)}</b> account at <b>${esc(shop.name)}</b> was just changed using a code sent to this email.</p><p>If this wasn't you, tell your shop Admin straight away.</p>`)).catch(() => null);
    }
    return json({ ok: true, name: person.name, role: person.role, staffId: person.id, shop: { id: shop.id, name: shop.name, shop_code: shop.shop_code } });
  } catch (e) {
    return json({ ok: false, code: 'server_error', detail: String(e) }, 500);
  }
});
