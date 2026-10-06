# Security lockdown plan (Supabase)

Status (2026-10-07): policies written and passing 33 local isolation tests (supabase/tests/rls_isolation_test.mjs).
NOT applied to the live database. Still to build: `shop-login` / `shop-register` edge functions and the app release that uses them.

## Problem
Every shop table has an `allow all for anon` policy (`USING (true)`), and the anon key ships in
`index.html`. Anyone with the key can read/write/delete every shop's data (staff PINs, sales,
products, debts, M-Pesa records, shops table). Platform tables (`platform_admins`,
`platform_audit_log`) are already locked (RLS on, no policies) and only reachable through edge functions.

## Target
A device can only touch rows whose `shop_id` matches its own verified session, online or offline-first.

## Design
1. `shop-login` edge function (service role): verifies shop PIN server-side, returns a short-lived signed
   session JWT with claims `shop_id`, `staff_id`, `role`. (Signing mechanism to be confirmed on a branch:
   project JWT secret vs Supabase Auth admin sessions.)
2. App: `sbHeaders()` sends the session token instead of the bare anon key; refresh while online; the app
   keeps working offline from IndexedDB and resumes sync when it has a valid session.
3. RLS: replace every "allow all" policy with `shop_id = (auth.jwt() ->> 'shop_id')::uuid`.
   Revoke anon table grants. `shops` table: read own row only; platform-admin ops via edge functions.
4. Platform Admin: `super-admin-login` currently returns ok/name but no token, and shop management uses
   the open `shops` table. It must issue its own token (role `platform_admin`) so shop activation,
   licence notes and business types keep working once `shops` is locked.
5. PIN lookups ("PIN used elsewhere?", "PIN belongs to another shop") move to server functions that
   return only yes/no + shop name. `staff.pin` stored hashed.
6. Edge functions that already use the service role (`mpesa-*`, `c2b-*`, `invoice-ocr`, `product-scan`)
   are unaffected but must be re-checked for any reliance on anon access.
7. `adjust_stock` RPC: becomes SECURITY INVOKER bound to the session's shop (or checks the claim).

## Rollout
1. Backup (Pro plan daily backup) + Supabase branch with data for testing.
2. Build + test `shop-login`, token handling, policies on the branch.
3. App release that supports tokens AND the old path (policies still open).
4. Migrate staff identities; test on one shop (Kevo Gas Point).
5. Tighten policies table by table: staff, sales, shop_settings, then the rest.
6. Isolation test: cross-shop read/write/delete with another shop's token and with no token must all fail.
7. Hash PINs; re-run Supabase security advisor.

## Risks
- Old builds / devices offline since before the change stop syncing until they sign in online once.
- A wrong policy shows up as silent sync failures; test sale, stock, M-Pesa, table orders, PO sync per step.

## Design decisions (2026-10-07)
- Sessions come from Supabase Auth (works whatever JWT signing the project uses). One auth user per staff
  member: email `<staff_id>@staff.invalid`, password = HMAC-SHA256(SERVICE_ROLE_KEY, 'staff-pw:'+staff_id)
  computed inside the edge function only (no new secret to manage). `app_metadata` = {shop_id, staff_id, role}.
- `shop-auth` edge function, actions: `login` {pin, shopId?} -> {staff row, session} or {code:'not_found'|'other_shop'|'suspended'};
  `prefix_exists` {pin prefix}; `pin_unique` {pin, excludeStaffId}; `register_shop` (new shop + first admin).
- DB trigger on `staff`: when active/role changes, update auth.users (role claim, banned_until) so a
  deactivated/demoted person's token stops working at its next refresh.
- Platform Administrator: `super-admin-login` must return a signed, short-lived platform token and the
  platform screens (shops list/patch, billing + shop_payments, admin PIN reset, platform_business_types)
  must call an edge function with it. Fingerprint sign-in for the platform admin needs a re-verify step.

## App touch-points that rely on the open anon key today (all must change in the app release)
- Sign-in lookups: lookupPinGlobally, lookupPinForThisShop, pinPrefixExists, the PIN-uniqueness check (staff?pin=...).
- Sync: pushToSupabase / pullShopData (every shop table), adjust_stock + next_po_number RPCs, shop active/licence checks.
- Platform: shops list/PATCH, licence, billing, shop_payments, admin PIN reset (staff PATCH), platform_business_types, mpesa_c2b_payments.
- M-Pesa: mpesa_requests status polling (read-only for the shop is enough).
- Open design question: staff PINs are synced to every device of a shop for offline sign-in; hashing them
  means offline checks compare a hash (salted with staff id) instead of the raw PIN.
