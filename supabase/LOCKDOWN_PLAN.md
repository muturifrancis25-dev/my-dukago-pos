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
