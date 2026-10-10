-- ============================================================================================
-- Security lockdown: per-shop row-level security.   STATUS: ready to apply (trial). Undo with supabase/lockdown_rollback.sql.
-- Apply only together with the app release that signs in through the `shop-login` function
-- (otherwise every device loses sync). See LOCKDOWN_PLAN.md.
--
-- Session model: a signed-in device holds a Supabase Auth session whose app_metadata contains
--   { "shop_id": "<uuid>", "staff_id": "<id>", "role": "cashier|supervisor|admin" }
-- (set server-side by the shop-login edge function using the service role; users cannot edit
-- app_metadata). PostgREST exposes it to policies via auth.jwt().
-- ============================================================================================

create or replace function public.jwt_shop_id() returns uuid
language sql stable set search_path = public as $$
  select nullif(auth.jwt() -> 'app_metadata' ->> 'shop_id', '')::uuid
$$;

create or replace function public.jwt_role() returns text
language sql stable set search_path = public as $$
  select coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '')
$$;

-- 1. Remove every old open policy.
do $$
declare r record;
begin
  for r in select schemaname, tablename, policyname from pg_policies where schemaname = 'public' loop
    execute format('drop policy %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
end $$;

-- 2. Anonymous (no session) gets nothing; logged-in users get only what policies allow.
revoke all on all tables in schema public from anon;
revoke truncate, references, trigger on all tables in schema public from authenticated;

-- 3. Shop-scoped tables: a session sees and writes only its own shop's rows.
do $$
declare t text;
begin
  foreach t in array array[
    'audit_log','cart_removal_requests','customer_debts','payables','po_number_counters','products',
    'purchase_orders','refunds','sales','shop_settings','staff_cash','stock_movements','stock_takes','table_orders'
  ] loop
    execute format('alter table public.%I enable row level security', t);
    execute format($p$create policy shop_isolation on public.%I for all to authenticated
                      using (shop_id = public.jwt_shop_id()) with check (shop_id = public.jwt_shop_id())$p$, t);
  end loop;
end $$;

-- 4. staff: readable within the shop (devices cache the list for offline PIN sign-in);
--    only an admin session may create/change/delete staff.
alter table public.staff enable row level security;
create policy staff_read  on public.staff for select to authenticated using (shop_id = public.jwt_shop_id());
create policy staff_write on public.staff for all to authenticated
  using (shop_id = public.jwt_shop_id() and public.jwt_role() = 'admin')
  with check (shop_id = public.jwt_shop_id() and public.jwt_role() = 'admin');

-- 5. shops: a session may read only its own shop row (for the licence/active check). Never write.
alter table public.shops enable row level security;
create policy shop_read_own on public.shops for select to authenticated using (id = public.jwt_shop_id());

-- 6. mpesa_requests: a shop may read its own payment requests; only edge functions (service role) write.
alter table public.mpesa_requests enable row level security;
create policy mpesa_req_read on public.mpesa_requests for select to authenticated using (shop_id = public.jwt_shop_id());

-- 7. platform_business_types: every signed-in shop may read the platform's type list; writes are service-role only.
alter table public.platform_business_types enable row level security;
create policy pbt_read on public.platform_business_types for select to authenticated using (true);

-- 7b. shop_payments: a shop may read its own payment history; writes are service-role only.
alter table public.shop_payments enable row level security;
create policy shop_pay_read on public.shop_payments for select to authenticated using (shop_id = public.jwt_shop_id());

-- 8. Platform-only tables stay locked (RLS on, no policy): platform_admins, platform_audit_log,
--    mpesa_c2b_payments (written by the Daraja callback functions; reading it from the app moves to an
--    edge function / RPC in the app release).
alter table public.platform_admins enable row level security;
alter table public.platform_audit_log enable row level security;
alter table public.mpesa_c2b_payments enable row level security;

-- 9. adjust_stock: run as the caller (RLS applies) and ignore the shop id the client sends if it
--    does not match the session.
create or replace function public.adjust_stock(p_shop_id text, p_sku text, p_delta numeric)
returns table(sku text, stock numeric)
language plpgsql set search_path = public as $$
begin
  if p_shop_id::uuid is distinct from public.jwt_shop_id() then
    raise exception 'shop mismatch' using errcode = '42501';
  end if;
  return query
    update public.products
       set stock = coalesce(products.stock, 0) + p_delta, updated_at = now()
     where products.shop_id = p_shop_id::uuid and products.sku = p_sku
    returning products.sku, products.stock;
end;
$$;
revoke execute on function public.adjust_stock(text, text, numeric) from anon;
grant execute on function public.adjust_stock(text, text, numeric) to authenticated;
