-- Subscription billing. Applied to the live project 2026-10-07 (three migrations).
-- Plans: small KSh 500 / medium KSh 1,000 / large (supermarket, restaurant) KSh 1,500 per month. Setup free.
alter table public.shops add column if not exists plan text not null default 'small';
alter table public.shops add column if not exists license_expires_at timestamptz;
alter table public.shops drop constraint if exists shops_plan_check;
alter table public.shops add constraint shops_plan_check check (plan in ('small','medium','large'));

create table if not exists public.shop_payments (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  amount numeric not null, months integer not null default 1, plan text,
  method text default 'mpesa', reference text, recorded_by text,
  paid_at timestamptz not null default now(), extends_to timestamptz
);
create index if not exists shop_payments_shop_idx on public.shop_payments (shop_id, paid_at desc);
alter table public.shop_payments enable row level security;
-- Open like the other platform screens today; moves behind a platform-admin token in the security lockdown.
create policy "allow all for anon" on public.shop_payments for all using (true) with check (true);

-- Suspend shops whose paid-until date passed more than 7 days ago. No expiry date = never touched.
create or replace function public.suspend_expired_shops() returns integer
language plpgsql set search_path = public as $$
declare n integer;
begin
  update public.shops
     set active = false, license_status = 'suspended',
         license_note = coalesce(nullif(license_note,''), 'Subscription expired - please renew to continue')
   where license_expires_at is not null and license_expires_at + interval '7 days' < now() and active is not false;
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.suspend_expired_shops() from anon, authenticated;

create extension if not exists pg_cron;
select cron.schedule('suspend-expired-shops', '15 * * * *', $$select public.suspend_expired_shops();$$);
