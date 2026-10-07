-- STATUS: the table was created live (RLS currently OFF, anon can read/write like the other shop tables).
-- The policy/RLS part below was cancelled when applied; lockdown_policies.sql now covers this table.
-- The app has pushed and pulled `refunds` since refunds were added, but the table was never created
-- in the backend. Every sync pull hit a 404 here and aborted, so everything pulled after it
-- (payables, customer debts, removal requests, purchase orders, stock takes, staff cash...) never reached other devices.
create table if not exists public.refunds (
  id text primary key,
  shop_id uuid not null,
  sale_id text,
  amount numeric,
  method text,
  reason text,
  restocked boolean,
  ts timestamptz,
  "by" text,
  updated_at timestamptz not null default now()
);
create index if not exists refunds_shop_idx on public.refunds (shop_id);
alter table public.refunds enable row level security;
-- Same open policy as every other shop table for now; lockdown_policies.sql replaces it with a per-shop policy.
drop policy if exists "allow all for anon" on public.refunds;
create policy "allow all for anon" on public.refunds for all using (true) with check (true);
