-- Staff cash (cash taken from the business by staff, and repayments). Already applied to the live project.
create table if not exists public.staff_cash (
  id text primary key,
  shop_id uuid not null,
  staff_id text,
  staff_name text,
  kind text not null default 'advance',   -- 'advance' | 'repayment'
  amount numeric not null,
  reason text,
  recorded_by text,
  recorded_by_id text,
  ts timestamptz not null default now(),
  status text not null default 'pending', -- 'pending' | 'cleared' | 'flagged'
  reviewed_by text,
  reviewed_at timestamptz,
  review_note text,
  updated_at timestamptz not null default now()
);
create index if not exists staff_cash_shop_idx on public.staff_cash (shop_id);
alter table public.staff_cash enable row level security;
-- Open to the anon key like every other shop table today; to be tightened in the security lockdown.
create policy "allow all for anon" on public.staff_cash for all using (true) with check (true);
