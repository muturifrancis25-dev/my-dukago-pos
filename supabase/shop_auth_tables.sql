-- Support tables for the shop-auth edge function. RLS on with NO policies: only the service role
-- (edge functions) can touch them; the app's anon/session tokens cannot.
create table if not exists public.shop_auth_attempts (
  key text primary key,            -- 'shop:<shop_id>'
  fails int not null default 0,
  window_start timestamptz not null default now(),
  locked_until timestamptz
);
create table if not exists public.staff_auth (
  staff_id text primary key,       -- staff.id
  auth_user_id uuid not null unique,
  created_at timestamptz not null default now()
);
alter table public.shop_auth_attempts enable row level security;
alter table public.staff_auth enable row level security;
revoke all on public.shop_auth_attempts, public.staff_auth from anon, authenticated;
