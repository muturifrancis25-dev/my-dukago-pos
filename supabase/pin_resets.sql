-- Forgot-PIN by email (build 93). Used only by the pin-reset edge function (service role).
-- RLS on with NO policies: the app's anon / staff tokens cannot read or write these rows.
create table if not exists public.pin_resets (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  email text not null,                 -- lower-cased address the code was sent to
  code_hash text not null,             -- sha256 of the 6-digit code (+ server secret), never the code itself
  attempts int not null default 0,     -- wrong codes typed; 5 kills the code
  expires_at timestamptz not null,     -- 15 minutes after sending
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists pin_resets_lookup on public.pin_resets (shop_id, email, created_at desc);
alter table public.pin_resets enable row level security;
revoke all on public.pin_resets from anon, authenticated;

-- Fast, case-insensitive "which staff in this shop use this email" lookup.
create index if not exists staff_shop_email_lower on public.staff (shop_id, lower(email)) where email is not null;

-- Test switch for the pin-reset function (see its header). Empty in normal use.
create table if not exists public.pin_reset_config (k text primary key, v text not null);
alter table public.pin_reset_config enable row level security;
revoke all on public.pin_reset_config from anon, authenticated;
