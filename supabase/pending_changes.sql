-- Run this whole file once in the Supabase SQL editor (project duoshfyiiplvtoasxghn).
-- 1) Audit log shared across a shop's devices (so an admin sees what other phones did).
create table if not exists public.audit_log (id text primary key, shop_id uuid not null, ts timestamptz not null default now(), actor text, role text, action text, details text);
create index if not exists audit_log_shop_ts on public.audit_log (shop_id, ts desc);
alter table public.audit_log enable row level security;
drop policy if exists "allow all for anon" on public.audit_log;
create policy "allow all for anon" on public.audit_log for all using (true) with check (true);

-- 2) refunds: RLS is on but there is no policy, so refunds can't sync. Same open policy as the other shop tables (tightened later by lockdown_policies.sql).
drop policy if exists "allow all for anon" on public.refunds;
create policy "allow all for anon" on public.refunds for all using (true) with check (true);

-- 3) Keep logins in step with staff changes (see staff_auth_sync.sql).
-- Keeps a staff member's login (Supabase Auth user) in step with their staff row:
-- role change -> next token refresh carries the new role; deactivated/deleted -> login banned,
-- so their refresh token stops working. Without this, a removed cashier could keep a live session
-- (up to the 60 min token life, then refresh forever).
create or replace function public.sync_staff_auth() returns trigger
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if tg_op = 'DELETE' then
    select auth_user_id into uid from public.staff_auth where staff_id = old.id;
    if uid is not null then update auth.users set banned_until = 'infinity' where id = uid; end if;
    return old;
  end if;
  select auth_user_id into uid from public.staff_auth where staff_id = new.id;
  if uid is not null then
    update auth.users set
      raw_app_meta_data = coalesce(raw_app_meta_data,'{}'::jsonb) || jsonb_build_object('shop_id', new.shop_id, 'staff_id', new.id, 'role', new.role),
      banned_until = case when new.active is false then 'infinity'::timestamptz else null end
    where id = uid;
  end if;
  return new;
end $$;
revoke all on function public.sync_staff_auth() from public, anon, authenticated;
drop trigger if exists staff_auth_sync on public.staff;
create trigger staff_auth_sync after update of role, active, shop_id or delete on public.staff
  for each row execute function public.sync_staff_auth();
