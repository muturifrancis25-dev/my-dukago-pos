-- Race-proof attempt counters for the edge functions (shop-auth, super-admin-login, pin-reset). Build 94.
--
-- The functions used to read a counter row, add one in TypeScript and write it back. Many requests sent at the
-- same moment all read the same old value, so the "10 tries" limit could be blown past. These functions lock the
-- counter row, so every attempt is counted, however many arrive at once. The attempt is counted BEFORE the PIN or
-- code is checked; a successful sign-in clears the counter again.
--
-- Also: the Platform Administrator PIN is now stored scrambled (same keyed hash as staff PINs, see pin_hashing_a.sql).
-- Only the edge functions (service role) can call any of this.

-- Counts one attempt against p_key. Returns { allowed, retry_seconds }.
-- More than p_limit attempts inside p_window_s seconds locks the key for p_lock_s seconds.
create or replace function public.auth_attempt_hit(p_key text, p_window_s integer, p_limit integer, p_lock_s integer)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.shop_auth_attempts%rowtype;
begin
  insert into public.shop_auth_attempts (key, fails, window_start, locked_until) values (p_key, 0, now(), null)
  on conflict (key) do nothing;
  select * into r from public.shop_auth_attempts where key = p_key for update;
  if r.locked_until is not null and r.locked_until > now() then
    return jsonb_build_object('allowed', false, 'retry_seconds', ceil(extract(epoch from r.locked_until - now())));
  end if;
  if r.window_start < now() - make_interval(secs => p_window_s) then
    r.fails := 0; r.window_start := now();
  end if;
  r.fails := r.fails + 1;
  if r.fails > p_limit then
    update public.shop_auth_attempts set fails = 0, window_start = now(), locked_until = now() + make_interval(secs => p_lock_s)
     where key = p_key;
    return jsonb_build_object('allowed', false, 'retry_seconds', p_lock_s);
  end if;
  update public.shop_auth_attempts set fails = r.fails, window_start = r.window_start, locked_until = null where key = p_key;
  return jsonb_build_object('allowed', true, 'retry_seconds', 0);
end $$;

create or replace function public.auth_attempt_clear(p_key text)
returns void language sql security definer set search_path = public as $$
  update public.shop_auth_attempts set fails = 0, window_start = now(), locked_until = null where key = p_key;
$$;

-- Uses up one try of a PIN-reset code before it is compared. Returns the tries used, or null when the code is
-- spent / expired (and marks it used). p_refund = true gives the try back after a correct code.
create or replace function public.pin_reset_try(p_id uuid, p_max integer, p_refund boolean default false)
returns integer language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if p_refund then
    update public.pin_resets set attempts = greatest(attempts - 1, 0) where id = p_id returning attempts into n;
    return n;
  end if;
  update public.pin_resets set attempts = attempts + 1
   where id = p_id and used_at is null and expires_at > now() and attempts < p_max
  returning attempts into n;
  if n is null then
    update public.pin_resets set used_at = coalesce(used_at, now()) where id = p_id;
  end if;
  return n;
end $$;

revoke all on function public.auth_attempt_hit(text, integer, integer, integer), public.auth_attempt_clear(text),
  public.pin_reset_try(uuid, integer, boolean) from public, anon, authenticated;
grant execute on function public.auth_attempt_hit(text, integer, integer, integer), public.auth_attempt_clear(text),
  public.pin_reset_try(uuid, integer, boolean) to service_role;

-- Platform Administrator PIN: scrambled on every write, existing value converted.
drop trigger if exists a_platform_pin_scramble on public.platform_admins;
create trigger a_platform_pin_scramble before insert or update of pin on public.platform_admins
  for each row execute function public.scramble_staff_pin();
update public.platform_admins set pin = public.pin_hash(pin) where pin is not null and pin not like 'h1:%';

-- Trigger functions are never called directly.
revoke execute on function public.scramble_staff_pin() from public, anon, authenticated;
revoke execute on function public.check_pin_prefix_collision() from public, anon, authenticated;
