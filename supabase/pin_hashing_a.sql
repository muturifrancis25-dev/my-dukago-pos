-- PIN hashing, phase A (safe to apply while the old app/edge function are still live).
-- Adds the keyed hash helpers and makes every server-side PIN check accept EITHER the plain PIN OR its hash,
-- so nothing breaks while rows are converted in phase B (pin_hashing_b.sql).
--
-- Stored form in staff.pin:  h1:<length>:<hmac of first 4 digits>:<hmac of whole PIN>
-- The HMAC key ("pepper") is generated inside the database and kept in Supabase Vault, so it is never in this
-- file, never in a table dump, and never seen by anyone. A cashier or leaked backup that reads staff.pin gets values
-- that cannot be reversed or brute-forced without that key.

do $$
begin
  if not exists (select 1 from vault.secrets where name = 'pin_pepper') then
    perform vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'pin_pepper', 'Key for hashing staff PINs');
  end if;
end $$;

create or replace function public.pin_hash(p_pin text) returns text
language plpgsql security definer set search_path = public, extensions, vault as $$
declare k text;
begin
  if p_pin is null then return null; end if;
  select decrypted_secret into k from vault.decrypted_secrets where name = 'pin_pepper';
  if k is null then raise exception 'PIN key missing'; end if;
  return 'h1:' || length(p_pin) || ':'
      || encode(hmac(convert_to(left(p_pin, 4), 'utf8'), convert_to(k, 'utf8'), 'sha256'), 'hex') || ':'
      || encode(hmac(convert_to(p_pin, 'utf8'), convert_to(k, 'utf8'), 'sha256'), 'hex');
end $$;

-- Already-hashed values pass through; plain values get hashed (used while old plain rows still exist).
create or replace function public.pin_norm(p_x text) returns text
language sql stable security definer set search_path = public, extensions, vault as $$
  select case when p_x is null then null when p_x like 'h1:%' then p_x else public.pin_hash(p_x) end
$$;

-- Do two stored PINs clash? Same PIN, or one is the 4-digit start of the other's 6 digits.
create or replace function public.pin_clash(a text, b text) returns boolean
language sql immutable as $$
  select a is not null and b is not null
     and split_part(a, ':', 3) = split_part(b, ':', 3)
     and (split_part(a, ':', 2) <> split_part(b, ':', 2) or a = b)
$$;

-- Does this stored PIN belong to this typed PIN? (phase A: plain OR hashed)
create or replace function public.pin_matches(p_stored text, p_plain text) returns boolean
language sql stable security definer set search_path = public, extensions, vault as $$
  select p_stored is not null and p_plain is not null and (p_stored = public.pin_hash(p_plain) or p_stored = p_plain)
$$;

-- Is this PIN (or one it overlaps) already used by another active person on any shop?
create or replace function public.pin_in_use(p_pin text, p_exclude text) returns boolean
language sql stable security definer set search_path = public, extensions, vault as $$
  select exists (
    select 1 from public.staff s
     where s.active = true and s.pin is not null
       and s.id <> coalesce(p_exclude, '')
       and public.pin_clash(public.pin_norm(s.pin), public.pin_hash(p_pin)))
$$;

-- Sign-in help text for a wrong PIN (never says whose).
create or replace function public.pin_login_hint(p_shop text, p_pin text) returns text
language sql stable security definer set search_path = public, extensions, vault as $$
  select case
    when length(p_pin) = 4 and exists (
      select 1 from public.staff s
       where s.shop_id::text = p_shop and s.active = true and s.pin is not null
         and split_part(public.pin_norm(s.pin), ':', 2)::int > 4
         and split_part(public.pin_norm(s.pin), ':', 3) = split_part(public.pin_hash(p_pin), ':', 3)) then 'prefix'
    when exists (
      select 1 from public.staff s
       where s.shop_id::text <> p_shop and s.active = true and s.pin is not null
         and public.pin_norm(s.pin) = public.pin_hash(p_pin)) then 'other_shop'
    else 'not_found' end
$$;

revoke all on function public.pin_hash(text), public.pin_norm(text), public.pin_matches(text, text),
  public.pin_in_use(text, text), public.pin_login_hint(text, text) from public, anon, authenticated;
grant execute on function public.pin_hash(text), public.pin_norm(text), public.pin_matches(text, text),
  public.pin_in_use(text, text), public.pin_login_hint(text, text) to service_role;

-- The "no overlapping PINs" rule, now hash-aware and checked across ALL shops (it used to see only the caller's shop).
create or replace function public.check_pin_prefix_collision() returns trigger
language plpgsql security definer set search_path = public, extensions, vault as $$
begin
  if new.active = true and new.pin is not null then
    if exists (select 1 from public.staff s
                where s.active = true and s.id <> new.id and s.pin is not null
                  and public.pin_clash(public.pin_norm(s.pin), public.pin_norm(new.pin))) then
      raise exception 'PIN conflicts with an existing active staff PIN (exact match or prefix)';
    end if;
  end if;
  return new;
end $$;

-- Admin-PIN checks inside the licence/device functions: accept plain OR hashed.
do $$
declare r record; d text;
begin
  for r in select p.oid from pg_proc p
            where p.pronamespace = 'public'::regnamespace
              and p.proname in ('remove_device', 'shop_devices_list', 'submit_license_payment', 'register_device') loop
    d := pg_get_functiondef(r.oid);
    d := replace(d, 't.pin = p_pin', 'public.pin_matches(t.pin, p_pin)');
    d := replace(d, 't.pin = p_admin_pin', 'public.pin_matches(t.pin, p_admin_pin)');
    execute d;
  end loop;
end $$;
