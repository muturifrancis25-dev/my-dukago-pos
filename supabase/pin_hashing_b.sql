-- PIN hashing, phase B: from now on every PIN written to staff.pin is scrambled by the database itself, and the
-- PINs already stored are converted. Run AFTER pin_hashing_a.sql and after the new shop-auth is deployed.
-- Cannot be undone for existing PINs (that is the point). A locked-out person gets a new PIN from Platform Admin.

create or replace function public.scramble_staff_pin() returns trigger
language plpgsql security definer set search_path = public, extensions, vault as $$
begin
  if new.pin is not null and new.pin not like 'h1:%' then
    new.pin := public.pin_hash(new.pin);
  end if;
  return new;
end $$;

-- Named so it fires BEFORE staff_pin_prefix_check (triggers run alphabetically).
create trigger a_staff_pin_scramble before insert or update of pin on public.staff
  for each row execute function public.scramble_staff_pin();

-- Convert what is already there (updated_at is left alone so devices don't re-download every staff row).
update public.staff set pin = public.pin_hash(pin) where pin is not null and pin not like 'h1:%';

-- The "plain PIN also accepted" fallback is no longer needed: no plain PIN can be stored any more.
create or replace function public.pin_matches(p_stored text, p_plain text) returns boolean
language sql stable security definer set search_path = public, extensions, vault as $$
  select p_stored is not null and p_plain is not null and p_stored = public.pin_hash(p_plain)
$$;
