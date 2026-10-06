-- Licence columns the Platform Administrator screens (and the remote sign-out check) expect.
-- Without them every `select=active,license_note` request returned 400, so a suspended shop was
-- never signed out on devices that were already logged in. Applied to the live project 2026-10-07.
-- (Both existing shops were active, so the default 'active' was already correct for them.)
alter table public.shops add column if not exists license_status text not null default 'active';
alter table public.shops add column if not exists license_note text;
