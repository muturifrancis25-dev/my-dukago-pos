-- Licence columns the Platform Administrator screens (and the remote sign-out check) expect.
-- Without them every `select=active,license_note` request returned 400, so a suspended shop was
-- never signed out on devices that were already logged in. Already applied to the live project.
alter table public.shops add column if not exists license_status text not null default 'active';
alter table public.shops add column if not exists license_note text;
update public.shops set license_status = case when active is false then 'suspended' else 'active' end;
