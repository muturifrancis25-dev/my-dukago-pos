-- Shop Code: a short code a new device enters once to attach itself to a shop.
-- Alphabet leaves out 0/O, 1/I/L so codes are easy to read out and type.
create or replace function public.gen_shop_code() returns text
language plpgsql as $$
declare
  alphabet constant text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  c text; i int;
begin
  loop
    c := '';
    for i in 1..5 loop
      c := c || substr(alphabet, 1 + floor(random()*length(alphabet))::int, 1);
    end loop;
    exit when not exists (select 1 from public.shops where shop_code = c);
  end loop;
  return c;
end $$;

alter table public.shops add column if not exists shop_code text;
update public.shops set shop_code = public.gen_shop_code() where shop_code is null;
alter table public.shops alter column shop_code set default public.gen_shop_code();
alter table public.shops alter column shop_code set not null;
create unique index if not exists shops_shop_code_key on public.shops (shop_code);
