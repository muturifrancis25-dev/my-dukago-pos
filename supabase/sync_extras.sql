-- Objects that were created on the live project without a file in this repo (recorded 2026-10-17, build 94,
-- from the live definitions). Safe to re-run.

-- 1. Idempotent stock changes: every stock_adjust the app queues carries an op id; a retried push with the same
--    id is ignored, so a sale's stock is never taken off twice. Replaces adjust_stock for new builds.
create table if not exists public.stock_ops (
  shop_id uuid not null,
  op_id text not null,
  created_at timestamptz not null default now(),
  primary key (shop_id, op_id)
);
alter table public.stock_ops enable row level security;   -- no policies: only adjust_stock_v2 (security definer) writes it

create or replace function public.adjust_stock_v2(p_shop_id text, p_sku text, p_delta numeric, p_op_id text)
returns table(sku text, stock numeric)
language plpgsql security definer set search_path to 'public' as $function$
declare ins int;
begin
  if p_shop_id::uuid is distinct from public.jwt_shop_id() then
    raise exception 'shop mismatch' using errcode = '42501';
  end if;
  if p_op_id is not null and p_op_id <> '' then
    insert into public.stock_ops(shop_id, op_id) values (p_shop_id::uuid, p_op_id) on conflict do nothing;
    get diagnostics ins = row_count;
    if ins = 0 then
      return query select pr.sku, pr.stock from public.products pr where pr.shop_id = p_shop_id::uuid and pr.sku = p_sku;
      return;
    end if;
  end if;
  return query
    update public.products
       set stock = coalesce(products.stock, 0) + p_delta, updated_at = now()
     where products.shop_id = p_shop_id::uuid and products.sku = p_sku
    returning products.sku, products.stock;
end;
$function$;
revoke execute on function public.adjust_stock_v2(text, text, numeric, text) from public, anon;
grant execute on function public.adjust_stock_v2(text, text, numeric, text) to authenticated;

-- 2. Product tombstones: a product deleted on one phone is removed on the shop's other phones at their next pull.
create table if not exists public.product_tombstones (
  shop_id uuid not null,
  sku text not null,
  deleted_at timestamptz not null default now(),
  primary key (shop_id, sku)
);
alter table public.product_tombstones enable row level security;
drop policy if exists shop_isolation on public.product_tombstones;
create policy shop_isolation on public.product_tombstones for all
  using (shop_id = public.jwt_shop_id()) with check (shop_id = public.jwt_shop_id());

create or replace function public.product_tombstone_add() returns trigger
language plpgsql security definer set search_path to 'public' as $function$
begin
  insert into public.product_tombstones(shop_id, sku, deleted_at) values (old.shop_id, old.sku, now()) on conflict (shop_id, sku) do update set deleted_at = now();
  return old;
end $function$;

create or replace function public.product_tombstone_clear() returns trigger
language plpgsql security definer set search_path to 'public' as $function$
begin
  delete from public.product_tombstones where shop_id = new.shop_id and sku = new.sku;
  return new;
end $function$;

drop trigger if exists products_tombstone_add on public.products;
create trigger products_tombstone_add after delete on public.products for each row execute function product_tombstone_add();
drop trigger if exists products_tombstone_clear on public.products;
create trigger products_tombstone_clear after insert or update of sku on public.products for each row execute function product_tombstone_clear();
revoke execute on function public.product_tombstone_add(), public.product_tombstone_clear() from public, anon, authenticated;
