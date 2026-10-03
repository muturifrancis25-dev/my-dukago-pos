-- Atomic stock adjustment for My DukaGO POS.
--
-- WHY THIS EXISTS: a sale (or a refund restocking items) used to work by reading a product's
-- current stock on the device, subtracting/adding locally, and pushing the resulting ABSOLUTE
-- number back up. If two devices sold the same SKU around the same time, each one was working
-- from its own slightly-stale snapshot — so whichever push reached Supabase last simply
-- OVERWROTE the other device's deduction. A real sale's stock movement could be silently
-- erased, or an oversell could be silently masked, with nothing in the data to show it happened.
--
-- This function makes the adjustment happen INSIDE Postgres, as a single
-- "stock = stock + delta" UPDATE, atomic on that one row regardless of how many devices call
-- it at once or in what order — there is no read-then-write gap for another device's call to
-- land inside.
--
-- HOW TO APPLY: open this project's Supabase dashboard → SQL Editor → paste this whole file →
-- Run. Safe to re-run (CREATE OR REPLACE).

create or replace function adjust_stock(p_shop_id text, p_sku text, p_delta numeric)
returns table(sku text, stock numeric)
language plpgsql
as $$
begin
  return query
    update products
       set stock = coalesce(stock, 0) + p_delta,
           updated_at = now()
     where products.shop_id = p_shop_id
       and products.sku = p_sku
    returning products.sku, products.stock;
end;
$$;

-- Lets the app call this with the same credentials (the anon/publishable key) it already uses
-- for every other request. If your `products` table's row-level security policies already let
-- the app's current key UPDATE a row, this is enough — PostgREST runs the function as the
-- calling role by default (SECURITY INVOKER), so it's bound by the same RLS as a normal
-- update already is. If calling this from the app comes back with a permission/RLS error that
-- a normal product edit does NOT hit, the fix is to make this specific function bypass RLS by
-- adding `security definer` (and ideally `set search_path = public` alongside it) to the
-- `create or replace function` line above and re-running this file — that widens ONLY this one
-- narrow, parameterized operation (stock, by shop_id+sku, by a fixed delta), not general table
-- access, so it stays safe to do even though it skips RLS.
grant execute on function adjust_stock(text, text, numeric) to anon, authenticated;
