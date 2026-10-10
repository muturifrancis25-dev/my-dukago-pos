-- Undo supabase/lockdown_policies.sql: puts back the open access every table had before.
do $$
declare r record; t text;
begin
  for r in select schemaname, tablename, policyname from pg_policies where schemaname = 'public' loop
    execute format('drop policy %I on %I.%I', r.policyname, r.schemaname, r.tablename);
  end loop;
  foreach t in array array['audit_log','cart_removal_requests','customer_debts','mpesa_c2b_payments','mpesa_requests','payables','platform_business_types','po_number_counters','products','purchase_orders','refunds','sales','shop_payments','shop_settings','shops','staff','staff_cash','stock_movements','stock_takes','table_orders'] loop
    execute format('grant all on public.%I to anon, authenticated', t);
    execute format('create policy "allow all for anon" on public.%I for all using (true) with check (true)', t);
  end loop;
end $$;
create or replace function public.adjust_stock(p_shop_id text, p_sku text, p_delta numeric)
returns table(sku text, stock numeric) language plpgsql set search_path = public as $$
begin
  return query update public.products set stock = coalesce(products.stock, 0) + p_delta, updated_at = now()
   where products.shop_id = p_shop_id::uuid and products.sku = p_sku returning products.sku, products.stock;
end; $$;
grant execute on function public.adjust_stock(text, text, numeric) to anon, authenticated;
