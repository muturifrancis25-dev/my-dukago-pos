// Run: npm i @electric-sql/pglite && node supabase/tests/rls_isolation_test.mjs
// Local (no network, no live DB) test of supabase/lockdown_policies.sql against a copy of the live schema.
import {PGlite} from '@electric-sql/pglite';
import fs from 'fs';
const db = new PGlite();
const t = (name, ok, extra='') => { console.log((ok?'PASS':'FAIL')+'  '+name+(extra?'  '+extra:'')); if(!ok) process.exitCode=1; };

// ---- mock Supabase roles + auth.jwt() ----
await db.exec(`
 create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
 create schema auth;
 create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true),''),'{}')::jsonb $$;
 grant usage on schema public, auth to anon, authenticated, service_role;
`);
// ---- live schema (columns copied from the production database) ----
await db.exec(`
 create table shops(id uuid primary key, name text, created_at timestamptz default now(), active boolean default true, license_status text default 'active', license_note text);
 create table staff(id text primary key, shop_id uuid, name text, role text, pin text, active boolean, updated_at timestamptz, email text);
 create table products(sku text, shop_id uuid, name text, cat text, price numeric, cost numeric, stock numeric, btype text, updated_at timestamptz, supplier_name text, reorder_threshold int, reorder_qty int, expiry_date date, is_rx boolean, primary key(shop_id, sku));
 create table sales(id text primary key, shop_id uuid, cashier text, total numeric, ts timestamptz);
 create table shop_settings(shop_id uuid, key text, value jsonb, updated_at timestamptz, primary key(shop_id,key));
 create table cart_removal_requests(id text primary key, shop_id uuid, reason text);
 create table customer_debts(id text primary key, shop_id uuid, amount numeric);
 create table payables(id text primary key, shop_id uuid, amount numeric);
 create table po_number_counters(shop_id uuid primary key, last_number int);
 create table purchase_orders(id text primary key, shop_id uuid);
 create table staff_cash(id text primary key, shop_id uuid, amount numeric);
 create table stock_movements(id bigserial primary key, shop_id uuid, sku text);
 create table stock_takes(id text primary key, shop_id uuid);
 create table table_orders(id text primary key, shop_id uuid);
 create table mpesa_requests(checkout_request_id text primary key, shop_id uuid, status text);
 create table platform_business_types(id text primary key, label text);
 create table platform_admins(id text primary key, name text, pin text);
 create table platform_audit_log(id bigserial primary key, shop_id uuid, action text);
 create table mpesa_c2b_payments(id bigserial primary key, trans_id text, matched boolean);
 -- production state: RLS on, wide-open anon policy, full grants
 grant all on all tables in schema public to anon, authenticated, service_role;
 grant all on all sequences in schema public to anon, authenticated, service_role;
`);
const A='aaaaaaaa-0000-0000-0000-00000000000a', B='bbbbbbbb-0000-0000-0000-00000000000b';
await db.exec(`
 insert into shops(id,name) values('${A}','Shop A'),('${B}','Shop B');
 insert into staff values('sA1','${A}','Ann','admin','123456',true,now(),null),('sA2','${A}','Cy','cashier','1111',true,now(),null),('sB1','${B}','Bob','admin','654321',true,now(),null);
 insert into products(sku,shop_id,name,stock) values('x1','${A}','A item',10),('x1','${B}','B item',10);
 insert into sales values('sale-a','${A}','Ann',100,now()),('sale-b','${B}','Bob',200,now());
 insert into platform_admins values('p1','Root','999999');
 insert into platform_business_types values('t1','Bar');
 insert into mpesa_requests values('req-a','${A}','ok'),('req-b','${B}','ok');
`);
// production-like starting point: open policies everywhere
const tables = (await db.query(`select tablename from pg_tables where schemaname='public'`)).rows.map(r=>r.tablename);
for(const x of tables){ await db.exec(`alter table ${x} enable row level security; create policy "allow all for anon" on ${x} for all using (true) with check (true);`); }
// functions as they are live today
await db.exec(`create function adjust_stock(p_shop_id text, p_sku text, p_delta numeric) returns table(sku text, stock numeric) language plpgsql as $$ begin return query update products set stock = coalesce(products.stock,0)+p_delta where products.shop_id=p_shop_id::uuid and products.sku=p_sku returning products.sku, products.stock; end; $$;`);

async function as(role, claims, sql){
  await db.exec(`set role ${role}; select set_config('request.jwt.claims', '${claims?JSON.stringify(claims).replace(/'/g,"''"):''}', false);`);
  try{ return await db.query(sql); }
  finally{ await db.exec(`reset role; select set_config('request.jwt.claims','',false);`); }
}
async function tryAs(role, claims, sql){ try{ const r=await as(role,claims,sql); return {rows:r.rows, n:r.affectedRows??r.rows.length}; }catch(e){ return {err:e.message}; } }

// ---- BEFORE: prove the hole exists today ----
let r = await tryAs('anon', null, `select count(*)::int c from sales`);
t('BEFORE: anon key can read every shop\'s sales', r.rows?.[0].c===2, JSON.stringify(r.rows));
r = await tryAs('anon', null, `select pin from staff where shop_id='${B}'`);
t('BEFORE: anon key can read another shop\'s staff PINs', r.rows?.length===1);

// ---- apply the real lockdown file ----
await db.exec(fs.readFileSync('' + new URL('../lockdown_policies.sql', import.meta.url).pathname + '','utf8'));

const jwtA = (role='admin') => ({app_metadata:{shop_id:A, staff_id:'sA1', role}});
const jwtB = () => ({app_metadata:{shop_id:B, staff_id:'sB1', role:'admin'}});

// ---- AFTER ----
r = await tryAs('anon', null, `select * from sales`);
t('anon (no session): cannot read sales', !!r.err, r.err);
r = await tryAs('anon', null, `select * from staff`);
t('anon: cannot read staff / PINs', !!r.err, r.err);
r = await tryAs('anon', null, `select * from platform_admins`);
t('anon: cannot read platform_admins', !!r.err);
r = await tryAs('anon', null, `delete from sales`);
t('anon: cannot delete sales', !!r.err);
r = await tryAs('anon', null, `truncate sales`);
t('anon: cannot truncate sales', !!r.err);

r = await tryAs('authenticated', jwtA(), `select id from sales`);
t('Shop A session sees only its own sales', r.rows?.length===1 && r.rows[0].id==='sale-a', JSON.stringify(r.rows));
r = await tryAs('authenticated', jwtA(), `select * from staff`);
t('Shop A session sees only its own staff', r.rows?.length===2 && r.rows.every(x=>x.shop_id===A));
r = await tryAs('authenticated', jwtA(), `select * from shops`);
t('Shop A session sees only its own shop row', r.rows?.length===1 && r.rows[0].id===A);
r = await tryAs('authenticated', jwtA(), `select * from products where shop_id='${B}'`);
t('Shop A cannot read Shop B products by filtering for it', r.rows?.length===0);
r = await tryAs('authenticated', jwtA(), `update sales set total=1 where shop_id='${B}' returning id`);
t('Shop A cannot update Shop B sales', (r.rows?.length||0)===0 && !r.err);
r = await tryAs('authenticated', jwtA(), `delete from sales where shop_id='${B}' returning id`);
t('Shop A cannot delete Shop B sales', (r.rows?.length||0)===0 && !r.err);
r = await tryAs('authenticated', jwtA(), `insert into sales(id,shop_id,total) values('evil','${B}',1)`);
t('Shop A cannot insert rows into Shop B', !!r.err, r.err);
r = await tryAs('authenticated', jwtA(), `insert into sales(id,shop_id,total) values('sale-a2','${A}',5)`);
t('Shop A can insert its own sales', !r.err, r.err);
r = await tryAs('authenticated', jwtA(), `update sales set shop_id='${B}' where id='sale-a2'`);
t('Shop A cannot move a row into Shop B (with check)', !!r.err || r.n===0, r.err||'');
r = await tryAs('authenticated', jwtA(), `insert into shop_settings values('${A}','vat','{"a":1}',now()) on conflict (shop_id,key) do update set value=excluded.value`);
t('Shop A can upsert its own settings (merge-duplicates path)', !r.err, r.err);

// role rules on staff
r = await tryAs('authenticated', jwtA('admin'), `update staff set name='Ann2' where id='sA1' returning id`);
t('Admin session can edit staff', r.rows?.length===1, r.err);
r = await tryAs('authenticated', jwtA('cashier'), `update staff set pin='0000' where id='sA1' returning id`);
t('Cashier session cannot change staff/PINs', (r.rows?.length||0)===0, r.err||'');
r = await tryAs('authenticated', jwtA('cashier'), `insert into staff(id,shop_id,name,role,pin,active) values('hack','${A}','H','admin','1','t')`);
t('Cashier session cannot create an admin', !!r.err, r.err);
r = await tryAs('authenticated', jwtB(), `select * from staff where pin='123456'`);
t('Shop B cannot look up Shop A PINs', r.rows?.length===0);

// shops / platform tables
r = await tryAs('authenticated', jwtA(), `update shops set active=false where id='${A}' returning id`);
t('Shop session cannot change its own licence/active flag', (r.rows?.length||0)===0 || !!r.err);
r = await tryAs('authenticated', jwtA(), `select * from platform_admins`);
t('Shop session cannot read platform_admins', !!r.err || r.rows.length===0);
r = await tryAs('authenticated', jwtA(), `select * from platform_business_types`);
t('Shop session can read platform business types', r.rows?.length===1, r.err);
r = await tryAs('authenticated', jwtA(), `insert into platform_business_types values('t2','x')`);
t('Shop session cannot write platform business types', !!r.err);
r = await tryAs('authenticated', jwtA(), `select * from mpesa_requests`);
t('Shop session reads only its own mpesa requests', r.rows?.length===1 && r.rows[0].shop_id===A);
r = await tryAs('authenticated', jwtA(), `insert into mpesa_requests values('r2','${A}','x')`);
t('Shop session cannot forge an mpesa request', !!r.err);

// adjust_stock
r = await tryAs('authenticated', jwtA(), `select * from adjust_stock('${A}','x1',-3)`);
t('adjust_stock works for own shop', r.rows?.[0]?.stock==7, r.err||JSON.stringify(r.rows));
r = await tryAs('authenticated', jwtA(), `select * from adjust_stock('${B}','x1',-3)`);
t('adjust_stock refuses another shop', !!r.err, r.err);
r = await tryAs('anon', null, `select * from adjust_stock('${A}','x1',-3)`);
t('adjust_stock refuses anon', !!r.err, r.err);

// service role (edge functions) still works
r = await tryAs('service_role', null, `select count(*)::int c from sales`);
t('service_role (edge functions) still sees everything', r.rows?.[0].c>=2, r.err);
r = await tryAs('service_role', null, `select * from platform_admins`);
t('service_role can read platform_admins (super-admin-login)', r.rows?.length===1, r.err);

// leftover open policies?
r = await db.query(`select tablename, policyname from pg_policies where schemaname='public' and (qual='true' and policyname<>'pbt_read')`);
t('no open "true" policies remain (except pbt_read)', r.rows.length===0, JSON.stringify(r.rows));
