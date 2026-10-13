import { chromium } from 'playwright-core';
import fs from 'fs';
const b = await chromium.launch({executablePath:'/opt/pw-browsers/chromium',args:['--no-sandbox']});
const SHOP='11111111-1111-1111-1111-111111111111';
const now=()=>new Date().toISOString();
const fh=p=>'h1:'+p.length+':x'+p.slice(0,4)+':y'+p;
const staff=[{id:'u1',shop_id:SHOP,name:'Owner',role:'admin',pin:'123456',active:true,updated_at:now()},{id:'u2',shop_id:SHOP,name:'Wanjiru',role:'cashier',pin:'4444',active:true,updated_at:now()}];
const DB={staff:[...staff],products:[],shop_settings:[{shop_id:SHOP,key:'active_business_types',value:['spareparts'],updated_at:now()},{shop_id:SHOP,key:'business_profile',value:{storeName:'Spare Shop',ownerName:'P',phone:'1',location:'x',address:'x'},updated_at:now()}],sales:[],refunds:[],audit_log:[],payables:[],customer_debts:[],cart_removal_requests:[],staff_cash:[],purchase_orders:[],table_orders:[],stock_takes:[],stock_movements:[],product_tombstones:[],shops:[{id:SHOP,name:'Spare Shop',active:true,license_status:'active',plan:'small'}]};
for(let i=0;i<0;i++)DB.products.push({shop_id:SHOP,sku:'SKU'+String(i).padStart(5,'0'),name:'Item '+i,cat:'Groceries',price:50+i%90,cost:30,stock:20,btype:'duka',reorder_threshold:5,updated_at:now()});
const COLS={staff:'id,shop_id,name,role,pin,active,updated_at,email',products:'sku,shop_id,name,cat,price,cost,stock,btype,updated_at,supplier_name,reorder_threshold,reorder_qty,expiry_date,is_rx,make,model,brand,part_no,grade,position,shelf',shop_settings:'shop_id,key,value,updated_at',sales:'id,shop_id,ts',refunds:'id,shop_id,ts',payables:'id,shop_id',customer_debts:'id,shop_id',cart_removal_requests:'id,shop_id',staff_cash:'id,shop_id',purchase_orders:'id,shop_id',table_orders:'id,shop_id',stock_takes:'id,shop_id',stock_movements:'id,shop_id,ts',product_tombstones:'shop_id,sku,deleted_at',audit_log:'id,shop_id,ts'};
const PK={products:'sku',shop_settings:'key'};
let reqCount={};
function rest(u,method,body,prefer){
  const url=new URL(u); const t=url.pathname.split('/rest/v1/')[1]; const q=url.searchParams;
  if(t==='rpc/next_po_number'){ DB._po=(DB._po||0)+1; return [200,'PO-2026-'+String(DB._po).padStart(4,'0')]; }
  if(t==='rpc/adjust_stock_v2'){ const a=JSON.parse(body); DB.stock_ops=DB.stock_ops||[]; if(DB.stock_ops.includes(a.p_op_id))return [200,[]]; DB.stock_ops.push(a.p_op_id); const p=DB.products.find(x=>x.sku===a.p_sku); if(p){p.stock=Number(p.stock||0)+a.p_delta; p.updated_at=now();} return [200,[]]; }
  if(t==='rpc/adjust_stock'){ const a=JSON.parse(body); const p=DB.products.find(x=>x.sku===a.p_sku); if(p){p.stock=Number(p.stock||0)+a.p_delta; p.updated_at=now();} return [200,[]]; }
  const tab=DB[t]; if(!tab) return [200,[]];
  reqCount[t]=(reqCount[t]||0)+1;
  if(method==='GET'){ let rows=tab.filter(r=>{for(const [k,v] of q){ if(['select','order','limit','offset'].includes(k))continue; if(v.startsWith('eq.')&&String(r[k])!==v.slice(3))return false;} return true;});
    const o=q.get('order'); if(o){const [c,d]=o.split('.'); if(!(COLS[t]||'').split(',').includes(c)){ console.log('BAD ORDER COLUMN',t,c); return [400,{message:'column does not exist'}]; } rows=[...rows].sort((a,b)=>(a[c]>b[c]?1:a[c]<b[c]?-1:0)*(d==='desc'?-1:1));}
    const off=+q.get('offset')||0, lim=q.get('limit')?+q.get('limit'):1000; return [200,rows.slice(off,off+Math.min(lim,1000))]; }
  if(method==='POST'){ const arr=[].concat(JSON.parse(body)); const k=PK[t]||'id'; for(const r of arr){ const i=tab.findIndex(x=>x.shop_id===r.shop_id&&x[k]===r[k]&&r[k]!==undefined);
      if(i>=0){ if(!(prefer||'').includes('ignore'))tab[i]=Object.assign(tab[i],r); } else tab.push(Object.assign({},r)); if(t==='products')DB.product_tombstones=DB.product_tombstones.filter(x=>x.sku!==r.sku); } return [201,[]]; }
  if(method==='PATCH'){ const p=JSON.parse(body); tab.forEach(r=>{let m=true;for(const [k,v] of q){if(v.startsWith('eq.')&&String(r[k])!==v.slice(3))m=false;} if(m)Object.assign(r,p);}); return [204,[]]; }
  if(method==='DELETE'){ const del=tab.filter(r=>{let m=true;for(const [k,v] of q){if(v.startsWith('eq.')&&String(r[k])!==v.slice(3))m=false;}return m;}); del.forEach(r=>{tab.splice(tab.indexOf(r),1); if(t==='products')DB.product_tombstones.push({shop_id:r.shop_id,sku:r.sku,deleted_at:now()});}); return [204,[]]; }
  return [200,[]];
}
async function mkDevice(name){
  const ctx=await b.newContext({viewport:{width:420,height:820}}); const page=await ctx.newPage();
  const errs=[]; page.on('pageerror',e=>{errs.push(e.message);console.log(name,'PAGEERR',e.message)});
  page.on('console',m=>{ if(m.type()==='error'&&!/Failed to load resource|net::/.test(m.text())) console.log(name,'CONSOLE',m.text().slice(0,160)); });
  await ctx.route(/muturifrancis25-dev\.github\.io/, r=>{ const p=new URL(r.request().url()).pathname.replace('/my-dukago-pos/','')||'index.html'; try{ r.fulfill({status:200,contentType:p.endsWith('.js')?'application/javascript':p.endsWith('.json')?'application/json':'text/html',body:fs.readFileSync('/home/claude/my-dukago-pos/'+p)}); }catch(e){ r.fulfill({status:404,body:''}); } });
  await ctx.route(/supabase\.co/, r=>{ const rq=r.request(), u=rq.url(), body=rq.postData()||'';
    const ok=(o,st=200)=>r.fulfill({status:st,contentType:'application/json',body:JSON.stringify(o)});
    if(u.includes('/functions/v1/shop-auth')){ const j=JSON.parse(body||'{}');
      if(j.action==='login'){ const s0=DB.staff.find(x=>(x.pin===fh(j.pin)||x.pin===j.pin)&&x.active); const s=s0&&Object.assign({},s0,{pin:j.pin,pin_h:s0.pin}); if(!s0){ if(j.pin.length===4&&DB.staff.some(x=>(x.pin.startsWith('h1:6:')&&x.pin.split(':')[2]===('x'+j.pin))||(x.pin.length===6&&x.pin.startsWith(j.pin))))return ok({ok:false,code:'prefix'},401); return ok({ok:false,code:'not_found'},401);}  return ok({ok:true,staff:s,shop:{id:SHOP,name:'Spare Shop'},session:{access_token:'h.'+Buffer.from(JSON.stringify({app_metadata:{shop_id:SHOP}})).toString('base64url')+'.s',refresh_token:'r',expires_at:Math.floor(Date.now()/1000)+3600}}); }
      if(j.action==='rpc')return ok({ok:true,data:{ok:true,count:1,limit:2,plan:'small'}});
      return ok({ok:true,rows:[]}); }
    if(u.includes('/rest/v1/')){ const [st,d]=rest(u,rq.method(),body,rq.headers()['prefer']); return r.fulfill({status:st,contentType:'application/json',body:JSON.stringify(d)}); }
    ok([]); });
  await page.goto('https://muturifrancis25-dev.github.io/my-dukago-pos/index.html'); await page.waitForTimeout(2000);
  await page.evaluate(async(S)=>{ await put('settings',{key:'shop_id',value:S}); },SHOP);
  await page.reload(); await page.waitForTimeout(2500);
  return {ctx,page,errs};
}
async function pin(page,p){ for(const k of p){ await page.click(`#loginKeypad button[data-k="${k}"]`); await page.waitForTimeout(110); } await page.waitForTimeout(7000); }






const scramble=()=>{ DB.staff.forEach(s=>{ if(!s.pin.startsWith('h1:')) s.pin=fh(s.pin); }); };
async function signOut(p){ await p.evaluate(()=>{ currentUser=null; try{localStorage.removeItem('my_duka_session_uid')}catch(e){} showLoginScreen(); }); await p.waitForTimeout(500); }
const who=async p=>p.evaluate(()=>currentUser?currentUser.name:null);
const locPins=async p=>p.evaluate(async()=>(await getAll('users')).map(u=>u.name+':'+u.pin+':'+(u.pin_h||'-')));
// --- Device A: has the PINs from before the change (server still plain)
const A=await mkDevice('A'); const pa=A.page;
await pin(pa,'123456'); console.log('A online plain login ->',await who(pa)); await signOut(pa);
console.log('A local before scramble',await locPins(pa));
scramble(); await pa.evaluate(async()=>{ await pullShopData(true,false); }); await pa.waitForTimeout(2500);
console.log('A local after scramble pull',await locPins(pa));
await A.ctx.setOffline(true); await pa.waitForTimeout(800);
await pin(pa,'123456'); console.log('A OFFLINE owner ->',await who(pa)); await signOut(pa);
await pin(pa,'4444'); console.log('A OFFLINE cashier ->',await who(pa)); await signOut(pa);
await A.ctx.setOffline(false);
// --- Device B: brand new, server already scrambled
const B=await mkDevice('B'); const pb=B.page;
console.log('B local initial',await locPins(pb));
await pin(pb,'4444'); console.log('B online cashier (first time) ->',await who(pb)); console.log('B local',await locPins(pb)); await signOut(pb);
await pin(pb,'999999'); console.log('B wrong pin ->',await who(pb), await pb.evaluate(()=>document.getElementById('loginHint').textContent));
await pb.waitForTimeout(500);
await B.ctx.setOffline(true); await pb.waitForTimeout(800);
await pin(pb,'4444'); console.log('B OFFLINE same cashier ->',await who(pb)); await signOut(pb);
await pin(pb,'123456'); console.log('B OFFLINE owner (never signed in here) ->',await who(pb)); await signOut(pb);
await B.ctx.setOffline(false);
// --- cashier PIN changed elsewhere
const u2=DB.staff.find(s=>s.id==='u2'); u2.pin=fh('5555'); u2.updated_at=new Date(Date.now()+60000).toISOString();
await pb.evaluate(async()=>{ await pullShopData(true,false); }); await pb.waitForTimeout(2500);
console.log('B local after PIN change elsewhere',await locPins(pb));
await B.ctx.setOffline(true); await pb.waitForTimeout(800);
await pin(pb,'4444'); console.log('B OFFLINE old cashier PIN ->',await who(pb)); await signOut(pb);
await B.ctx.setOffline(false);
await pin(pb,'5555'); console.log('B online NEW cashier PIN ->',await who(pb)); console.log('B local',await locPins(pb));
console.log('errs A',A.errs.length,'B',B.errs.length);
await b.close();
