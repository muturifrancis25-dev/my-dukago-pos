// My DukaGO POS — app-shell service worker
// Caches the till page + manifest so the app can be opened cold, with zero
// network at all, after the first successful visit. This only caches the
// app's own files — sales/stock data lives in IndexedDB (see index.html)
// and is untouched by this file.

const CACHE_NAME = 'my-duka-pos-shell-v40-2026-10-20-107';
const SHELL_FILES = [
  './index.html',
  './manifest.json',
  './zxing.min.js' // the barcode-scanner library — vendored locally (not a CDN) specifically so
  // it's cached offline from the very first visit, same as the app shell itself, and never
  // depends on a browser's own native barcode support (which varies wildly across Android
  // devices/browsers — see index.html's barcode scanner comments for why this replaced that).
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    // cache:'reload' so the offline copy is fetched fresh, never from the browser's HTTP cache.
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES.map((u) => new Request(u, { cache: 'reload' }))))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      // Only the POS's own old caches: other DukaGO apps (Clinic on the go) live on the same web address.
      Promise.all(names.filter((n) => n.startsWith('my-duka-pos-shell-') && n !== CACHE_NAME).map((n) => caches.delete(n)))
    ).then(() => self.clients.claim()).then(() => sweepOldWindows(true))
  );
});

// Added 17 Oct 2026 (build 92) - reload app windows left open on an old build.
// Android keeps a home-screen app's window alive for days; switching back to it shows the old
// page as it was, and builds before 89 never reload themselves. Pages from build 92 on answer a
// BUILD_PING; any window that doesn't answer is an older build and is reloaded - but only while
// it is in the background, so nobody's screen changes under them mid-sale.
const MIN_REPLYING_BUILD = 92;
let lastSweep = 0;
function askBuild(client) {
  return new Promise((resolve) => {
    const ch = new MessageChannel();
    const t = setTimeout(() => resolve(0), 3000);
    ch.port1.onmessage = (e) => { clearTimeout(t); const m = /-(\d+)$/.exec((e.data && e.data.build) || ''); resolve(m ? +m[1] : 0); };
    try { client.postMessage({ type: 'BUILD_PING' }, [ch.port2]); } catch (e) { clearTimeout(t); resolve(0); }
  });
}
async function sweepOldWindows(force) {
  if (!force && Date.now() - lastSweep < 60000) return;
  lastSweep = Date.now();
  const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  await Promise.all(wins.map(async (c) => {
    if (await askBuild(c) >= MIN_REPLYING_BUILD) return;
    if (c.visibilityState === 'hidden' && c.navigate) { try { await c.navigate(c.url); } catch (e) {} }
  }));
}
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SWEEP_OLD_WINDOWS') event.waitUntil(sweepOldWindows(true));
});

// Network-first for the shell so an online cashier always gets the latest
// build; falls back to the cached copy the moment the network fails.
// cache:'no-store' matters here — without it, `fetch()` can still be silently
// answered by the browser's own HTTP cache (or a CDN's) instead of actually
// hitting the network, which is how a real deploy can sit invisible even
// though this network-first logic looks correct.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  // Any open, up-to-date page syncs every few seconds, so this keeps checking (at most once a
  // minute) for old windows sitting in the background.
  if (Date.now() - lastSweep > 60000) event.waitUntil(sweepOldWindows(false).catch(() => {}));

  const isNavigation = event.request.mode === 'navigate';

  event.respondWith(
    fetch(event.request, { cache: 'no-store' })
      .then((response) => {
        // Only a genuine success is ever saved or served as "the app". A 404/5xx from the host
        // (e.g. GitHub Pages being unpublished) is a successful *fetch* but not a usable page —
        // caching it would overwrite the good offline copy and leave offline phones showing
        // "File not found". Throwing sends it down the .catch below to the last good cached copy.
        if(!response.ok && !response.redirected && response.type !== 'opaque') throw new Error('bad response '+response.status);
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() =>
        // ignoreSearch matters here — a home-screen icon can launch with an
        // extra query string (e.g. some Android PWA wrappers append one),
        // which would otherwise miss an exact cache match even though the
        // shell is cached. For a page-load itself, always fall back to the
        // cached index.html specifically (this is a single-page app — there
        // is nothing else to navigate to), not just a same-URL cache match.
        caches.match(event.request, { ignoreSearch: true })
          .then((cached) => cached || (isNavigation ? caches.match('./index.html') : undefined))
      )
  );
});

// ===== Background sync (build 93) =====================================================================
// Sends what the phone saved (sales, stock, payments...) when the browser wakes this worker with a 'sync'
// (back online - even with the app closed) or 'periodicsync' event. If an app window is on screen, that window
// does it instead. pushToSupabase() below is copied from index.html when the build is made.
const DukaBG = (() => {
  let shopId = null, supaUrl = '', supaKey = '', shopSession = null, db = null;
  const DB_NAME = 'soko_pos_db_v1';
  function fetchT(e, t, n) { const a = n || 12e3, s = new AbortController(), i = setTimeout(() => s.abort(), a), o = Object.assign({}, t, { signal: s.signal }); return fetch(e, o).finally(() => clearTimeout(i)); }
  function sessionValid() { return !!(shopSession && shopSession.access && shopSession.expires - Date.now() / 1e3 > 30); }
  function sbHeaders(e) { const t = sessionValid() ? shopSession.access : supaKey; return Object.assign({ 'Content-Type': 'application/json', apikey: supaKey, Authorization: `Bearer ${t}` }, e || {}); }
  function isScrambledPin(e) { return 'string' == typeof e && e.startsWith('h1:'); }
  const req = r => new Promise((a, b) => { r.onsuccess = () => a(r.result); r.onerror = () => b(r.error); });
  const tx = (st, m) => db.transaction(st, m || 'readonly').objectStore(st);
  const getAll = st => req(tx(st).getAll());
  const getOne = (st, k) => req(tx(st).get(k));
  const put = (st, v) => req(tx(st, 'readwrite').put(v));
  const del = (st, k) => req(tx(st, 'readwrite').delete(k));
  const getSetting = k => getOne('settings', k);
  async function tableOrderForPush() { throw new Error('left for the app'); }
  async function openDb() {
    if (indexedDB.databases) { const l = await indexedDB.databases(); if (!l.some(d => d.name === DB_NAME)) return null; }
    const d = await new Promise((a, b) => { const r = indexedDB.open(DB_NAME); r.onsuccess = () => a(r.result); r.onerror = () => b(r.error); r.onupgradeneeded = () => { try { r.transaction.abort(); } catch (e) {} }; });
    d.onversionchange = () => { try { d.close(); } catch (e) {} };
    if (!['settings', 'sync_queue', 'sales'].every(n => d.objectStoreNames.contains(n))) { d.close(); return null; }
    return d;
  }
  async function refresh() {
    if (!shopSession || !shopSession.refresh) return false;
    try {
      const e = await fetchT(`${supaUrl}/auth/v1/token?grant_type=refresh_token`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: supaKey }, body: JSON.stringify({ refresh_token: shopSession.refresh }) }, 8e3);
      if (!e.ok) return false; const t = await e.json(); if (!t.access_token) return false;
      shopSession = { access: t.access_token, refresh: t.refresh_token, expires: t.expires_at || Date.now() / 1e3 + (t.expires_in || 3600), staffId: shopSession.staffId };
      await put('settings', { key: 'shop_session', value: shopSession }); return true;
    } catch (e) { return false; }
  }
  async function pushToSupabase(e){if('staff_delete'===e.type){const t=await fetchT(`${supaUrl}/rest/v1/staff?shop_id=eq.${shopId}&id=eq.${encodeURIComponent(e.payload.id)}`,{method:'DELETE',headers:sbHeaders({Prefer:'return=minimal'})});if(!t.ok){const e=await t.text().catch((()=>''));throw new Error(`Supabase rejected the staff removal: ${t.status}${e?' - '+e.slice(0,150):''}`)}return}if('product_delete'===e.type){const t=await fetchT(`${supaUrl}/rest/v1/products?shop_id=eq.${shopId}&sku=eq.${encodeURIComponent(e.payload.sku)}`,{method:'DELETE',headers:sbHeaders({Prefer:'return=minimal'})});if(!t.ok){const e=await t.text().catch((()=>''));throw new Error(`Supabase rejected the delete: ${t.status}${e?' - '+e.slice(0,150):''}`)}return}if('stock_adjust'===e.type){const t=e.payload,n=await fetchT(`${supaUrl}/rest/v1/rpc/${t.opId?'adjust_stock_v2':'adjust_stock'}`,{method:'POST',headers:sbHeaders({Prefer:'return=minimal'}),body:JSON.stringify(t.opId?{p_shop_id:shopId,p_sku:t.sku,p_delta:t.delta,p_op_id:t.opId}:{p_shop_id:shopId,p_sku:t.sku,p_delta:t.delta})});if(!n.ok){const e=await n.text().catch((()=>''));throw new Error(`Supabase rejected the stock adjustment: ${n.status}${e?' - '+e.slice(0,150):''}`)}return}let t,n,a='resolution=merge-duplicates,return=minimal';if('sale'===e.type){t='sales';const a=e.payload;n={id:a.id,shop_id:shopId,cashier:a.cashier,till:a.till,lines:a.lines,subtotal:a.subtotal,tax:a.tax,total:a.total,method:a.method,tendered:a.tendered,change:a.change,mpesa_code:a.mpesaCode||null,btypes:a.btypes,ts:a.ts,synced:!0}}else if('stock_movement'===e.type)t='stock_movements',n=Object.assign({shop_id:shopId},e.payload);else if('staff_upsert'===e.type)t='staff',n=Object.assign({shop_id:shopId},e.payload),a='resolution=merge-duplicates,return=representation';else if('product_upsert'===e.type||'product_seed'===e.type){t='products',a='product_seed'===e.type?'resolution=ignore-duplicates,return=minimal':'resolution=merge-duplicates,return=minimal';const s=e.payload;n={shop_id:shopId,sku:s.sku,name:s.name,cat:s.cat,price:s.price,cost:s.cost,stock:s.stock,btype:s.btype,supplier_name:s.supplierName||null,reorder_threshold:0===s.reorderThreshold?0:s.reorderThreshold||10,expiry_date:s.expiryDate||null,is_rx:s.isRx||!1,make:s.make||null,model:s.model||null,brand:s.brand||null,part_no:s.partNo||null,grade:s.grade||null,position:s.position||null,shelf:s.shelf||null,updated_at:s.updated_at||(new Date).toISOString()},s.noStock&&delete n.stock}else if('settings_upsert'===e.type)t='shop_settings',n=Object.assign({shop_id:shopId},e.payload),a='resolution=merge-duplicates,return=minimal';else if('audit_insert'===e.type){t='audit_log',a='resolution=ignore-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,ts:s.ts,actor:s.actor,role:s.role,action:s.action,details:s.details}}else if('refund_record'===e.type){t='refunds';const a=e.payload;n={id:a.id,shop_id:shopId,sale_id:a.saleId,amount:a.amount,method:a.method,reason:a.reason,restocked:a.restocked,ts:a.ts,by:a.by}}else if('payable_upsert'===e.type){t='payables',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,supplier_name:s.supplierName,amount:s.amount,invoice_date:s.invoiceDate,due_date:s.dueDate,photo:s.photo,notes:s.notes,po_number:s.poNumber||null,status:s.status,added_by:s.addedBy,paid_date:s.paidDate,paid_by:s.paidBy,stock_update_status:s.stockUpdateStatus||null,stock_update_by:s.stockUpdateBy||null,stock_update_at:s.stockUpdateAt||null,updated_at:s.updated_at||(new Date).toISOString()}}else if('debt_upsert'===e.type){t='customer_debts',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,customer_name:s.customerName,customer_phone:s.customerPhone,amount:s.amount,tax:s.tax||0,date_given:s.dateGiven,notes:s.notes,status:s.status,cost:s.cost,paid_date:s.paidDate,added_by:s.addedBy,due_date:s.dueDate,line_items:s.lineItems,updated_at:s.updated_at||(new Date).toISOString()}}else if('removal_upsert'===e.type){t='cart_removal_requests',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,kind:s.kind,item_info:s.itemInfo,reason:s.reason,requested_by:s.requestedBy,requested_at:s.requestedAt,status:s.status,reviewed_by:s.reviewedBy,reviewed_at:s.reviewedAt,review_note:s.reviewNote}}else if('staff_cash_upsert'===e.type){t='staff_cash',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,staff_id:s.staffId,staff_name:s.staffName,kind:s.kind,amount:s.amount,reason:s.reason,recorded_by:s.recordedBy,recorded_by_id:s.recordedById||null,ts:s.ts,status:s.status,reviewed_by:s.reviewedBy||null,reviewed_at:s.reviewedAt||null,review_note:s.reviewNote||null,updated_at:s.updated_at||(new Date).toISOString()}}else if('po_upsert'===e.type){t='purchase_orders',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,po_number:s.poNumber,supplier_name:s.supplierName,items:s.items,status:s.status,created_by:s.createdBy,created_at:s.createdAt,invoice_number:s.invoiceNumber,invoice_photo:s.invoicePhoto,received_at:s.receivedAt,updated_at:s.updated_at||(new Date).toISOString()}}else if('table_order_upsert'===e.type){t='table_orders',a='resolution=merge-duplicates,return=minimal';const s=await tableOrderForPush(e.payload);n={id:s.id,shop_id:shopId,label:s.label,status:s.status,lines:s.lines,bill_printed:s.billPrinted||!1,kitchen_round_count:s.kitchenRoundCount||0,opened_by:s.openedBy,opened_at:s.openedAt,settled_at:s.settledAt,settled_sale_id:s.settledSaleId,updated_at:s.updated_at||(new Date).toISOString()}}else if('stock_take_upsert'===e.type){t='stock_takes',a='resolution=merge-duplicates,return=minimal';const s=e.payload;n={id:s.id,shop_id:shopId,ts:s.ts,performed_by:s.performed_by,items:s.items,updated_at:s.updated_at||(new Date).toISOString()}}else{if('shop_upsert'!==e.type)throw new Error(`Unknown sync item type "${e.type}" - nothing in pushToSupabase() handles it`);{const s=e.payload;if(!s||!s.name||'New shop'===s.name)return;const t=await fetchT(`${supaUrl}/functions/v1/shop-auth`,{method:'POST',headers:sbHeaders(),body:JSON.stringify({action:'shop_name',name:s.name})},1e4);if(!t.ok)throw new Error('Shop name not saved: '+t.status);return}}const s=await fetchT(`${supaUrl}/rest/v1/${t}`,{method:'POST',headers:sbHeaders({Prefer:a}),body:JSON.stringify(n)});if(!s.ok){const e=await s.text().catch((()=>''));if('audit_log'===t&&(404===s.status||/PGRST205|42P01/.test(e)))return;throw new Error(`Supabase rejected the row: ${s.status}${e?' - '+e.slice(0,150):''}`)}if('staff_upsert'===e.type)try{for(const r of await s.json()){const u=await getOne('users',r.id);u&&isScrambledPin(r.pin)&&u.pin===e.payload.pin&&(u.pin_h=r.pin,u.updated_at=r.updated_at,await put('users',u))}}catch(e){}}
  // These three need the open app (table reconciling, PIN bookkeeping, shop rename) - they wait for it.
  const LEAVE = new Set(['table_order_upsert', 'staff_upsert', 'shop_upsert']);
  async function flushNow() {
    db = await openDb(); if (!db) return { skipped: 'no data on this phone' };
    try {
      const id = await getSetting('shop_id'), ss = await getSetting('shop_session'), cfg = await getSetting('bg_sync_cfg');
      if (!id || !id.value || !cfg || !cfg.value || !cfg.value.supaUrl || !cfg.value.supaKey) return { skipped: 'not set up' };
      shopId = id.value; supaUrl = cfg.value.supaUrl; supaKey = cfg.value.supaKey; shopSession = ss && ss.value || null;
      const q = await getAll('sync_queue'); if (!q.length) return { done: 0, failed: 0, left: 0 };
      if (!sessionValid() && !(await refresh())) return { skipped: 'signed out - waits for the app', left: q.length };
      let done = 0, failed = 0, left = 0, offline = false;
      for (const n of q) {
        if (LEAVE.has(n.type)) { left++; continue; }
        try {
          await pushToSupabase(n);
          if (n.type === 'sale') { const s = await getOne('sales', n.payload.id); if (s) { s.synced = true; await put('sales', s); } }
          await del('sync_queue', n.id); done++;
        } catch (e) {
          failed++; n.failCount = (n.failCount || 0) + 1; await put('sync_queue', n);
          if (/fetch|network|abort/i.test(String(e && (e.message || e.name) || e))) { offline = true; break; }
        }
      }
      await put('settings', { key: 'bg_sync_last', value: { at: Date.now(), done, failed, left } });
      return { done, failed, left, offline };
    } finally { try { db.close(); } catch (e) {} db = null; }
  }
  async function flush(why) {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const onScreen = wins.find(c => c.visibilityState === 'visible');
    if (onScreen) { onScreen.postMessage({ type: 'RUN_SYNC' }); return { handedToApp: true }; }
    const r = self.navigator.locks ? await self.navigator.locks.request('dukago-sync', () => flushNow()) : await flushNow();
    if (r.done) for (const c of wins) { try { c.postMessage(Object.assign({ type: 'BG_SYNCED', why }, r)); } catch (e) {} }
    return r;
  }
  return { flush };
})();
self.DukaBG = DukaBG;
self.addEventListener('sync', (event) => {
  if (event.tag !== 'dukago-push') return;
  // Rejecting tells the browser to try again later (it backs off by itself) - only when the network let us down.
  event.waitUntil(DukaBG.flush('sync').then((r) => { if (r && r.offline) throw new Error('still offline'); }));
});
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'dukago-periodic') event.waitUntil(DukaBG.flush('periodic').catch(() => {}));
});
