// My DukaGO POS — app-shell service worker
// Caches the till page + manifest so the app can be opened cold, with zero
// network at all, after the first successful visit. This only caches the
// app's own files — sales/stock data lives in IndexedDB (see index.html)
// and is untouched by this file.

const CACHE_NAME = 'my-duka-pos-shell-v26-2026-10-17';
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
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
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
