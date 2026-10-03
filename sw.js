// My DukaGO POS — app-shell service worker
// Caches the till page + manifest so the app can be opened cold, with zero
// network at all, after the first successful visit. This only caches the
// app's own files — sales/stock data lives in IndexedDB (see index.html)
// and is untouched by this file.

const CACHE_NAME = 'my-duka-pos-shell-v5-2026-10-03';
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
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// Network-first for the shell so an online cashier always gets the latest
// build; falls back to the cached copy the moment the network fails.
// cache:'no-store' matters here — without it, `fetch()` can still be silently
// answered by the browser's own HTTP cache (or a CDN's) instead of actually
// hitting the network, which is how a real deploy can sit invisible even
// though this network-first logic looks correct.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const isNavigation = event.request.mode === 'navigate';

  event.respondWith(
    fetch(event.request, { cache: 'no-store' })
      .then((response) => {
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
