// My DukaGO POS — app-shell service worker
// Caches the till page + manifest so the app can be opened cold, with zero
// network at all, after the first successful visit. This only caches the
// app's own files — sales/stock data lives in IndexedDB (see index.html)
// and is untouched by this file.

const CACHE_NAME = 'my-duka-pos-shell-v2';
const SHELL_FILES = [
  './index.html',
  './manifest.json'
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

  event.respondWith(
    fetch(event.request, { cache: 'no-store' })
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
