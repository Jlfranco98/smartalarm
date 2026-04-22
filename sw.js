const CACHE = 'mialarm-v5.4'; // <-- cambia esto en cada despliegue (v6, v7...)
const STATIC = ['/', '/index.html', '/manifest.json'];

// INSTALL: guarda estáticos, sin skipWaiting para que el index controle cuándo activar
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC))
  );
});

// ACTIVATE: borra cachés antiguas y reclama clientes
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// MESSAGE: el index.html llama a skipWaiting cuando el usuario pulsa ACTUALIZAR
self.addEventListener('message', e => {
  if (e.data?.action === 'skipWaiting') self.skipWaiting();
});

// FETCH
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = new URL(e.request.url);

  // API y recursos externos: nunca cachear, siempre red directa
  if (url.pathname.startsWith('/api/') || url.origin !== self.location.origin) {
    e.respondWith(fetch(e.request));
    return;
  }

  // index.html y navegación: network-first para detectar actualizaciones
  if (e.request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    e.respondWith(
      fetch(e.request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // Resto (manifest, iconos): cache-first
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
        return res;
      });
    })
  );
});
