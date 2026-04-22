const CACHE = 'mialarm-v5'; // <--- CADA VEZ QUE SUBAS ALGO, CAMBIA ESTO (v2, v3, v4...)
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json'
];

// Instalación: Guardar archivos en caché
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS))
  );
  // No usamos skipWaiting aquí para que el index.html pueda controlarlo
});

// Activación: Limpiar cachés antiguas
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE).map(k => caches.delete(k))
    ))
  );
  self.clients.claim();
});

// Escuchar el mensaje del index.html para forzar la actualización
self.addEventListener('message', e => {
  if (e.data && e.data.action === 'skipWaiting') {
    self.skipWaiting();
  }
});

// Estrategia de red: Intentar red primero para el index.html, si falla, usar caché
// Esto asegura que si hay internet, siempre busque la última versión
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  e.respondWith(
    fetch(e.request)
      .then(res => {
        // Si la red responde, guardamos copia en caché y devolvemos
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => {
        // Si no hay red (offline), servimos de la caché
        return caches.match(e.request);
      })
  );
});
