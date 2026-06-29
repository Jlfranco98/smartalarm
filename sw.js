const CACHE = 'mialarm-v7.7';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
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
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => {
        return caches.match(e.request);
      })
  );
});

// ── Push: mostrar notificación + avisar a clientes abiertos (bandeja) ──────
self.addEventListener('push', e => {
  let data = { title: 'Smart Alarm', body: 'Nueva notificación', icon: '/icon-192.png', data: { url: '/' } };
  try { data = e.data.json(); } catch(err) {}

  e.waitUntil(
    Promise.all([
      // 1. Notificación nativa del sistema
      self.registration.showNotification(data.title, {
        body:     data.body,
        icon:     data.icon  || '/icon-192.png',
        badge:    data.badge || '/icon-192.png',
        vibrate:  [200, 100, 200],
        tag:      'alarm-status',
        renotify: true,
        data:     data.data || { url: '/' }
      }),
      // 2. Avisar a la app abierta → bandeja de notificaciones
      self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
        clients.forEach(c => c.postMessage({
          title: data.title,
          body:  data.body,
        }));
      })
    ])
  );
});

// ── Push: al pulsar la notificación, abrir la app ─────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.notification.data?.url || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cls => {
      if (url.includes('maps.google.com')) {
        return clients.openWindow(url);
      }
      const app = cls.find(c => c.url.includes(self.location.origin));
      if (app) return app.focus();
      return clients.openWindow('/');
    })
  );
});
