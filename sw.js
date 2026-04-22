const CACHE = 'mialarm-v6.7'; // <--- Recuerda subir la versión
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json'
];

// ... (Tus eventos install, activate y fetch se mantienen igual) ...

// ── EVENTO: RECIBIR NOTIFICACIÓN PUSH ──────────────────────────────────
self.addEventListener('push', e => {
  let data = { title: 'Alarma', body: 'Nueva actualización de estado', icon: '/icon-192.png' };

  if (e.data) {
    try {
      data = e.data.json();
    } catch (err) {
      data.body = e.data.text();
    }
  }

  const options = {
    body: data.body,
    icon: data.icon || '/icon-192.png',
    badge: '/icon-192.png', // Icono pequeño para la barra de estado
    vibrate: [200, 100, 200],
    data: {
      url: self.registration.scope // Para saber a dónde ir al hacer clic
    },
    // Si es un salto de alarma, podemos añadirle más prioridad
    tag: data.tag || 'alarma-status', 
    renotify: true
  };

  e.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// ── EVENTO: CLIC EN LA NOTIFICACIÓN ─────────────────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close(); // Cerrar la notificación

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      // Si la app ya está abierta, poner el foco en ella
      for (const client of clientList) {
        if (client.url === e.notification.data.url && 'focus' in client) {
          return client.focus();
        }
      }
      // Si no está abierta, abrirla
      if (clients.openWindow) {
        return clients.openWindow(e.notification.data.url);
      }
    })
  );
});
