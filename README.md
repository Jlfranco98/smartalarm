# MiAlarma PWA

App web progresiva con login, pantalla de inicio estilo Verisure y barra de navegación inferior.

## Credenciales de prueba

| Nombre          | Usuario  | Contraseña  | PIN   | Rol   |
|-----------------|----------|-------------|-------|-------|
| Administrador   | admin    | admin123    | 1234  | Admin |
| María García    | maria    | maria123    | 5678  | User  |
| Carlos López    | carlos   | carlos123   | 9012  | User  |

## Pantallas

- **Inicio** — Estado de alarma (círculo grande), acciones rápidas, últimos eventos
- **Historial** — Todos los eventos de armado/desarmado
- **Usuarios** — Gestión de usuarios (solo admin puede agregar/eliminar)
- **Mi cuenta** — Info del usuario, config de backend Tuya, cambio de contraseña

## Publicar (Netlify — gratis)

1. Ve a https://app.netlify.com
2. Arrastra la carpeta `alarm-pwa2` al área de deploy
3. Obtén URL HTTPS pública al instante

## Instalar en móvil

- **Android**: Chrome → menú ⋮ → "Instalar app"
- **iOS**: Safari → Compartir → "Añadir a pantalla de inicio"

## Conectar con backend Tuya

Login como admin → Mi cuenta → "Conexión backend Tuya"
- URL Backend: `https://tu-backend.railway.app`
- App Secret: la clave `APP_SECRET` de tu backend
- Device ID: ID de la alarma
