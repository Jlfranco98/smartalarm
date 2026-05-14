const express  = require('express');
const cors     = require('cors');
const path     = require('path');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const webpush  = require('web-push');
const { TuyaContext } = require('@tuya/tuya-connector-nodejs');

const crypto = require('crypto');
const twilio = require('twilio');
const app = express();
app.use('/api/change-avatar', express.json({ limit: '800kb' })); // avatares en base64
app.use(express.json({ limit: '10kb' }));                              // resto de rutas
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || false, // Pon en Railway: ALLOWED_ORIGIN=https://tu-dominio.com
  methods: ['GET','POST','PUT','PATCH','DELETE'],
  allowedHeaders: ['Content-Type','X-App-Token']
}));
app.use(express.static(path.join(__dirname, '.')));

function generateToken() { return crypto.randomBytes(32).toString('hex'); }

// ── Rate limiting de login (sin dependencias externas) ──────────────────────
// Bloquea IPs que fallen más de 10 veces en 15 minutos
const loginAttempts = new Map(); // ip -> { count, firstAt }
const LOGIN_MAX     = 10;
const LOGIN_WINDOW  = 15 * 60 * 1000; // 15 min

function checkLoginRateLimit(ip) {
  const now  = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.firstAt > LOGIN_WINDOW) {
    loginAttempts.set(ip, { count: 1, firstAt: now });
    return { allowed: true };
  }
  if (entry.count >= LOGIN_MAX) {
    const waitMs   = LOGIN_WINDOW - (now - entry.firstAt);
    const waitMins = Math.ceil(waitMs / 60000);
    return { allowed: false, waitMins };
  }
  entry.count++;
  return { allowed: true };
}
function resetLoginRateLimit(ip) { loginAttempts.delete(ip); }
// Limpiar entradas expiradas cada hora
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now - entry.firstAt > LOGIN_WINDOW) loginAttempts.delete(ip);
  }
}, 60 * 60 * 1000);

// ── Rate limiting de PIN (más estricto: 5 intentos en 10 minutos) ────────────
const pinAttempts = new Map(); // ip -> { count, firstAt }
const PIN_MAX     = 5;
const PIN_WINDOW  = 10 * 60 * 1000; // 10 min

function checkPinRateLimit(ip) {
  const now   = Date.now();
  const entry = pinAttempts.get(ip);
  if (!entry || now - entry.firstAt > PIN_WINDOW) {
    pinAttempts.set(ip, { count: 1, firstAt: now });
    return { allowed: true };
  }
  if (entry.count >= PIN_MAX) {
    const waitMs   = PIN_WINDOW - (now - entry.firstAt);
    const waitMins = Math.ceil(waitMs / 60000);
    return { allowed: false, waitMins };
  }
  entry.count++;
  return { allowed: true };
}
function resetPinRateLimit(ip) { pinAttempts.delete(ip); }
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of pinAttempts) {
    if (now - entry.firstAt > PIN_WINDOW) pinAttempts.delete(ip);
  }
}, 60 * 60 * 1000);

// PINs bloqueados por ser demasiado predecibles
const PIN_BLACKLIST = [
  '0000','1111','2222','3333','4444','5555','6666','7777','8888','9999',
  '1234','4321','1122','1212','2580','0852','2468','1357',
  '0123','9876','6969','1010','1001',
];

// Compara PIN sea cual sea su formato (texto plano legacy o bcrypt)
async function checkPinCompat(inputPin, storedPin, username) {
  if (!storedPin) return false;
  const isHashed = storedPin.startsWith('$2b$') || storedPin.startsWith('$2a$');
  if (isHashed) {
    return await bcrypt.compare(inputPin, storedPin);
  } else {
    if (inputPin !== storedPin) return false;
    const hashed = await bcrypt.hash(inputPin, 10);
    await require('mongoose').model('User').updateOne({ username }, { $set: { pin: hashed } });
    console.log(`🔒 PIN de ${username} migrado a bcrypt automáticamente`);
    return true;
  }
}

// ── Sesiones en MongoDB (sobreviven reinicios del servidor) ────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['x-app-token'];
  if (!token) return res.status(401).json({ success: false, message: 'No autorizado' });
  try {
    const session = await Session.findOne({ token });
    if (!session) return res.status(401).json({ success: false, message: 'No autorizado' });
    req.sessionUser = session.username;
    // Actualizar lastSeenAt sin bloquear la petición
    Session.updateOne({ token }, { $set: { lastSeenAt: new Date() } }).catch(() => {});
    next();
  } catch(e) {
    res.status(500).json({ success: false, message: 'Error de sesión' });
  }
}

// --- 1. VARIABLES DE ENTORNO ---
const MONGO_URI          = process.env.MONGO_URL || process.env.MONGODB_URI;
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;       // Cuenta B: agua + panel
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;   // Cuenta B
const TUYA_DEVICE_ID     = process.env.TUYA_DEVICE_KEY;      // Panel alarma
const TUYA_REGION        = process.env.TUYA_REGION || 'eu';
const VAPID_PUBLIC       = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE      = process.env.VAPID_PRIVATE_KEY || '';

// Cloudinary (para avatares — evita guardar base64 en MongoDB)
const CLOUDINARY_URL     = process.env.CLOUDINARY_URL || '';  // formato: cloudinary://api_key:api_secret@cloud_name

// Twilio (llamadas de alarma)
const TWILIO_SID   = process.env.TWILIO_SID   || '';
const TWILIO_TOKEN = process.env.TWILIO_TOKEN  || '';
const TWILIO_FROM  = process.env.TWILIO_FROM   || ''; // número Twilio: +12184234129
const TWILIO_TO    = (process.env.TWILIO_TO    || '').split(',').map(n => n.trim()).filter(Boolean);

// Cuenta A: solo sensor de luz (alarma crítica)
const TUYA_CLIENT_ID_ALARMA     = process.env.TUYA_CLIENT_ID_ALARMA;
const TUYA_CLIENT_SECRET_ALARMA = process.env.TUYA_CLIENT_SECRET_ALARMA;

const REGION_URL = {
  eu: 'https://openapi.tuyaeu.com',
  us: 'https://openapi.tuyaus.com',
  cn: 'https://openapi.tuyacn.com',
  in: 'https://openapi.tuyain.com',
};
const BASE_URL = REGION_URL[TUYA_REGION] || REGION_URL['eu'];

// ⏱️ DOS VELOCIDADES OPTIMIZADAS:
const POLL_ALARMA_MS = 5 * 60 * 1000;  // 5 min (CUENTA A - Respaldo, ya que MacroDroid es el principal)
const POLL_NORMAL_MS = 15 * 60 * 1000;  // 15 min (CUENTA B - Equilibrio agua + panel)

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:admin@smartalarm.app', VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('✅ Web Push VAPID configurado');
}

// --- 2. MONGODB ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error MongoDB:', err));

// --- 3. ESQUEMAS ---
const userSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  pin: String,
  role: { type: String, default: 'user' },
  isNew: { type: Boolean, default: true },
  avatar: { type: String, default: null }
}, { collection: 'users', timestamps: true, suppressReservedKeysWarning: true });

const logSchema = new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}, { collection: 'logs' });

const configSchema = new mongoose.Schema({
  id: { type: String, default: 'global_config', unique: true },
  backendUrl: String,
  deviceId: String,
  alarmStatus: { type: String, default: 'disarmed' }
}, { collection: 'configs' });

const pushSubSchema = new mongoose.Schema({
  username: { type: String, required: true },
  subscription: { type: Object, required: true },
  device: { type: String, default: 'unknown' }
}, { collection: 'push_subscriptions', timestamps: true });

const sessionSchema = new mongoose.Schema({
  token:      { type: String, required: true, unique: true },
  username:   { type: String, required: true },
  createdAt:  { type: Date, default: Date.now, expires: 60 * 60 * 24 * 90 }, // 90 días
  lastSeenAt: { type: Date, default: Date.now },
  userAgent:  { type: String, default: '' },
  deviceName: { type: String, default: '' }  // Nombre personalizado del dispositivo
}, { collection: 'sessions' });

const notifPrefSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  arm_away: { type: Boolean, default: true },
  arm_home: { type: Boolean, default: true },
  disarm:   { type: Boolean, default: true }
}, { collection: 'notif_prefs' });

// ── Automatizaciones ──────────────────────────────────────────────────────────
const automationSchema = new mongoose.Schema({
  // 'alarma' = armar/desarmar (visible para todos) | 'recordatorio' | 'silencio' | 'resumen' (personales)
  tipo:       { type: String, required: true },
  // Para tipo 'alarma': null (pertenece a todos). Para el resto: username del propietario
  username:   { type: String, default: null },
  nombre:     { type: String, required: true },
  dias:       [{ type: String }],   // ['L','M','X','J','V','S','D']
  hora:       { type: String },     // 'HH:MM'
  horaFin:    { type: String },     // solo para silencio
  accion:     { type: String },     // arm_away | arm_home | disarm  (solo tipo alarma)
  mensaje:    { type: String },     // solo tipo recordatorio
  activa:     { type: Boolean, default: true },
  ultimaEjecucion: { type: Date, default: null }
}, { collection: 'automations', timestamps: true });

const User       = mongoose.model('User',       userSchema);
const Session    = mongoose.model('Session',    sessionSchema);
const Log        = mongoose.model('Log',        logSchema);
const Config     = mongoose.model('Config',     configSchema);
const PushSub    = mongoose.model('PushSub',    pushSubSchema);
const NotifPref  = mongoose.model('NotifPref',  notifPrefSchema);
const Automation = mongoose.model('Automation', automationSchema);

// --- 4. DOS CLIENTES TUYA ---

// CLIENTE A: sensor de luz (cuenta exclusiva para la alarma)
const tuyaClientAlarma = new TuyaContext({
  baseUrl: BASE_URL,
  accessKey: TUYA_CLIENT_ID_ALARMA,
  secretKey: TUYA_CLIENT_SECRET_ALARMA,
});

// CLIENTE B: agua + panel (cuenta principal)
const tuyaClientNormal = new TuyaContext({
  baseUrl: BASE_URL,
  accessKey: TUYA_CLIENT_ID,
  secretKey: TUYA_CLIENT_SECRET,
});

async function tuyaAlarma(method, path, body) {
  return await tuyaClientAlarma.request({ method, path, body });
}
async function tuyaNormal(method, path, body) {
  return await tuyaClientNormal.request({ method, path, body });
}

// --- 5. ESTADO EN MEMORIA ---
const SENSOR_LUZ_ID = process.env.SENSOR_LUZ_ID;
const SENSORES_AGUA = [
  { id: process.env.SENSOR_AGUA_JOSE,    nombre: 'Jose'    },
  { id: process.env.SENSOR_AGUA_COCINA,  nombre: 'Cocina'  },
  { id: process.env.SENSOR_AGUA_PASILLO, nombre: 'Pasillo' },
];
let sensorOffline = false;
const dispositivosOffline = {};
const deviceStateCache = {};
let ultimoHeartbeat = Date.now(); // Arranca asumiendo que está vivo
let heartbeatAlertaEnviada = false;
const HEARTBEAT_TIMEOUT_MS = 10 * 60 * 1000; // 10 min sin pulso = alerta

// --- 6. SENSOR DE LUZ (CUENTA A)
// Solo comprueba online/offline — MacroDroid gestiona el salto de alarma
async function checkSensorLuz() {
  try {
    const data = await tuyaAlarma('GET', `/v1.0/devices/${SENSOR_LUZ_ID}`);
    const isOnline = data.result?.online === true;
    deviceStateCache[SENSOR_LUZ_ID] = { online: isOnline, updatedAt: Date.now() };
    console.log(`🛡️ Comprobando Estado Centralita: ${isOnline ? '✅' : '❌'}`);

    if (!isOnline && !sensorOffline) {
      sensorOffline = true;
      await new Log({ usuario: 'Verisure', accion: '⚠️ Centralita desconectada' }).save();
      await sendPushNotification('sensor_offline', 'Verisure');
      return;
    }
    if (isOnline && sensorOffline) {
      sensorOffline = false;
      await new Log({ usuario: 'Verisure', accion: '✅ Centralita reconectada' }).save();
      await sendPushNotification('sensor_online', 'Verisure');
    }
  } catch (e) {
    console.error('❌ Error sensor luz:', e.message);
  }
}

// --- 7. AGUA + PANEL (CUENTA B)
// Solo comprueba online/offline — MacroDroid gestiona la deteccion de fugas de agua
async function checkSensoresLentos() {
  await Promise.all([
    checkPanelAlarma(),
    ...SENSORES_AGUA.map(s => checkSensorAgua(s))
  ]);
  const panel = deviceStateCache[TUYA_DEVICE_ID]?.online ? '✅' : '❌';
  const agua = SENSORES_AGUA.map(s => `${s.nombre}: ${deviceStateCache[s.id]?.online ? '✅' : '❌'}`).join(' | ');
  console.log(`🔎 Comprobando Estado Dispositivos — Panel: ${panel} | Agua — ${agua}`);
}

async function checkPanelAlarma() {
  try {
    const data = await tuyaNormal('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`);
    const isOnline = data.result?.online === true;
    deviceStateCache[TUYA_DEVICE_ID] = { online: isOnline, updatedAt: Date.now() };

    if (!isOnline && !dispositivosOffline['panel']) {
      dispositivosOffline['panel'] = true;
      await new Log({ usuario: 'Verisure', accion: '⚠️ Panel Alarma desconectado' }).save();
      await sendPushNotification('panel_offline', 'Verisure');
    } else if (isOnline && dispositivosOffline['panel']) {
      dispositivosOffline['panel'] = false;
      await new Log({ usuario: 'Verisure', accion: '✅ Panel Alarma reconectado' }).save();
      await sendPushNotification('panel_online', 'Verisure');
    }
  } catch (e) { console.error('❌ Error panel:', e.message); }
}

// Solo comprueba online/offline — MacroDroid gestiona la detección de fugas
async function checkSensorAgua(sensor) {
  try {
    const data = await tuyaNormal('GET', `/v1.0/devices/${sensor.id}`);
    const isOnline = data.result?.online === true;
    deviceStateCache[sensor.id] = { online: isOnline, updatedAt: Date.now() };

    if (!isOnline && !dispositivosOffline[sensor.id]) {
      dispositivosOffline[sensor.id] = true;
      await new Log({ usuario: 'Verisure', accion: `⚠️ Sensor Agua ${sensor.nombre} desconectado` }).save();
      await sendPushNotification('dispositivo_offline_' + sensor.id, 'Verisure');
      return;
    }
    if (isOnline && dispositivosOffline[sensor.id]) {
      dispositivosOffline[sensor.id] = false;
      await new Log({ usuario: 'Verisure', accion: `✅ Sensor Agua ${sensor.nombre} reconectado` }).save();
      await sendPushNotification('dispositivo_online_' + sensor.id, 'Verisure');
    }
  } catch (e) { console.error(`❌ Error agua ${sensor.nombre}:`, e.message); }
}

// --- 8. PUSH NOTIFICATIONS ---
async function sendPushNotification(action, triggeredBy, ubicacion = null) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  
  const notificarATodos = ['sos','sensor_luz','sensor_offline','sensor_online','panel_offline','panel_online','macrodroid_offline','macrodroid_online'].includes(action)
    || action.startsWith('sensor_agua_') || action.startsWith('dispositivo_offline_') || action.startsWith('dispositivo_online_');

  let subs;
  if (notificarATodos) {
    subs = await PushSub.find({});
  } else {
    const prefs = await NotifPref.find({ [action]: true });
    if (!prefs.length) return;
    subs = await PushSub.find({ username: { $in: prefs.map(p => p.username) } });
  }

  if (!subs.length) return;

  // Labels dinámicos para sensores de agua (usan IDs de variables de entorno)
  const labelsAgua = {};
  for (const s of SENSORES_AGUA) {
    if (!s.id) continue;
    labelsAgua[`sensor_agua_${s.id}`]         = `💧 Fuga de agua — ${s.nombre}`;
    labelsAgua[`dispositivo_offline_${s.id}`] = `⚠️ Sensor Agua ${s.nombre} desconectado`;
    labelsAgua[`dispositivo_online_${s.id}`]  = `✅ Sensor Agua ${s.nombre} reconectado`;
  }
  const labels = {
    arm_away: '🔒 Modo total activado', arm_home: '🌙 Modo noche activado',
    disarm: '🔓 Alarma desarmada', sos: '🆘 PÁNICO / SOS', sensor_luz: '🚨 ¡ALARMA SALTADA!',
    sensor_offline: '⚠️ Centralita desconectada', sensor_online: '✅ Centralita reconectada',
    panel_offline: '⚠️ Panel Alarma desconectado', panel_online: '✅ Panel Alarma reconectado',
    macrodroid_offline: '⚠️ Servidor de seguridad caído',
    macrodroid_online: '✅ Servidor de seguridad reactivado',
    ...labelsAgua,
  };

  const mapsUrl = ubicacion ? `https://maps.google.com/?q=${ubicacion.lat},${ubicacion.lng}` : null;
  const body = action === 'sos' && mapsUrl
    ? `${triggeredBy} — 📍 Pulsa para ver ubicación (±${ubicacion.precision}m)`
    : `Por: ${triggeredBy}`;

  const payload = JSON.stringify({
    title: labels[action] || action,
    body,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: mapsUrl ? { url: mapsUrl } : { url: '/' }
  });

  await Promise.allSettled(subs.map(async sub => {
    try { await webpush.sendNotification(sub.subscription, payload); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await PushSub.deleteOne({ _id: sub._id }); }
  }));
}

// --- 9. USUARIOS ---
app.get('/api/usuarios', requireAuth, async (req, res) => { try { res.json(await User.find({}, '-password')); } catch (e) { res.status(500).json([]); } });
app.post('/api/usuarios', requireAuth, async (req, res) => {
  try {
    // Solo admins pueden crear usuarios
    const requestingUser = await User.findOne({ username: req.sessionUser });
    if (!requestingUser || requestingUser.role !== 'admin')
      return res.status(403).json({ success: false, message: 'Solo un administrador puede crear usuarios' });

    const { name, username, password, pin, role } = req.body;
    const hashedPin = pin ? await bcrypt.hash(pin, 10) : null;
    await new User({ name, username, password: await bcrypt.hash(password, 10), pin: hashedPin, role: role || 'user' }).save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/usuarios/:username', requireAuth, async (req, res) => {
  try {
    if (req.params.username === 'admin') return res.status(403).json({ success: false, message: 'No se puede eliminar al admin principal' });
    await User.findOneAndDelete({ username: req.params.username });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// --- 10. AUTH ---
app.post('/api/login', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  try {
    const { username, password, deviceName } = req.body;

    // Comprobar rate limit antes de tocar la base de datos
    const rl = checkLoginRateLimit(ip);
    if (!rl.allowed) {
      return res.status(429).json({ success: false, message: `Demasiados intentos. Inténtalo en ${rl.waitMins} minuto${rl.waitMins > 1 ? 's' : ''}.` });
    }

    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
      resetLoginRateLimit(ip); // Login correcto: limpiar conteo
      const token = generateToken();
      const ua = req.headers['user-agent'] || '';
      await Session.create({ token, username: user.username, userAgent: ua, deviceName: (deviceName || '').trim().slice(0, 60) });
      res.json({ success: true, token, user: { name: user.name, username: user.username, role: user.role, isNew: user.isNew, avatar: user.avatar || null } });
    }
    else res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
  } catch (e) { res.status(500).json({ success: false }); }
});

// Panel de sesiones activas (solo admin)
app.get('/api/sessions', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.sessionUser });
    if (!user || user.role !== 'admin') return res.status(403).json({ success: false });
    const sessions = await Session.find({}, '-token').sort({ lastSeenAt: -1 });
    res.json(sessions);
  } catch(e) { res.status(500).json([]); }
});

app.delete('/api/sessions/:id', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.sessionUser });
    if (!user || user.role !== 'admin') return res.status(403).json({ success: false });
    const session = await Session.findById(req.params.id);
    if (session) {
      // Si es la única sesión activa de ese usuario, también borramos sus push subs
      const otherSessions = await Session.countDocuments({ username: session.username, _id: { $ne: session._id } });
      if (otherSessions === 0) await PushSub.deleteMany({ username: session.username });
    }
    await Session.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ success: false }); }
});

app.patch('/api/sessions/:id/device-name', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.sessionUser });
    if (!user || user.role !== 'admin') return res.status(403).json({ success: false });
    const { deviceName } = req.body;
    if (!deviceName || !deviceName.trim()) return res.status(400).json({ success: false, message: 'Nombre no válido' });
    await Session.findByIdAndUpdate(req.params.id, { $set: { deviceName: deviceName.trim().slice(0, 60) } });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ success: false }); }
});

app.delete('/api/sessions/user/:username', requireAuth, async (req, res) => {  try {
    const user = await User.findOne({ username: req.sessionUser });
    if (!user || user.role !== 'admin') return res.status(403).json({ success: false });
    await Session.deleteMany({ username: req.params.username });
    await PushSub.deleteMany({ username: req.params.username });
    res.json({ success: true });
  } catch(e) { res.status(500).json({ success: false }); }
});

app.post('/api/force-set-pin', requireAuth, async (req, res) => {
  try {
    const { username, newPin } = req.body;
    if (!username || !/^\d{4}$/.test(newPin)) return res.status(400).json({ success: false, message: 'Datos inválidos' });
    if (PIN_BLACKLIST.includes(newPin)) return res.json({ success: false, message: 'PIN demasiado predecible.' });
    const user = await User.findOne({ username });
    if (!user || !user.isNew) return res.status(403).json({ success: false, message: 'No permitido' });
    const newPinHashed = await bcrypt.hash(newPin, 10);
    await User.updateOne({ username }, { $set: { pin: newPinHashed, isNew: false } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/verify-pin', requireAuth, async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  try {
    const rl = checkPinRateLimit(ip);
    if (!rl.allowed)
      return res.status(429).json({ valid: false, message: `Demasiados intentos. Inténtalo en ${rl.waitMins} minuto${rl.waitMins > 1 ? 's' : ''}.` });

    const { username, pin } = req.body;
    if (!username || !pin) return res.status(400).json({ valid: false });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ valid: false });
    const valid = await checkPinCompat(pin, user.pin, username);
    if (valid) resetPinRateLimit(ip); // PIN correcto: resetear contador
    res.json({ valid });
  } catch (e) { res.status(500).json({ valid: false }); }
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { username, currentPassword, newPassword } = req.body;
    if (!username || !currentPassword || !newPassword)
      return res.status(400).json({ success: false, message: 'Faltan campos obligatorios.' });
    const forbidden = ['password','pass','123','1234','12345','123456','admin','qwerty'];
    if (forbidden.includes(newPassword.toLowerCase()))
      return res.json({ success: false, message: 'Contraseña demasiado fácil.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    // Validar contraseña actual
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) return res.json({ success: false, message: 'La contraseña actual es incorrecta.' });
    // Que no sea igual a la anterior
    if (await bcrypt.compare(newPassword, user.password))
      return res.json({ success: false, message: 'La nueva contraseña debe ser diferente a la anterior.' });
    await User.updateOne({ username }, { $set: { password: await bcrypt.hash(newPassword, 10), isNew: false } });
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/change-name', requireAuth, async (req, res) => {
  try {
    const { username, name } = req.body;
    if (!username || !name || name.trim().length < 2)
      return res.status(400).json({ success: false, message: 'Nombre no válido.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    if (username !== req.sessionUser) return res.status(403).json({ success: false, message: 'No autorizado' });
    await User.updateOne({ username }, { $set: { name: name.trim() } });
    res.json({ success: true, message: 'Nombre actualizado correctamente' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/change-avatar', requireAuth, async (req, res) => {
  try {
    const { username, avatar } = req.body;
    if (!username) return res.status(400).json({ success: false, message: 'Falta el usuario.' });
    const requestingUser = await User.findOne({ username: req.sessionUser });
    if (username !== req.sessionUser && requestingUser?.role !== 'admin') return res.status(403).json({ success: false, message: 'No autorizado' });

    if (!avatar) {
      // Eliminar avatar
      await User.updateOne({ username }, { $set: { avatar: null } });
      return res.json({ success: true, message: 'Foto eliminada' });
    }

    // Si Cloudinary está configurado, subir la imagen allí y guardar solo la URL
    if (CLOUDINARY_URL) {
      try {
        // Parsear CLOUDINARY_URL: cloudinary://api_key:api_secret@cloud_name
        const match = CLOUDINARY_URL.match(/cloudinary:\/\/([^:]+):([^@]+)@(.+)/);
        if (!match) return res.status(500).json({ success: false, message: 'CLOUDINARY_URL mal formada' });
        const [, apiKey, apiSecret, cloudName] = match;

        // Subir imagen a Cloudinary via API REST (sin SDK para no añadir dependencia)
        const timestamp = Math.floor(Date.now() / 1000);
        const signStr = `overwrite=true&public_id=avatar_${username}&timestamp=${timestamp}&transformation=c_fill,h_256,w_256`;
        const signature = require('crypto')
          .createHash('sha1')
          .update(signStr + apiSecret)
          .digest('hex');

        const formData = new URLSearchParams();
        formData.append('file', avatar);
        formData.append('public_id', `avatar_${username}`);
        formData.append('timestamp', timestamp);
        formData.append('api_key', apiKey);
        formData.append('signature', signature);
        formData.append('transformation', 'c_fill,h_256,w_256');
        formData.append('overwrite', 'true');

        const uploadRes = await fetch(
          `https://api.cloudinary.com/v1_1/${cloudName}/image/upload`,
          { method: 'POST', body: formData }
        );
        const uploadData = await uploadRes.json();
        if (!uploadData.secure_url) throw new Error(uploadData.error?.message || 'Upload fallido');

        await User.updateOne({ username }, { $set: { avatar: uploadData.secure_url } });
        return res.json({ success: true, message: 'Foto actualizada correctamente', avatarUrl: uploadData.secure_url });
      } catch (uploadErr) {
        console.error('❌ Error Cloudinary:', uploadErr.message);
        return res.status(500).json({ success: false, message: 'Error al subir la imagen' });
      }
    }

    // Fallback: si no hay Cloudinary, guardar base64 con límite estricto de 500KB
    if (avatar.length > 700 * 1024)
      return res.status(400).json({ success: false, message: 'Imagen demasiado grande. Configura Cloudinary para imágenes mayores.' });
    await User.updateOne({ username }, { $set: { avatar } });
    res.json({ success: true, message: 'Foto actualizada correctamente' });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/change-pin', requireAuth, async (req, res) => {
  try {
    const { username, currentPin, newPin } = req.body;
    if (PIN_BLACKLIST.includes(newPin)) return res.json({ success: false, message: 'PIN demasiado predecible.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    const pinMatch = await checkPinCompat(currentPin, user.pin, username);
    if (!pinMatch) return res.json({ success: false, message: 'PIN actual incorrecto' });
    if (newPin === currentPin) return res.json({ success: false, message: 'El nuevo PIN debe ser diferente.' });
    const newPinHashed = await bcrypt.hash(newPin, 10);
    await User.updateOne({ username }, { $set: { pin: newPinHashed, isNew: false } });
    res.json({ success: true, message: 'PIN actualizado' });
  } catch (e) { res.status(500).json({ success: false }); }
});

// --- 11. PUSH ---
app.get('/api/push/vapid-public', (req, res) => res.json({ publicKey: VAPID_PUBLIC }));
app.post('/api/push/subscribe', requireAuth, async (req, res) => {
  try {
    const { username, subscription, device } = req.body;
    if (!username || !subscription) return res.status(400).json({ success: false });
    await PushSub.findOneAndUpdate({ 'subscription.endpoint': subscription.endpoint }, { username, subscription, device: device || 'unknown' }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});
app.get('/api/push/prefs/:username', requireAuth, async (req, res) => {
  try { res.json(await NotifPref.findOne({ username: req.params.username }) || { arm_away: true, arm_home: true, disarm: true }); }
  catch (e) { res.status(500).json({ arm_away: true, arm_home: true, disarm: true }); }
});
app.post('/api/push/prefs', requireAuth, async (req, res) => {
  try {
    const { username, arm_away, arm_home, disarm } = req.body;
    await NotifPref.findOneAndUpdate({ username }, { arm_away, arm_home, disarm }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});
// --- HEARTBEAT STATUS ---
app.get('/api/heartbeat-status', requireAuth, (req, res) => {
  const ahora = Date.now();
  const segundos = Math.floor((ahora - ultimoHeartbeat) / 1000);
  const vivo = (ahora - ultimoHeartbeat) < HEARTBEAT_TIMEOUT_MS;
  res.json({ vivo, segundosDesdeUltimoPulso: segundos });
});

// --- 12. CONTROL ALARMA (usa cuenta B, el panel está ahí) ---
app.post('/api/control', requireAuth, async (req, res) => {
  const { action, alarmStatus, ubicacion } = req.body; // 'user' ignorado — usamos req.sessionUser
  const mapping = { disarm: 'switch_1', arm_home: 'switch_2', arm_away: 'switch_3', sos: 'switch_4' };
  const nombres = { disarm: 'Alarma Desarmada', arm_home: 'Modo noche activado', arm_away: 'Modo total activado', sos: 'PÁNICO / SOS' };
  try {
    const deviceInfo = await tuyaNormal('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`);
    if (!deviceInfo.result?.online) return res.json({ success: false, error: 'Panel desconectado.' });
    const result = await tuyaNormal('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
      commands: [{ code: mapping[action], value: true }]
    });
    if (result.success) {
      const mapsUrl = ubicacion ? `https://maps.google.com/?q=${ubicacion.lat},${ubicacion.lng}` : null;
      const accionLog = action === 'sos' && mapsUrl
        ? `PÁNICO / SOS — 📍 ${mapsUrl} (±${ubicacion.precision}m)`
        : nombres[action] || action;
      const userDoc = await User.findOne({ username: req.sessionUser });
      await new Log({ usuario: userDoc?.name || req.sessionUser, accion: accionLog }).save();
      await Config.findOneAndUpdate({ id: 'global_config' }, { $set: { alarmStatus } }, { upsert: true });
      sendPushNotification(action, userDoc?.name || req.sessionUser, ubicacion).catch(console.error);
    }
    res.json({ success: result.success, result: result.result });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// --- RUTA PARA MACRODROID ALARMA ---
app.get('/alerta-alarma', async (req, res) => {
  try {
    // 1. Definimos una clave secreta (pon la que tu quieras)
    const CLAVE_SECRETA = process.env.MACRODROID_SECRET; 
    
    // 2. Recogemos el token que viene en la URL
    const tokenRecibido = req.query.token;

    // 3. Verificamos si la clave es correcta
    if (tokenRecibido !== CLAVE_SECRETA) {
      console.log('❌ Intento de acceso no autorizado a la alarma');
      return res.status(401).send("No autorizado");
    }

    console.log('🚨 [MacroDroid] ¡AVISO DE ALARMA RECIBIDO Y VALIDADO!');
    
    // Guardar el log y enviar notificación
    await new Log({ 
      usuario: 'Verisure', 
      accion: '🚨 ALARMA SALTADA' 
    }).save();

    await sendPushNotification('sensor_luz', 'Verisure');
    await llamarAlarma();

    res.status(200).send("✅ Alerta procesada");
  } catch (e) {
    console.error('❌ Error en alerta MacroDroid:', e.message);
    res.status(500).send("Error");
  }
});

app.get('/alerta-agua', async (req, res) => {
  try {
    const { token, sensor } = req.query; // sensor será "Jose", "Cocina" o "Pasillo"
    const CLAVE_SECRETA = process.env.MACRODROID_SECRET;

    if (token !== CLAVE_SECRETA) return res.status(401).send("No autorizado");

    // 🔍 BUSCADOR DINÁMICO:
    // Buscamos en tu array SENSORES_AGUA el que tenga el nombre que viene de MacroDroid
    const datosSensor = SENSORES_AGUA.find(s => s.nombre.toLowerCase() === sensor.toLowerCase());
    
    // Si lo encuentra, usamos su ID. Si no, usamos uno genérico para no romper el código.
    const sensorId = datosSensor ? datosSensor.id : 'desconocido';

    console.log(`💧 [MacroDroid] Fuga detectada en: ${sensor} (ID identificado: ${sensorId})`);

    // 1. Guardar log con el nombre exacto
    await new Log({ 
      usuario: 'Verisure', 
      accion: `💧 Fuga de agua detectada — ${sensor}` 
    }).save();

    // 2. Enviar notificación push con el ID correcto
    await sendPushNotification('sensor_agua_' + sensorId, `Verisure`);

    res.status(200).send("✅ Alerta de agua procesada correctamente, enviando alerta");
  } catch (e) {
    console.error('❌ Error en alerta agua:', e.message);
    res.status(500).send("Error");
  }
});

// --- HEARTBEAT ENDPOINT ---
app.get('/heartbeat', async (req, res) => {
  const token = req.query.token;
  if (token !== process.env.MACRODROID_SECRET) {
    return res.status(401).send('No autorizado');
  }
  
  // Si estaba caído y vuelve, notificar
  if (heartbeatAlertaEnviada) {
    heartbeatAlertaEnviada = false;
    console.log('✅ Servidor de seguridad reactivado');
    await new Log({ usuario: 'Sistema', accion: '✅ Servidor de seguridad reactivado' }).save();
    await sendPushNotification('macrodroid_online', 'MacroDroid');
  }

  ultimoHeartbeat = Date.now();
  console.log('💓 Heartbeat recibido del servidor de seguridad');
  res.status(200).send('OK');
});

// Comprueba cada 5 minutos si el móvil sigue vivo
setInterval(async () => {
  try {
    const ahora = Date.now();
    const tiempoSinHeartbeat = ahora - ultimoHeartbeat;
    console.log(`🔍 Check heartbeat: ${Math.floor(tiempoSinHeartbeat / 60000)} min sin pulso`);
    if (tiempoSinHeartbeat > HEARTBEAT_TIMEOUT_MS && !heartbeatAlertaEnviada) {
      heartbeatAlertaEnviada = true;
      console.log('⚠️ Servidor de seguridad sin respuesta — enviando alerta');
      await new Log({ usuario: 'Sistema', accion: '⚠️ Servidor de seguridad caído — sin respuesta' }).save();
      await sendPushNotification('macrodroid_offline', 'MacroDroid');
    }
  } catch(e) {
    console.error('❌ Error en check heartbeat:', e.message);
  }
}, 5 * 60 * 1000);

// --- 13. HISTORIAL Y CONFIG ---
app.get('/api/logs', requireAuth,      async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(500)); } catch (e) { res.status(500).json([]); } });
app.get('/api/historial', requireAuth, async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(500)); } catch (e) { res.status(500).json([]); } });
app.get('/api/config', requireAuth,    async (req, res) => { try { res.json(await Config.findOne({ id: 'global_config' }) || {}); } catch (e) { res.status(500).json({}); } });
app.post('/api/config', requireAuth, async (req, res) => {
  try {
    const requestingUser = await User.findOne({ username: req.sessionUser });
    if (!requestingUser || requestingUser.role !== 'admin')
      return res.status(403).json({ success: false, message: 'Solo un administrador puede modificar la configuración' });
    const { alarmStatus, backendUrl, deviceId } = req.body;
    await Config.findOneAndUpdate({ id: 'global_config' }, { alarmStatus, backendUrl, deviceId }, { upsert: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});
app.get('/api/status', requireAuth,    async (req, res) => { try { const c = await Config.findOne({ id: 'global_config' }); res.json({ alarmStatus: c?.alarmStatus || 'disarmed' }); } catch (e) { res.status(500).send(e.message); } });

// --- 14. DISPOSITIVOS ---
const LISTA_DISPOSITIVOS = [
  { id: SENSOR_LUZ_ID,                    nombre: 'Centralita Alarma',    icono: '🛡️', ubicacion: 'Es el corazón de tu alarma'           },
  { id: TUYA_DEVICE_ID,                   nombre: 'Panel Alarma',         icono: '🛜', ubicacion: 'Es la unidad de control de tu alarma' },
  ...SENSORES_AGUA.filter(s => s.id).map(s => ({
    id: s.id, nombre: 'Sensor Fugas de Agua', icono: '💧', ubicacion: s.nombre
  })),
];

// Rastrear cuándo se detectó por primera vez que un dispositivo está offline
const offlineTracker = {};

app.get('/api/dispositivos', requireAuth, async (req, res) => {
  try {
    const ahora = Date.now();
    const VEINTE_MIN = 20 * 60 * 1000;
    const todosEnCache = LISTA_DISPOSITIVOS.every(d =>
      deviceStateCache[d.id] && (ahora - deviceStateCache[d.id].updatedAt) < VEINTE_MIN
    );
    const buildDispositivo = d => {
      const online = deviceStateCache[d.id]?.online ?? false;
      if (!online && !offlineTracker[d.id]) offlineTracker[d.id] = new Date().toISOString();
      if (online && offlineTracker[d.id]) delete offlineTracker[d.id];
      return { ...d, online, bateria: deviceStateCache[d.id]?.bateria ?? null, offlineSince: offlineTracker[d.id] || null };
    };
    if (todosEnCache) {
      return res.json(LISTA_DISPOSITIVOS.map(buildDispositivo));
    }
    await Promise.all([checkSensorLuz(), checkSensoresLentos()]);
    res.json(LISTA_DISPOSITIVOS.map(buildDispositivo));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- 14b. AUTOMATIZACIONES ---

// GET: devuelve automatizaciones de alarma (todas) + personales del usuario autenticado
app.get('/api/automations', requireAuth, async (req, res) => {
  try {
    const alarmAutos    = await Automation.find({ tipo: 'alarma' }).sort({ createdAt: -1 });
    const personalAutos = await Automation.find({ tipo: { $ne: 'alarma' }, username: req.sessionUser }).sort({ createdAt: -1 });
    res.json([...alarmAutos, ...personalAutos]);
  } catch(e) { res.status(500).json([]); }
});

// POST: crear automatización
app.post('/api/automations', requireAuth, async (req, res) => {
  try {
    const { tipo, nombre, dias, hora, horaFin, accion, mensaje } = req.body;
    const TIPOS_VALIDOS   = ['alarma', 'recordatorio', 'silencio', 'resumen'];
    const ACCIONES_VALIDAS = ['arm_away', 'arm_home', 'disarm'];
    const HORA_REGEX = /^([01]\d|2[0-3]):[0-5]\d$/;
    if (!tipo || !nombre) return res.status(400).json({ success: false, message: 'Faltan campos' });
    if (!TIPOS_VALIDOS.includes(tipo)) return res.status(400).json({ success: false, message: 'Tipo no válido' });
    if (hora && !HORA_REGEX.test(hora)) return res.status(400).json({ success: false, message: 'Formato de hora inválido' });
    if (horaFin && !HORA_REGEX.test(horaFin)) return res.status(400).json({ success: false, message: 'Formato de hora fin inválido' });
    if (tipo === 'alarma' && !accion) return res.status(400).json({ success: false, message: 'Falta la acción' });
    if (accion && !ACCIONES_VALIDAS.includes(accion)) return res.status(400).json({ success: false, message: 'Acción no válida' });
    if ((tipo === 'alarma' || tipo === 'recordatorio' || tipo === 'resumen') && (!dias || !dias.length || !hora))
      return res.status(400).json({ success: false, message: 'Faltan días u hora' });
    if (tipo === 'silencio' && (!hora || !horaFin))
      return res.status(400).json({ success: false, message: 'Faltan hora inicio y fin' });

    const auto = new Automation({
      tipo,
      username: tipo === 'alarma' ? null : req.sessionUser,
      nombre,
      dias:    dias    || [],
      hora:    hora    || null,
      horaFin: horaFin || null,
      accion:  accion  || null,
      mensaje: mensaje || null,
      activa:  true
    });
    await auto.save();
    res.json({ success: true, automation: auto });
  } catch(e) { res.status(500).json({ success: false, error: e.message }); }
});

// PUT: editar automatización completa
app.put('/api/automations/:id', requireAuth, async (req, res) => {
  try {
    const auto = await Automation.findById(req.params.id);
    if (!auto) return res.status(404).json({ success: false, message: 'No encontrada' });
    if (auto.tipo !== 'alarma' && auto.username !== req.sessionUser)
      return res.status(403).json({ success: false, message: 'Sin permiso' });

    const { nombre, dias, hora, horaFin, accion, mensaje } = req.body;
    const ACCIONES_VALIDAS_PUT = ['arm_away', 'arm_home', 'disarm'];
    const HORA_REGEX_PUT = /^([01]\d|2[0-3]):[0-5]\d$/;
    if (!nombre) return res.status(400).json({ success: false, message: 'Falta el nombre' });
    if (hora && !HORA_REGEX_PUT.test(hora)) return res.status(400).json({ success: false, message: 'Formato de hora inválido' });
    if (horaFin && !HORA_REGEX_PUT.test(horaFin)) return res.status(400).json({ success: false, message: 'Formato de hora fin inválido' });
    if (auto.tipo === 'alarma' && !accion) return res.status(400).json({ success: false, message: 'Falta la acción' });
    if (accion && !ACCIONES_VALIDAS_PUT.includes(accion)) return res.status(400).json({ success: false, message: 'Acción no válida' });
    if ((auto.tipo === 'alarma' || auto.tipo === 'recordatorio' || auto.tipo === 'resumen') && (!dias || !dias.length || !hora))
      return res.status(400).json({ success: false, message: 'Faltan días u hora' });
    if (auto.tipo === 'silencio' && (!hora || !horaFin))
      return res.status(400).json({ success: false, message: 'Faltan hora inicio y fin' });

    auto.nombre  = nombre;
    auto.dias    = dias    || [];
    auto.hora    = hora    || null;
    auto.horaFin = horaFin || null;
    auto.accion  = accion  || null;
    auto.mensaje = mensaje || null;
    await auto.save();
    res.json({ success: true, automation: auto });
  } catch(e) { res.status(500).json({ success: false, error: e.message }); }
});

// PATCH: activar / desactivar
app.patch('/api/automations/:id', requireAuth, async (req, res) => {
  try {
    const auto = await Automation.findById(req.params.id);
    if (!auto) return res.status(404).json({ success: false });
    if (auto.tipo !== 'alarma' && auto.username !== req.sessionUser)
      return res.status(403).json({ success: false });
    auto.activa = req.body.activa !== undefined ? req.body.activa : !auto.activa;
    await auto.save();
    res.json({ success: true, activa: auto.activa });
  } catch(e) { res.status(500).json({ success: false }); }
});

// DELETE: eliminar
app.delete('/api/automations/:id', requireAuth, async (req, res) => {
  try {
    const auto = await Automation.findById(req.params.id);
    if (!auto) return res.status(404).json({ success: false });
    if (auto.tipo !== 'alarma' && auto.username !== req.sessionUser)
      return res.status(403).json({ success: false });
    await Automation.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ success: false }); }
});

// GET: silencio activo ahora para un usuario (excluye saltos, agua, offline que siempre pasan)
app.get('/api/automations/silencio/:username', requireAuth, async (req, res) => {
  try {
    const autos = await Automation.find({ tipo: 'silencio', username: req.params.username, activa: true });
    const ahora = new Date();
    const minAhora = ahora.getHours() * 60 + ahora.getMinutes();
    const DIAS_MAP = { L:1, M:2, X:3, J:4, V:5, S:6, D:0 };
    const diaJS = ahora.getDay();
    let activo = false;
    for (const auto of autos) {
      if (auto.dias && auto.dias.length) {
        const diasJS = auto.dias.map(d => DIAS_MAP[d]);
        if (!diasJS.includes(diaJS)) continue;
      }
      if (!auto.hora || !auto.horaFin) continue;
      const [hI,mI] = auto.hora.split(':').map(Number);
      const [hF,mF] = auto.horaFin.split(':').map(Number);
      const minI = hI * 60 + mI;
      const minF = hF * 60 + mF;
      const enRango = minI <= minF
        ? (minAhora >= minI && minAhora < minF)
        : (minAhora >= minI || minAhora < minF);
      if (enRango) { activo = true; break; }
    }
    res.json({ activo });
  } catch(e) { res.status(500).json({ activo: false }); }
});

// ── Cron de automatizaciones (cada minuto) ─────────────────────────────────
const DIAS_CRON = { L:1, M:2, X:3, J:4, V:5, S:6, D:0 };
const NOMBRES_ACCION_AUTO = { arm_away:'Modo total activado', arm_home:'Modo noche activado', disarm:'Alarma Desarmada' };

setInterval(async () => {
  try {
    const ahora = new Date();
    const horaAhora = ahora.getHours().toString().padStart(2,'0') + ':' + ahora.getMinutes().toString().padStart(2,'0');
    const diaJS = ahora.getDay();

    const autos = await Automation.find({ activa: true, tipo: { $ne: 'silencio' } });

    for (const auto of autos) {
      if (auto.hora !== horaAhora) continue;

      // Evitar doble ejecución en el mismo minuto del mismo día
      if (auto.ultimaEjecucion) {
        const ul = auto.ultimaEjecucion;
        const mismoMinuto = ul.getFullYear() === ahora.getFullYear() &&
          ul.getMonth() === ahora.getMonth() &&
          ul.getDate()  === ahora.getDate() &&
          ul.getHours() === ahora.getHours() &&
          ul.getMinutes() === ahora.getMinutes();
        if (mismoMinuto) continue;
      }

      // Comprobar día de la semana
      if (auto.dias && auto.dias.length) {
        const diasJS = auto.dias.map(d => DIAS_CRON[d]);
        if (!diasJS.includes(diaJS)) continue;
      }

      if (auto.tipo === 'alarma') {
        const mapping = { disarm:'switch_1', arm_home:'switch_2', arm_away:'switch_3' };
        const code = mapping[auto.accion];
        if (!code) continue;
        try {
          const deviceInfo = await tuyaNormal('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`);
          if (!deviceInfo.result?.online) { console.log(`⚠️ Auto ${auto.nombre}: panel offline`); continue; }
          const result = await tuyaNormal('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code, value: true }]
          });
          if (result.success) {
            const nextStatus = auto.accion === 'disarm' ? 'disarmed' : auto.accion === 'arm_away' ? 'armed' : 'arm_home';
            await new Log({ usuario: `🤖 ${auto.nombre}`, accion: `${NOMBRES_ACCION_AUTO[auto.accion]}` }).save();
            await Config.findOneAndUpdate({ id: 'global_config' }, { $set: { alarmStatus: nextStatus } }, { upsert: true });
            sendPushNotification(auto.accion, `🤖 ${auto.nombre}`).catch(() => {});
            console.log(`✅ Auto alarma ejecutada: ${auto.nombre} → ${auto.accion}`);
          }
        } catch(e) { console.error(`❌ Error auto alarma ${auto.nombre}:`, e.message); }

      } else if (auto.tipo === 'recordatorio') {
        try {
          const subs = await PushSub.find({ username: auto.username });
          if (subs.length) {
            const payload = JSON.stringify({
              title: `🔔 ${auto.nombre}`,
              body:  auto.mensaje || 'Recordatorio programado',
              icon:  '/icon-192.png', badge: '/icon-192.png', data: { url: '/' }
            });
            await Promise.allSettled(subs.map(async sub => {
              try { await webpush.sendNotification(sub.subscription, payload); }
              catch(e2) { if (e2.statusCode===404||e2.statusCode===410) await PushSub.deleteOne({ _id: sub._id }); }
            }));
            console.log(`🔔 Recordatorio enviado a ${auto.username}: ${auto.nombre}`);
          }
        } catch(e) { console.error(`❌ Error recordatorio ${auto.nombre}:`, e.message); }

      } else if (auto.tipo === 'resumen') {
        try {
          const ayer = new Date(ahora); ayer.setDate(ayer.getDate()-1); ayer.setHours(0,0,0,0);
          const hoyI = new Date(ahora); hoyI.setHours(0,0,0,0);
          const logs = await Log.find({ fecha: { $gte: ayer, $lt: hoyI } }).sort({ fecha: -1 });
          const subs = await PushSub.find({ username: auto.username });
          if (subs.length) {
            const body = logs.length
              ? `${logs.length} evento${logs.length>1?'s':''} ayer. Último: ${logs[0].accion.slice(0,50)}`
              : 'Sin actividad ayer.';
            const payload = JSON.stringify({
              title: '📊 Resumen diario', body,
              icon: '/icon-192.png', badge: '/icon-192.png', data: { url: '/' }
            });
            await Promise.allSettled(subs.map(async sub => {
              try { await webpush.sendNotification(sub.subscription, payload); }
              catch(e2) { if (e2.statusCode===404||e2.statusCode===410) await PushSub.deleteOne({ _id: sub._id }); }
            }));
            console.log(`📊 Resumen enviado a ${auto.username}`);
          }
        } catch(e) { console.error(`❌ Error resumen ${auto.nombre}:`, e.message); }
      }

      await Automation.findByIdAndUpdate(auto._id, { $set: { ultimaEjecucion: ahora } });
    }
  } catch(e) { console.error('❌ Error cron automatizaciones:', e.message); }
}, 60 * 1000);

// --- 14b. TWILIO — LLAMADA DE ALARMA ---
async function llamarAlarma() {
  if (!TWILIO_SID || !TWILIO_TOKEN || !TWILIO_FROM || !TWILIO_TO.length) {
    console.warn('⚠️ Twilio no configurado — llamada omitida');
    return;
  }
  const client     = twilio(TWILIO_SID, TWILIO_TOKEN);
  const backendUrl = process.env.BACKEND_URL || 'https://smartalarm-production.up.railway.app';
  const twimlUrl   = `${backendUrl}/twilio/locucion`;

  for (const numero of TWILIO_TO) {
    try {
      await client.calls.create({ to: numero, from: TWILIO_FROM, url: twimlUrl });
      console.log(`📞 Llamada de alarma iniciada a ${numero}`);
    } catch (e) {
      console.error(`❌ Error llamada Twilio a ${numero}:`, e.message);
    }
  }
}

// Twilio necesita acceso sin restricción de CORS
app.use('/twilio', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

// Endpoint público que Twilio llama para obtener la locución TwiML
// MacroDroid dispara /alerta-alarma → llamarAlarma() → Twilio llama a este endpoint
app.get('/twilio/locucion', (req, res) => {
  res.type('text/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Gather numDigits="1" timeout="15">
    <Say language="es-ES" voice="Polly.Lucia">
      Sistema de seguridad Verisure.
    </Say>
    <Pause length="1"/>
    <Say language="es-ES" voice="Polly.Lucia">
      Se ha producido una alarma en su vivienda.
      Le rogamos que compruebe el estado de su instalación inmediatamente.
      Si se encuentra en su domicilio y todo está correcto,
      pulse uno para cancelar la alerta.
      En caso contrario, no pulse ninguna tecla.
    </Say>
  </Gather>
  <Say language="es-ES" voice="Polly.Lucia">
    No hemos recibido respuesta. Permanezca en lugar seguro.
  </Say>
</Response>`);
});

// Endpoint que recibe la tecla pulsada durante la llamada
app.post('/twilio/confirmar', (req, res) => {
  const tecla = req.body.Digits;
  res.type('text/xml');
  if (tecla === '1') {
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say language="es-ES" voice="Polly.Lucia">
    Alerta cancelada. Gracias por confirmar. Hasta pronto.
  </Say>
</Response>`);
  } else {
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say language="es-ES" voice="Polly.Lucia">
    Procedemos a contactar con los servicios de emergencia. Permanezca en lugar seguro.
  </Say>
</Response>`);
  }
});

// --- 15. ARRANQUE ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  console.log(`🚀 Servidor activo en puerto ${PORT}`);
  console.log(`⚡ Cuenta A (alarma): polling cada ${POLL_ALARMA_MS / 60000} min`);
  console.log(`🔄 Cuenta B (agua+panel): polling cada ${POLL_NORMAL_MS / 60000} min`);

  setTimeout(async () => {
    await checkSensorLuz();
    await checkSensoresLentos();
  }, 3000);

  setInterval(() => checkSensorLuz(), POLL_ALARMA_MS);
  setInterval(() => checkSensoresLentos(), POLL_NORMAL_MS);
});
