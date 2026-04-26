const express  = require('express');
const cors     = require('cors');
const path     = require('path');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const webpush  = require('web-push');
const { TuyaContext } = require('@tuya/tuya-connector-nodejs');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// --- 1. VARIABLES DE ENTORNO ---
const MONGO_URI          = process.env.MONGO_URL || process.env.MONGODB_URI;
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;       // Cuenta B: agua + panel
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;   // Cuenta B
const TUYA_DEVICE_ID     = process.env.TUYA_DEVICE_KEY;      // Panel alarma
const TUYA_REGION        = process.env.TUYA_REGION || 'eu';
const VAPID_PUBLIC       = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE      = process.env.VAPID_PRIVATE_KEY || '';

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
const POLL_NORMAL_MS = 10 * 60 * 1000;  // 8 min (CUENTA B - Equilibrio agua + panel)

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
  isNew: { type: Boolean, default: true }
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

const notifPrefSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  arm_away: { type: Boolean, default: true },
  arm_home: { type: Boolean, default: true },
  disarm:   { type: Boolean, default: true }
}, { collection: 'notif_prefs' });

const User      = mongoose.model('User',      userSchema);
const Log       = mongoose.model('Log',       logSchema);
const Config    = mongoose.model('Config',    configSchema);
const PushSub   = mongoose.model('PushSub',   pushSubSchema);
const NotifPref = mongoose.model('NotifPref', notifPrefSchema);

// --- 4. DOS CLIENTES TUYA ---

// Cliente A: sensor de luz (cuenta exclusiva para la alarma)
const tuyaClientAlarma = new TuyaContext({
  baseUrl: BASE_URL,
  accessKey: TUYA_CLIENT_ID_ALARMA,
  secretKey: TUYA_CLIENT_SECRET_ALARMA,
});

// Cliente B: agua + panel (cuenta principal)
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
const SENSOR_LUZ_ID = 'bfc5d2d1da002201c6pcbl';
const SENSORES_AGUA = [
  { id: 'bfcbcf5e1f2b903dedyx4i', nombre: 'Jose' },
  { id: 'bf92df2609b5192252oyym', nombre: 'Cocina' },
  { id: 'bff7dcc64693fab3acucza', nombre: 'Pasillo' },
];
const LUX_UMBRAL = 2;
let sensorAlarmaActiva = false;
let sensorOffline = false;
const aguaActiva = {};
const dispositivosOffline = {};
const deviceStateCache = {};

// --- 6. POLLING RÁPIDO: SENSOR DE LUZ (CUENTA A)
async function checkSensorLuz() {
  try {
    const data = await tuyaAlarma('GET', `/v1.0/devices/${SENSOR_LUZ_ID}`);
    const isOnline = data.result?.online === true;
    deviceStateCache[SENSOR_LUZ_ID] = { ...deviceStateCache[SENSOR_LUZ_ID], online: isOnline, updatedAt: Date.now() };

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
    if (!isOnline) return;

    const statusData = await tuyaAlarma('GET', `/v1.0/devices/${SENSOR_LUZ_ID}/status`);
    const brightProp = statusData.result?.find(p => p.code === 'bright_value');
    if (!brightProp) return;

    const lux = brightProp.value;
    console.log(`💡 Comprobando Centralita: ${lux} LUX`);

    if (lux > LUX_UMBRAL && !sensorAlarmaActiva) {
      sensorAlarmaActiva = true;
      console.log('🚨 ALARMA DETECTADA');
      await new Log({ usuario: 'Verisure', accion: '🚨 Alarma saltada' }).save();
      await sendPushNotification('sensor_luz', 'Verisure');
    } else if (lux <= LUX_UMBRAL && sensorAlarmaActiva) {
      sensorAlarmaActiva = false;
      console.log('✅ Alarma resetada');
    }
  } catch (e) {
    console.error('❌ Error sensor luz:', e.message);
  }
}

// --- 7. POLLING LENTO: AGUA + PANEL (CUENTA B)
async function checkSensoresLentos() {
  console.log(`🔄 Comprobando sensores agua + panel...`);
  await Promise.all([
    checkPanelAlarma(),
    ...SENSORES_AGUA.map(s => checkSensorAgua(s))
  ]);
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
    if (!isOnline) return;

    const statusData = await tuyaNormal('GET', `/v1.0/devices/${sensor.id}/status`);
    const stateProp = statusData.result?.find(p => p.code === 'watersensor_state');
    if (!stateProp) return;

    const estado = stateProp.value;
    if (estado === 'alarm' && !aguaActiva[sensor.id]) {
      aguaActiva[sensor.id] = true;
      await new Log({ usuario: 'Verisure', accion: `💧 Fuga de agua detectada — ${sensor.nombre}` }).save();
      await sendPushNotification('sensor_agua_' + sensor.id, `Sensor ${sensor.nombre}`);
    } else if (estado === 'normal' && aguaActiva[sensor.id]) {
      aguaActiva[sensor.id] = false;
    }
  } catch (e) { console.error(`❌ Error agua ${sensor.nombre}:`, e.message); }
}

// --- 8. PUSH NOTIFICATIONS ---
async function sendPushNotification(action, triggeredBy) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  const notificarATodos = ['sos','sensor_luz','sensor_offline','sensor_online','panel_offline','panel_online'].includes(action)
    || action.startsWith('sensor_agua_') || action.startsWith('dispositivo_offline_') || action.startsWith('dispositivo_online_');
  const prefs = notificarATodos ? await NotifPref.find({}) : await NotifPref.find({ [action]: true });
  if (!prefs.length) return;
  const subs = await PushSub.find({ username: { $in: prefs.map(p => p.username) } });
  if (!subs.length) return;
  const labels = {
    arm_away: '🔒 Alarma armada (total)', arm_home: '🌙 Modo noche activado',
    disarm: '🔓 Alarma desarmada', sos: '🆘 PÁNICO / SOS', sensor_luz: '🚨 ¡ALARMA SALTADA!',
    sensor_offline: '⚠️ Centralita desconectada', sensor_online: '✅ Centralita reconectada',
    sensor_agua_bfcbcf5e1f2b903dedyx4i: '💧 Fuga de agua — Jose',
    sensor_agua_bf92df2609b5192252oyym: '💧 Fuga de agua — Cocina',
    sensor_agua_bff7dcc64693fab3acucza: '💧 Fuga de agua — Pasillo',
    dispositivo_offline_bfcbcf5e1f2b903dedyx4i: '⚠️ Sensor Agua Jose desconectado',
    dispositivo_offline_bf92df2609b5192252oyym: '⚠️ Sensor Agua Cocina desconectado',
    dispositivo_offline_bff7dcc64693fab3acucza: '⚠️ Sensor Agua Pasillo desconectado',
    dispositivo_online_bfcbcf5e1f2b903dedyx4i: '✅ Sensor Agua Jose reconectado',
    dispositivo_online_bf92df2609b5192252oyym: '✅ Sensor Agua Cocina reconectado',
    dispositivo_online_bff7dcc64693fab3acucza: '✅ Sensor Agua Pasillo reconectado',
    panel_offline: '⚠️ Panel Alarma desconectado', panel_online: '✅ Panel Alarma reconectado',
  };
  const payload = JSON.stringify({ title: labels[action] || action, body: `Por: ${triggeredBy}`, icon: '/icon-192.png', badge: '/icon-192.png' });
  await Promise.allSettled(subs.map(async sub => {
    try { await webpush.sendNotification(sub.subscription, payload); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await PushSub.deleteOne({ _id: sub._id }); }
  }));
}

// --- 9. USUARIOS ---
app.get('/api/usuarios', async (req, res) => { try { res.json(await User.find({}, '-password')); } catch (e) { res.status(500).json([]); } });
app.post('/api/usuarios', async (req, res) => {
  try {
    const { name, username, password, pin, role } = req.body;
    await new User({ name, username, password: await bcrypt.hash(password, 10), pin, role: role || 'user' }).save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});
app.delete('/api/usuarios/:username', async (req, res) => {
  try {
    if (req.params.username === 'admin') return res.status(403).json({ success: false, message: 'No se puede eliminar al admin principal' });
    await User.findOneAndDelete({ username: req.params.username });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// --- 10. AUTH ---
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password))
      res.json({ success: true, user: { name: user.name, username: user.username, role: user.role, pin: user.pin, isNew: user.isNew } });
    else res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    const forbidden = ['password','pass','123','1234','12345','123456','admin','qwerty'];
    if (forbidden.includes(newPassword.toLowerCase())) return res.json({ success: false, message: 'Contraseña demasiado fácil.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    if (await bcrypt.compare(newPassword, user.password)) return res.json({ success: false, message: 'Debe ser diferente a la anterior.' });
    await User.updateOne({ username }, { $set: { password: await bcrypt.hash(newPassword, 10), isNew: false } });
    res.json({ success: true, message: 'Contraseña actualizada' });
  } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/api/change-pin', async (req, res) => {
  try {
    const { username, currentPin, newPin } = req.body;
    if (['0000','1234','1111','2222','123456'].includes(newPin)) return res.json({ success: false, message: 'PIN demasiado predecible.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    if (user.pin !== currentPin) return res.json({ success: false, message: 'PIN actual incorrecto' });
    if (newPin === currentPin) return res.json({ success: false, message: 'El nuevo PIN debe ser diferente.' });
    await User.updateOne({ username }, { $set: { pin: newPin, isNew: false } });
    res.json({ success: true, message: 'PIN actualizado' });
  } catch (e) { res.status(500).json({ success: false }); }
});

// --- 11. PUSH ---
app.get('/api/push/vapid-public', (req, res) => res.json({ publicKey: VAPID_PUBLIC }));
app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { username, subscription, device } = req.body;
    if (!username || !subscription) return res.status(400).json({ success: false });
    await PushSub.findOneAndUpdate({ 'subscription.endpoint': subscription.endpoint }, { username, subscription, device: device || 'unknown' }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});
app.get('/api/push/prefs/:username', async (req, res) => {
  try { res.json(await NotifPref.findOne({ username: req.params.username }) || { arm_away: true, arm_home: true, disarm: true }); }
  catch (e) { res.status(500).json({ arm_away: true, arm_home: true, disarm: true }); }
});
app.post('/api/push/prefs', async (req, res) => {
  try {
    const { username, arm_away, arm_home, disarm } = req.body;
    await NotifPref.findOneAndUpdate({ username }, { arm_away, arm_home, disarm }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// --- 12. CONTROL ALARMA (usa cuenta B, el panel está ahí) ---
app.post('/api/control', async (req, res) => {
  const { action, user, alarmStatus } = req.body;
  const mapping = { disarm: 'switch_1', arm_home: 'switch_2', arm_away: 'switch_3', sos: 'switch_4' };
  const nombres = { disarm: 'Alarma Desarmada', arm_home: 'Modo noche activado', arm_away: 'Alarma armada (total)', sos: 'PÁNICO / SOS' };
  try {
    const deviceInfo = await tuyaNormal('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`);
    if (!deviceInfo.result?.online) return res.json({ success: false, error: 'Panel desconectado.' });
    const result = await tuyaNormal('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
      commands: [{ code: mapping[action], value: true }]
    });
    if (result.success) {
      await new Log({ usuario: user || 'Verisure', accion: nombres[action] || action }).save();
      await Config.findOneAndUpdate({ id: 'global_config' }, { $set: { alarmStatus } }, { upsert: true });
      sendPushNotification(action, user || 'Verisure').catch(console.error);
    }
    res.json({ success: result.success, result: result.result });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// --- RUTA PARA MACRODROID ALARMA ---
app.get('/alerta-alarma', async (req, res) => {
  try {
    // 1. Definimos una clave secreta (pon la que tu quieras)
    const CLAVE_SECRETA = "842g980wrehg8u3gvbw43"; 
    
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

    res.status(200).send("✅ Alerta procesada");
  } catch (e) {
    console.error('❌ Error en alerta MacroDroid:', e.message);
    res.status(500).send("Error");
  }
});

app.get('/alerta-agua', async (req, res) => {
  try {
    const { token, sensor } = req.query; // sensor será "Jose", "Cocina" o "Pasillo"
    const CLAVE_SECRETA = "842g980wrehg8u3gvbw43";

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
    // Ahora 'sensor_agua_' + sensorId se convertirá en, por ejemplo, 'sensor_agua_bf92df...'
    await sendPushNotification('sensor_agua_' + sensorId, `Aviso MacroDroid: ${sensor}`);

    res.status(200).send("✅ Alerta de agua procesada");
  } catch (e) {
    console.error('❌ Error en alerta agua:', e.message);
    res.status(500).send("Error");
  }
});

// --- 13. HISTORIAL Y CONFIG ---
app.get('/api/logs',      async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(30)); } catch (e) { res.status(500).json([]); } });
app.get('/api/historial', async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(20)); } catch (e) { res.status(500).json([]); } });
app.get('/api/config',    async (req, res) => { try { res.json(await Config.findOne({ id: 'global_config' }) || {}); } catch (e) { res.status(500).json({}); } });
app.post('/api/config',   async (req, res) => { try { await Config.findOneAndUpdate({ id: 'global_config' }, req.body, { upsert: true }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.get('/api/status',    async (req, res) => { try { const c = await Config.findOne({ id: 'global_config' }); res.json({ alarmStatus: c?.alarmStatus || 'disarmed' }); } catch (e) { res.status(500).send(e.message); } });

// --- 14. DISPOSITIVOS ---
const LISTA_DISPOSITIVOS = [
  { id: 'bfc5d2d1da002201c6pcbl', nombre: 'Centralita Alarma',    icono: '🛡️', ubicacion: 'Es el corazón de tu alarma'           },
  { id: TUYA_DEVICE_ID,          nombre: 'Panel Alarma',          icono: '🛜', ubicacion: 'Es la unidad de control de tu alarma' },
  { id: 'bfcbcf5e1f2b903dedyx4i', nombre: 'Sensor Fugas de Agua', icono: '💧', ubicacion: 'Habitación Jose'                      },
  { id: 'bf92df2609b5192252oyym', nombre: 'Sensor Fugas de Agua', icono: '💧', ubicacion: 'Cocina'                               },
  { id: 'bff7dcc64693fab3acucza', nombre: 'Sensor Fugas de Agua', icono: '💧', ubicacion: 'Pasillo'                              },
];

app.get('/api/dispositivos', async (req, res) => {
  try {
    const ahora = Date.now();
    const VEINTE_MIN = 20 * 60 * 1000;
    const todosEnCache = LISTA_DISPOSITIVOS.every(d =>
      deviceStateCache[d.id] && (ahora - deviceStateCache[d.id].updatedAt) < VEINTE_MIN
    );
    if (todosEnCache) {
      return res.json(LISTA_DISPOSITIVOS.map(d => ({
        ...d, online: deviceStateCache[d.id]?.online ?? false, bateria: deviceStateCache[d.id]?.bateria ?? null,
      })));
    }
    await Promise.all([checkSensorLuz(), checkSensoresLentos()]);
    res.json(LISTA_DISPOSITIVOS.map(d => ({
      ...d, online: deviceStateCache[d.id]?.online ?? false, bateria: deviceStateCache[d.id]?.bateria ?? null,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
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
