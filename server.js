const express  = require('express');
const crypto   = require('crypto');
const cors     = require('cors');
const path     = require('path');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const webpush  = require('web-push');
const { TuyaContext, TuyaMQTTClient } = require('@tuya/tuya-connector-nodejs');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// --- 1. VARIABLES DE ENTORNO ---
const MONGO_URI          = process.env.MONGO_URL || process.env.MONGODB_URI;
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = process.env.TUYA_DEVICE_KEY;
const TUYA_REGION        = process.env.TUYA_REGION || 'eu';
const VAPID_PUBLIC       = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE      = process.env.VAPID_PRIVATE_KEY || '';

// Mapa de región a URL base de Tuya
const REGION_URL = {
  eu: 'https://openapi.tuyaeu.com',
  us: 'https://openapi.tuyaus.com',
  cn: 'https://openapi.tuyacn.com',
  in: 'https://openapi.tuyain.com',
};
const BASE_URL = REGION_URL[TUYA_REGION] || REGION_URL['eu'];

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

// --- 4. CLIENTE TUYA (SDK oficial) ---
// Gestiona token automáticamente, no hay que pedirlo manualmente
const tuyaClient = new TuyaContext({
  baseUrl: BASE_URL,
  accessKey: TUYA_CLIENT_ID,
  secretKey: TUYA_CLIENT_SECRET,
});

// Wrapper simple para llamadas a la API
async function tuyaAPI(method, path, body) {
  const result = await tuyaClient.request({ method, path, body });
  return result;
}

// --- 5. SENSORES Y ESTADO ---
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

// --- 6. TUYA MESSAGE QUEUE (SDK oficial - recibe eventos sin polling) ---
function conectarMensajeria() {
  console.log('📡 Conectando al Message Queue de Tuya...');

  const mqttClient = new TuyaMQTTClient({
    accessKey: TUYA_CLIENT_ID,
    secretKey: TUYA_CLIENT_SECRET,
    mqttConfig: {
      // URL del broker según región
      url: `mqtts://m1.tuya${TUYA_REGION}.com:8883`,
    },
    linkListener: {
      // Se llama cuando llega un mensaje de cualquier dispositivo
      onMessage: async (topic, message) => {
        try {
          console.log('📨 Mensaje Tuya recibido:', JSON.stringify(message).substring(0, 200));
          const { bizCode, devId, bizData } = message;
          if (!devId) return;

          // Actualizar caché
          deviceStateCache[devId] = { ...deviceStateCache[devId], updatedAt: Date.now() };

          switch (bizCode) {
            case 'online':
              await procesarOnline(devId);
              break;
            case 'offline':
              await procesarOffline(devId);
              break;
            case 'statusReport':
            case 'devicePropertyMessage':
            case 'deviceEventMessage': {
              const props = bizData?.properties || bizData?.status || [];
              await procesarCambioEstado(devId, props);
              break;
            }
          }
        } catch (e) {
          console.error('Error procesando mensaje:', e.message);
        }
      },
      onConnect: () => console.log('✅ Message Queue conectado — eventos en tiempo real activos'),
      onError: (e) => console.error('❌ Error Message Queue:', e.message || e),
      onClose: () => console.log('⚠️ Message Queue desconectado, reconectando...'),
    }
  });

  mqttClient.start();
  return mqttClient;
}

async function procesarOnline(devId) {
  deviceStateCache[devId] = { ...deviceStateCache[devId], online: true };
  if (devId === SENSOR_LUZ_ID && sensorOffline) {
    sensorOffline = false;
    await new Log({ usuario: 'Verisure', accion: '✅ Centralita reconectada' }).save();
    await sendPushNotification('sensor_online', 'Verisure');
  } else if (devId === TUYA_DEVICE_ID && dispositivosOffline['panel']) {
    dispositivosOffline['panel'] = false;
    await new Log({ usuario: 'Verisure', accion: '✅ Panel Alarma reconectado' }).save();
    await sendPushNotification('panel_online', 'Verisure');
  } else {
    const sensor = SENSORES_AGUA.find(s => s.id === devId);
    if (sensor && dispositivosOffline[devId]) {
      dispositivosOffline[devId] = false;
      await new Log({ usuario: 'Verisure', accion: `✅ Sensor Agua ${sensor.nombre} reconectado` }).save();
      await sendPushNotification('dispositivo_online_' + devId, 'Verisure');
    }
  }
}

async function procesarOffline(devId) {
  deviceStateCache[devId] = { ...deviceStateCache[devId], online: false };
  if (devId === SENSOR_LUZ_ID && !sensorOffline) {
    sensorOffline = true;
    await new Log({ usuario: 'Verisure', accion: '⚠️ Centralita desconectada' }).save();
    await sendPushNotification('sensor_offline', 'Verisure');
  } else if (devId === TUYA_DEVICE_ID && !dispositivosOffline['panel']) {
    dispositivosOffline['panel'] = true;
    await new Log({ usuario: 'Verisure', accion: '⚠️ Panel Alarma desconectado' }).save();
    await sendPushNotification('panel_offline', 'Verisure');
  } else {
    const sensor = SENSORES_AGUA.find(s => s.id === devId);
    if (sensor && !dispositivosOffline[devId]) {
      dispositivosOffline[devId] = true;
      await new Log({ usuario: 'Verisure', accion: `⚠️ Sensor Agua ${sensor.nombre} desconectado` }).save();
      await sendPushNotification('dispositivo_offline_' + devId, 'Verisure');
    }
  }
}

async function procesarCambioEstado(devId, props) {
  if (!props?.length) return;

  if (devId === SENSOR_LUZ_ID) {
    const brightProp = props.find(p => p.code === 'bright_value');
    if (brightProp) {
      const lux = brightProp.value;
      console.log(`💡 Centralita: ${lux} LUX`);
      if (lux > LUX_UMBRAL && !sensorAlarmaActiva) {
        sensorAlarmaActiva = true;
        await new Log({ usuario: 'Verisure', accion: '🚨 Alarma saltada' }).save();
        await sendPushNotification('sensor_luz', 'Verisure');
      } else if (lux <= LUX_UMBRAL && sensorAlarmaActiva) {
        sensorAlarmaActiva = false;
      }
    }
  }

  const sensor = SENSORES_AGUA.find(s => s.id === devId);
  if (sensor) {
    const stateProp = props.find(p => p.code === 'watersensor_state');
    if (stateProp) {
      const estado = stateProp.value;
      console.log(`💧 Sensor agua ${sensor.nombre}: ${estado}`);
      if (estado === 'alarm' && !aguaActiva[devId]) {
        aguaActiva[devId] = true;
        await new Log({ usuario: 'Verisure', accion: `💧 Fuga de agua detectada — ${sensor.nombre}` }).save();
        await sendPushNotification('sensor_agua_' + devId, `Sensor ${sensor.nombre}`);
      } else if (estado === 'normal' && aguaActiva[devId]) {
        aguaActiva[devId] = false;
      }
    }
  }
}

// --- 7. PUSH NOTIFICATIONS ---
async function sendPushNotification(action, triggeredBy) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  const notificarATodos = ['sos','sensor_luz','sensor_offline','sensor_online','panel_offline','panel_online'].includes(action)
    || action.startsWith('sensor_agua_') || action.startsWith('dispositivo_offline_') || action.startsWith('dispositivo_online_');
  const prefs = notificarATodos ? await NotifPref.find({}) : await NotifPref.find({ [action]: true });
  if (!prefs.length) return;
  const subs = await PushSub.find({ username: { $in: prefs.map(p => p.username) } });
  if (!subs.length) return;
  const labels = {
    arm_away: '🔒 Alarma armada (total)', arm_home: '🌙 Alarma armada (modo noche)',
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

// --- 8. USUARIOS ---
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

// --- 9. AUTH ---
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

// --- 10. PUSH ---
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

// --- 11. CONTROL ALARMA ---
app.post('/api/control', async (req, res) => {
  const { action, user, alarmStatus } = req.body;
  const mapping = { disarm: 'switch_1', arm_home: 'switch_2', arm_away: 'switch_3', sos: 'switch_4' };
  const nombres = { disarm: 'Alarma Desarmada', arm_home: 'Alarma armada (modo noche)', arm_away: 'Alarma armada (total)', sos: 'PÁNICO / SOS' };
  try {
    const deviceInfo = await tuyaAPI('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`);
    if (!deviceInfo.result?.online) return res.json({ success: false, error: 'Panel desconectado.' });

    const result = await tuyaAPI('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
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

// --- 12. HISTORIAL Y CONFIG ---
app.get('/api/logs',      async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(30)); } catch (e) { res.status(500).json([]); } });
app.get('/api/historial', async (req, res) => { try { res.json(await Log.find().sort({ fecha: -1 }).limit(20)); } catch (e) { res.status(500).json([]); } });
app.get('/api/config',    async (req, res) => { try { res.json(await Config.findOne({ id: 'global_config' }) || {}); } catch (e) { res.status(500).json({}); } });
app.post('/api/config',   async (req, res) => { try { await Config.findOneAndUpdate({ id: 'global_config' }, req.body, { upsert: true }); res.json({ success: true }); } catch (e) { res.status(500).json({ success: false }); } });
app.get('/api/status',    async (req, res) => { try { const c = await Config.findOne({ id: 'global_config' }); res.json({ alarmStatus: c?.alarmStatus || 'disarmed' }); } catch (e) { res.status(500).send(e.message); } });

// --- 13. DISPOSITIVOS ---
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
    const UNA_HORA = 60 * 60 * 1000;
    const todosEnCache = LISTA_DISPOSITIVOS.every(d =>
      deviceStateCache[d.id] && (ahora - deviceStateCache[d.id].updatedAt) < UNA_HORA
    );

    if (todosEnCache) {
      return res.json(LISTA_DISPOSITIVOS.map(d => ({
        ...d,
        online:  deviceStateCache[d.id]?.online ?? false,
        bateria: deviceStateCache[d.id]?.bateria ?? null,
      })));
    }

    // Primera carga: consulta Tuya una vez
    console.log('🌐 Primera carga dispositivos desde Tuya API');
    const results = await Promise.all(LISTA_DISPOSITIVOS.map(async d => {
      try {
        const data = await tuyaAPI('GET', `/v1.0/devices/${d.id}`);
        const bateria = data.result?.status?.find(s => s.code === 'battery_percentage')?.value ?? null;
        const online  = data.result?.online || false;
        deviceStateCache[d.id] = { online, bateria, updatedAt: ahora };
        return { ...d, online, bateria };
      } catch (e) {
        return { ...d, online: false, bateria: null };
      }
    }));
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- 14. ARRANQUE ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 Servidor activo en puerto ${PORT}`);
  setTimeout(() => conectarMensajeria(), 3000);
});
