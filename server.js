const express = require('express');
const crypto  = require('crypto');
const cors    = require('cors');
const path    = require('path');
const mongoose = require('mongoose');
const bcrypt  = require('bcryptjs');
const webpush = require('web-push');

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

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:admin@smartalarm.app', VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('Web Push VAPID configurado');
}

// --- 2. CONEXIÓN A MONGODB ---
mongoose.connect(MONGO_URI)
  .then(() => console.log('¡Conectado con éxito a MongoDB!'))
  .catch(err => console.error('Error de conexión a MongoDB:', err));

// --- 3. ESQUEMAS Y MODELOS ---
const userSchema = new mongoose.Schema({
  name:     String,
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  pin:      String,
  role:     { type: String, default: 'user' },
  isNew:    { type: Boolean, default: true }
}, { collection: 'users', timestamps: true, suppressReservedKeysWarning: true });

const logSchema = new mongoose.Schema({
  usuario: String,
  accion:  String,
  fecha:   { type: Date, default: Date.now }
}, { collection: 'logs' });

const configSchema = new mongoose.Schema({
  id:          { type: String, default: 'global_config', unique: true },
  backendUrl:  String,
  deviceId:    String,
  alarmStatus: { type: String, default: 'disarmed' }
}, { collection: 'configs' });

// Suscripción push por dispositivo
const pushSubSchema = new mongoose.Schema({
  username:     { type: String, required: true },
  subscription: { type: Object, required: true },
  device:       { type: String, default: 'unknown' }
}, { collection: 'push_subscriptions', timestamps: true });

// Preferencias de notificación por usuario
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

// --- 4. USUARIOS (CRUD) ---

app.get('/api/usuarios', async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (e) { res.status(500).json([]); }
});

app.post('/api/usuarios', async (req, res) => {
  try {
    const { name, username, password, pin, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, await bcrypt.genSalt(10));
    await new User({ name, username, password: hashedPassword, pin, role: role || 'user' }).save();
    res.json({ success: true });
  } catch (e) {
    console.error('Error al crear usuario:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/usuarios/:username', async (req, res) => {
  try {
    const { username } = req.params;
    if (username === 'admin')
      return res.status(403).json({ success: false, message: 'No se puede eliminar al admin principal' });
    await User.findOneAndDelete({ username });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// --- 5. AUTENTICACIÓN ---

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
      res.json({ success: true, user: { name: user.name, username: user.username, role: user.role, pin: user.pin, isNew: user.isNew } });
    } else {
      res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
    }
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/change-password', async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    const forbidden = ['password', 'pass', '123', '1234', '12345', '123456', 'admin', 'qwerty'];
    if (forbidden.includes(newPassword.toLowerCase()))
      return res.json({ success: false, message: 'Contraseña demasiado fácil de adivinar.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    if (await bcrypt.compare(newPassword, user.password))
      return res.json({ success: false, message: 'La nueva contraseña debe ser diferente a la anterior.' });
    user.password = await bcrypt.hash(newPassword, await bcrypt.genSalt(10));
user.isNew = false;
// Fix para usuarios con fechas en formato legacy
if (user.createdAt && typeof user.createdAt === 'object' && user.createdAt.$date) {
  user.createdAt = new Date(user.createdAt.$date);
}
if (user.updatedAt && typeof user.updatedAt === 'object' && user.updatedAt.$date) {
  user.updatedAt = new Date(user.updatedAt.$date);
}
await User.updateOne({ username }, { $set: { password: await bcrypt.hash(newPassword, await bcrypt.genSalt(10)), isNew: false } });
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

app.post('/api/change-pin', async (req, res) => {
  try {
    const { username, currentPin, newPin } = req.body;
    const forbidden = ['0000', '1234', '1111', '2222', '123456'];
    if (forbidden.includes(newPin))
      return res.json({ success: false, message: 'PIN no permitido por ser demasiado predecible.' });
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    if (user.pin !== currentPin)
      return res.json({ success: false, message: 'PIN actual incorrecto' });
    if (newPin === currentPin)
      return res.json({ success: false, message: 'El nuevo PIN debe ser diferente al actual.' });
    
    // Usar updateOne en vez de save() para evitar problemas con fechas legacy
    await User.updateOne({ username }, { $set: { pin: newPin, isNew: false } });
    
    res.json({ success: true, message: 'PIN actualizado correctamente' });
  } catch (e) {
    console.error('Error change-pin completo:', e);
    res.status(500).json({ success: false, message: 'Error al cambiar PIN: ' + e.message });
  }
});

// --- 5b. NOTIFICACIONES PUSH ---

app.get('/api/push/vapid-public', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { username, subscription, device } = req.body;
    if (!username || !subscription) return res.status(400).json({ success: false });
    await PushSub.findOneAndUpdate(
      { 'subscription.endpoint': subscription.endpoint },
      { username, subscription, device: device || 'unknown' },
      { upsert: true, new: true }
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/push/prefs/:username', async (req, res) => {
  try {
    const prefs = await NotifPref.findOne({ username: req.params.username });
    res.json(prefs || { arm_away: true, arm_home: true, disarm: true });
  } catch (e) { res.status(500).json({ arm_away: true, arm_home: true, disarm: true }); }
});

app.post('/api/push/prefs', async (req, res) => {
  try {
    const { username, arm_away, arm_home, disarm } = req.body;
    await NotifPref.findOneAndUpdate({ username }, { arm_away, arm_home, disarm }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

async function sendPushNotification(action, triggeredBy) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) {
    console.log('Push: VAPID no configurado');
    return;
  }
  const notificarATodos = ['sos', 'sensor_luz', 'sensor_offline', 'sensor_online', 'panel_offline', 'panel_online'].includes(action) 
  || action.startsWith('sensor_agua_')
  || action.startsWith('dispositivo_offline_')
  || action.startsWith('dispositivo_online_');

const prefs = notificarATodos
  ? await NotifPref.find({})
  : await NotifPref.find({ [action]: true });
  console.log(`Push: ${prefs.length} usuarios con preferencia activa para ${action}`);
  if (!prefs.length) return;
  const usernames = prefs.map(p => p.username);
  const subs = await PushSub.find({ username: { $in: usernames } });
  console.log(`Push: ${subs.length} suscripciones encontradas para ${usernames}`);
  if (!subs.length) return;
  const labels = {
  arm_away:    '🔒 Alarma armada (total)',
  arm_home:    '🌙 Alarma armada (modo noche)',
  disarm:      '🔓 Alarma desarmada',
  sos:         '🆘 PÁNICO / SOS',
  sensor_luz:  '🚨 ¡ALARMA SALTADA!',
  sensor_offline: '⚠️ Centralita desconectada',
  sensor_online:  '✅ Centralita reconectada',
  sensor_agua_bfcbcf5e1f2b903dedyx4i: '💧 Fuga de agua — Jose',
  sensor_agua_bf92df2609b5192252oyym: '💧 Fuga de agua — Cocina',
  sensor_agua_bff7dcc64693fab3acucza: '💧 Fuga de agua — Pasillo',
  dispositivo_offline_bfcbcf5e1f2b903dedyx4i: '⚠️ Sensor Agua Jose desconectado',
  dispositivo_offline_bf92df2609b5192252oyym: '⚠️ Sensor Agua Cocina desconectado',
  dispositivo_offline_bff7dcc64693fab3acucza: '⚠️ Sensor Agua Pasillo desconectado',
  dispositivo_online_bfcbcf5e1f2b903dedyx4i: '✅ Sensor Agua Jose reconectado',
  dispositivo_online_bf92df2609b5192252oyym: '✅ Sensor Agua Cocina reconectado',
  dispositivo_online_bff7dcc64693fab3acucza: '✅ Sensor Agua Pasillo reconectado',
  panel_offline: '⚠️ Panel Alarma desconectado',
  panel_online:  '✅ Panel Alarma reconectado',
};
  const payload = JSON.stringify({
    title: labels[action] || action,
    body:  `Por el usuario: ${triggeredBy}`,
    icon:  '/icon-192.png',
    badge: '/icon-192.png'
  });
  await Promise.allSettled(subs.map(async sub => {
    try {
      await webpush.sendNotification(sub.subscription, payload);
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410)
        await PushSub.deleteOne({ _id: sub._id });
    }
  }));
}

// --- 6. CONTROL DE ALARMA (TUYA) ---

async function tuyaRequest(method, urlPath, body = null, token = '') {
  const t = Date.now().toString();
  const nonce = crypto.randomUUID();
  const bodyStr = body ? JSON.stringify(body) : '';
  const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
  const signSeed = token
    ? (TUYA_CLIENT_ID + token + t + nonce + strToSign)
    : (TUYA_CLIENT_ID + t + nonce + strToSign);
  const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();
  const headers = {
    'client_id': TUYA_CLIENT_ID, 'sign': signature, 't': t, 'nonce': nonce,
    'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json'
  };
  if (token) headers['access_token'] = token;
  const baseUrl = `https://openapi.tuya${TUYA_REGION}.com`;
  const response = await fetch(baseUrl + urlPath, { method, headers, body: bodyStr || undefined });
  return response.json();
}

app.post('/api/control', async (req, res) => {
  const { action, user, alarmStatus } = req.body;
  const mapping = { disarm: 'switch_1', arm_home: 'switch_2', arm_away: 'switch_3', sos: 'switch_4' };
  const nombresLegibles = { disarm: 'Alarma Desarmada', arm_home: 'Alarma armada (modo noche)', arm_away: 'Alarma armada (total)', sos: 'PÁNICO / SOS' };
  const code = mapping[action];
  try {
    const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (!tokenData.success) throw new Error('Error obteniendo token de Tuya');

    // Verificar que el panel está online antes de enviar comando
    const deviceInfo = await tuyaRequest('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`, null, tokenData.result.access_token);
    if (!deviceInfo.result?.online) {
      return res.json({ success: false, error: 'Panel de alarma desconectado. No se puede ejecutar el comando.' });
    }

    const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
      commands: [{ code, value: true }]
    }, tokenData.result.access_token);
    if (result.success) {
      await new Log({
        usuario: user || 'Verisure',
        accion:  nombresLegibles[action] || action,
        fecha:   new Date()
      }).save();
      await Config.findOneAndUpdate(
        { id: 'global_config' },
        { $set: { alarmStatus } },
        { upsert: true }
      );
      console.log(`Log guardado: ${nombresLegibles[action]} por ${user}`);
      sendPushNotification(action, user || 'Verisure').catch(e => console.error('Push error:', e));
    }
    res.json({ success: result.success, result: result.result });
  } catch (e) {
    console.error('Error en control:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// --- 7. HISTORIAL Y CONFIGURACIÓN ---

app.get('/api/logs', async (req, res) => {
  try {
    const logs = await Log.find().sort({ fecha: -1 }).limit(30);
    res.json(logs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/historial', async (req, res) => {
  try {
    const logs = await Log.find().sort({ fecha: -1 }).limit(20);
    res.json(logs);
  } catch (e) { res.status(500).json([]); }
});

app.get('/api/config', async (req, res) => {
  try {
    const config = await Config.findOne({ id: 'global_config' });
    res.json(config || { backendUrl: '', deviceId: '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/config', async (req, res) => {
  try {
    const { backendUrl, deviceId } = req.body;
    await Config.findOneAndUpdate({ id: 'global_config' }, { backendUrl, deviceId }, { upsert: true, new: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/status', async (req, res) => {
  try {
    const config = await Config.findOne({ id: 'global_config' });
    res.json({ alarmStatus: config ? config.alarmStatus : 'disarmed' });
  } catch (e) { res.status(500).send(e.message); }
});

// --- SENSORES ---
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

async function checkTodosLosSensores() {
  try {
    const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (!tokenData.success) return;
    const token = tokenData.result.access_token;
    await Promise.all([
      checkSensorLuz(token),
      checkPanelAlarma(token),
      ...SENSORES_AGUA.map(s => checkSensorAgua(s, token))
    ]);
  } catch(e) {
    console.error('Error sensores:', e.message);
  }
}

async function checkSensorLuz(token) {
  try {
    // Primero comprobamos si está online
    const deviceData = await tuyaRequest('GET', `/v1.0/devices/${SENSOR_LUZ_ID}`, null, token);
    const isOnline = deviceData.result?.online === true;

    if (!isOnline) {
      if (!sensorOffline) {
        sensorOffline = true;
        await new Log({ usuario: 'Verisure', accion: '⚠️ Centralita desconectada', fecha: new Date() }).save();
        await sendPushNotification('sensor_offline', 'Verisure');
      }
      return;
    }

    if (sensorOffline) {
      sensorOffline = false;
      await new Log({ usuario: 'Verisure', accion: '✅ Centralita reconectada', fecha: new Date() }).save();
      await sendPushNotification('sensor_online', 'Verisure');
    }

    // Si está online, leemos el valor de luz
    const statusData = await tuyaRequest('GET', `/v1.0/devices/${SENSOR_LUZ_ID}/status`, null, token);
    const brightProp = statusData.result?.find(p => p.code === 'bright_value');
    if (!brightProp) return;

    const lux = brightProp.value;
    console.log(`✅ CENTRALITA ALARMA - ${lux} LUX`);

    if (lux > LUX_UMBRAL && !sensorAlarmaActiva) {
      sensorAlarmaActiva = true;
      console.log('⚠️ SENSOR: Luz detectada, posible intrusión');
      await new Log({ usuario: 'Verisure', accion: '🚨 Alarma saltada', fecha: new Date() }).save();
      await sendPushNotification('sensor_luz', 'Verisure');
    } else if (lux <= LUX_UMBRAL && sensorAlarmaActiva) {
      sensorAlarmaActiva = false;
    }
  } catch(e) {
    console.error('Error sensor luz:', e.message);
  }
}

async function checkPanelAlarma(token) {
  try {
    const data = await tuyaRequest('GET', `/v1.0/devices/${TUYA_DEVICE_ID}`, null, token);
    console.log('✅ PANEL ONLINE:', data.result?.online);
    
    const isOnline = data.result?.online === true;
    
    if (!isOnline) {
      if (!dispositivosOffline['panel']) {
        dispositivosOffline['panel'] = true;
        await new Log({ usuario: 'Verisure', accion: '⚠️ Panel Alarma desconectado', fecha: new Date() }).save();
        await sendPushNotification('panel_offline', 'Verisure');
      }
      return;
    }
    if (dispositivosOffline['panel']) {
      dispositivosOffline['panel'] = false;
      await new Log({ usuario: 'Verisure', accion: '✅ Panel Alarma reconectado', fecha: new Date() }).save();
      await sendPushNotification('panel_online', 'Verisure');
    }
  } catch(e) {
    console.error('Error panel alarma:', e.message);
  }
}

async function checkSensorAgua(sensor, token) {
  try {
    const data = await tuyaRequest('GET', `/v1.0/devices/${sensor.id}/status`, null, token);
    if (!data.success || !data.result) {
      console.log(`❌ Sensor agua ${sensor.nombre}: offline`);
      if (!dispositivosOffline[sensor.id]) {
        dispositivosOffline[sensor.id] = true;
        await new Log({ usuario: 'Verisure', accion: `⚠️ Sensor Agua ${sensor.nombre} desconectado`, fecha: new Date() }).save();
        await sendPushNotification('dispositivo_offline_' + sensor.id, 'Verisure');
      }
      return;
    }
    if (dispositivosOffline[sensor.id]) {
      dispositivosOffline[sensor.id] = false;
      await new Log({ usuario: 'Verisure', accion: `✅ Sensor Agua ${sensor.nombre} reconectado`, fecha: new Date() }).save();
      await sendPushNotification('dispositivo_online_' + sensor.id, 'Verisure');
    }
    const stateProp = data.result.find(p => p.code === 'watersensor_state');
    if (!stateProp) return;
    const estado = stateProp.value;
    console.log(`✅ Sensor agua ${sensor.nombre}: ${estado}`);
    if (estado === 'alarm' && !aguaActiva[sensor.id]) {
      aguaActiva[sensor.id] = true;
      console.log(`⚠️ AGUA detectada en ${sensor.nombre}`);
      await new Log({
        usuario: 'Verisure',
        accion: `💧 Fuga de agua detectada — ${sensor.nombre}`,
        fecha: new Date()
      }).save();
      await sendPushNotification('sensor_agua_' + sensor.id, `Sensor ${sensor.nombre}`);
    } else if (estado === 'normal' && aguaActiva[sensor.id]) {
      aguaActiva[sensor.id] = false;
      console.log(`✅ Sensor agua ${sensor.nombre}: vuelta a normalidad`);
    }
  } catch(e) {
    console.error(`⚠️ Error sensor agua ${sensor.nombre}:`, e.message);
  }
}

// Sensor de luz (alarma) cada 2 horas, antes cada 10 segundos
setInterval(async () => {
  try {
    const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (!tokenData.success) return;
    await checkSensorLuz(tokenData.result.access_token);
  } catch(e) { console.error('Error polling luz:', e.message); }
}, 7200000);

// Panel y sensores de agua cada 2 horas, antes cada 30 segundos
setInterval(async () => {
  try {
    const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (!tokenData.success) return;
    const token = tokenData.result.access_token;
    await Promise.all([
      checkPanelAlarma(token),
      ...SENSORES_AGUA.map(s => checkSensorAgua(s, token))
    ]);
  } catch(e) { console.error('Error polling sensores:', e.message); }
}, 7200000);

// Arranque inicial
checkTodosLosSensores();

// --- DISPOSITIVOS ---
const LISTA_DISPOSITIVOS = [
  { id: 'bfc5d2d1da002201c6pcbl', nombre: 'Centralita Alarma',          icono: '🛡️', ubicacion: 'Es el corazón de tu alarma'            },
  { id: TUYA_DEVICE_ID,           nombre: 'Panel Alarma',               icono: '🛜', ubicacion: 'Es la unidad de control de tu alarma'  },
  { id: 'bfcbcf5e1f2b903dedyx4i', nombre: 'Sensor Fugas de Agua',       icono: '💧', ubicacion: 'Habitación Jose'                       },
  { id: 'bf92df2609b5192252oyym', nombre: 'Sensor Fugas de Agua',       icono: '💧', ubicacion: 'Cocina'                                },
  { id: 'bff7dcc64693fab3acucza', nombre: 'Sensor Fugas de Agua',       icono: '💧', ubicacion: 'Pasillo'                               },
];

app.get('/api/dispositivos', async (req, res) => {
  try {
    const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (!tokenData.success) throw new Error('Token error');
    const token = tokenData.result.access_token;

    const results = await Promise.all(LISTA_DISPOSITIVOS.map(async d => {
      try {
        const data = await tuyaRequest('GET', `/v1.0/devices/${d.id}`, null, token);
        const bateria = data.result?.status?.find(s => s.code === 'battery_percentage')?.value ?? null;
        return { ...d, online: d.forzarOnline || data.result?.online || false, bateria };
      } catch(e) {
        return { ...d, online: d.forzarOnline || false, bateria: null };
      }
    }));

    res.json(results);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// --- 8. INICIO DEL SERVIDOR ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Servidor activo en el puerto ${PORT}`));
