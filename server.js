const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, '.')));

// --- 1. CONEXIÓN A MONGODB ---
// Usamos la variable MONGO_URL que ya tienes configurada en Railway
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB correctamente"))
  .catch(err => console.error("Error al conectar a MongoDB:", err));

// Esquemas de la Base de Datos
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}, { collection: 'users' })); // Forzamos el nombre de la tabla que creaste

const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}));

// --- 2. CONFIGURACIÓN TUYA ---
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = "3800887034ab9509bc60"; 
const TUYA_HOST          = 'https://openapi.tuyaeu.com';
const PORT               = process.env.PORT || 8080;

// --- 3. RUTAS DE LA API PARA EL INDEX.HTML ---

// Obtener usuarios para el Login
app.get('/api/usuarios', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (e) {
    res.status(500).json([]);
  }
});

// Guardar historial
app.get('/api/historial', async (req, res) => {
  try {
    const logs = await Log.find().sort({ fecha: -1 }).limit(10);
    res.json(logs);
  } catch (e) {
    res.status(500).json([]);
  }
});

// Crear nuevos usuarios desde la App
app.post('/api/usuarios', async (req, res) => {
  try {
    const newUser = new User(req.body);
    await newUser.save();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// --- 4. CONTROL DE LA ALARMA Y MAPEADO ---
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();
    
    const headers = {
        'client_id': TUYA_CLIENT_ID,
        'sign': signature,
        't': t,
        'nonce': nonce,
        'sign_method': 'HMAC-SHA256',
        'Content-Type': 'application/json',
    };
    if (token) headers['access_token'] = token;

    const res = await fetch(TUYA_HOST + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    
    // --- AQUÍ ESTÁ EL MAPEADO DE TUS BOTONES ---
    const mapping = { 
      'disarm':   'switch_1', // Canal 1 -> Desarmar
      'arm_home':  'switch_2', // Canal 2 -> En casa 
      'arm_away': 'switch_3', // Canal 3 -> Armado TOTAL
      'sos':      'switch_4'  // Canal 4 -> SOS
    };
    const code = mapping[action] || 'switch_1';

    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const token = tokenData.result.access_token;

        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        if (result.success) {
            // Guardar en el historial de la base de datos
            await new Log({ usuario: user, accion: action }).save();
        }

        res.json({ success: result.success });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor de Alarma funcionando en puerto ${PORT}`);
});
