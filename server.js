const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());

app.use(express.static(path.join(__dirname, '.')));

// --- Conexión a MongoDB (Usando tus variables de Railway) ---
mongoose.connect(process.env.MONGO_URL || process.env.MONGODB_URI)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error DB:", err));

// Esquemas para la Base de Datos
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}));

const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}));

// --- Configuración Tuya ---
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = "3800887034ab9509bc60"; 
const TUYA_HOST          = 'https://openapi.tuyaeu.com';
const PORT               = process.env.PORT || 8080;

// --- RUTAS DE USUARIOS Y LOGS ---
app.get('/api/usuarios', async (req, res) => {
    try { const users = await User.find(); res.json(users); } 
    catch (e) { res.status(500).json([]); }
});

app.post('/api/usuarios', async (req, res) => {
    try { await new User(req.body).save(); res.json({ success: true }); } 
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/historial', async (req, res) => {
    const logs = await Log.find().sort({ fecha: -1 }).limit(20);
    res.json(logs);
});

// --- Lógica de Firma y Peticiones Tuya ---
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();
    const headers = { 'client_id': TUYA_CLIENT_ID, 'sign': signature, 't': t, 'nonce': nonce, 'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json' };
    if (token) headers['access_token'] = token;
    const res = await fetch(TUYA_HOST + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

// --- RUTA DE CONTROL CON EL MAPEO DE BOTONES REVISADO ---
app.post(['/api/control', '/alarm/command'], async (req, res) => {
    const { action, user } = req.body;
    
    // AQUÍ ESTÁ EL MAPEADO QUE FALTABA:
    const mapping = { 
      'disarm':   'switch_1', // Botón Desarmar -> Canal 1
      'arm_home':  'switch_2', // Botón En casa -> Canal 2 
      'arm_away': 'switch_3', // Botón Armado Total -> Canal 3
      'sos':      'switch_4'  // Botón SOS -> Canal 4
    };
    
    const code = mapping[action] || 'switch_1';

    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const token = tokenData.result.access_token;
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        if(result.success) {
            // Guardamos quién hizo la acción en la base de datos
            await new Log({ usuario: user || 'Sistema', accion: action }).save();
        }
        res.json({ success: result.success });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor con Mapeo y DB activo en puerto ${PORT}`);
});
