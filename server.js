const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// --- 1. CONEXIÓN A MONGODB ---
// Usamos la variable de entorno de Railway
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("¡CONECTADO A MONGODB CON ÉXITO!"))
  .catch(err => console.error("ERROR CRÍTICO DB:", err));

// Esquema de Usuario (Mapeado a tu imagen)
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}, { collection: 'users' }));

// Esquema de Logs (Para el historial de la alarma)
const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}, { collection: 'logs' }));

// --- 2. CONFIGURACIÓN TUYA ---
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = "3800887034ab9509bc60"; 
const TUYA_HOST          = 'https://openapi.tuyaeu.com';

// --- 3. RUTAS PARA EL LOGIN Y APP ---

// Esta ruta es vital: la app la pide al cargar para validar el login
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        console.log("Usuarios enviados a la app:", users.length);
        res.json(users);
    } catch (e) {
        res.status(500).json([]);
    }
});

// Ruta para ver el historial en la app
app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(10);
        res.json(logs);
    } catch (e) {
        res.status(500).json([]);
    }
});

// --- 4. FUNCIÓN DE FIRMA TUYA (Tus parámetros originales) ---
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    
    const strToSign = [
        method.toUpperCase(),
        crypto.createHash('sha256').update(bodyStr).digest('hex'),
        '',
        urlPath
    ].join('\n');

    const signSeed = token 
        ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) 
        : (TUYA_CLIENT_ID + t + nonce + strToSign);

    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET)
        .update(signSeed)
        .digest('hex')
        .toUpperCase();

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

// --- 5. RUTA DE CONTROL CON TUS 4 BOTONES ---
app.post(['/api/control', '/alarm/command'], async (req, res) => {
    const { action, user } = req.body;
    
    // Tu mapeo original de switches
    const mapping = { 
        'disarm':   'switch_1',
        'arm_home':  'switch_2',
        'arm_away': 'switch_3',
        'sos':      'switch_4'
    };
    const code = mapping[action] || 'switch_1';

    try {
        // Obtener token
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const token = tokenData.result.access_token;

        // Enviar comando a la alarma
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        if(result.success) {
            // Guardamos el log en MongoDB
            await new Log({ 
                usuario: user || 'admin', 
                accion: action 
            }).save();
        }
        res.json({ success: result.success });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Arrancar servidor
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor activo en puerto ${PORT}`);
});
