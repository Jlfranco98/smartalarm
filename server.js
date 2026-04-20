const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN A MONGO
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("¡CONECTADO A MONGODB!"))
  .catch(err => console.error("ERROR DE CONEXIÓN:", err));

// Esquemas para que el servidor sepa leer tus tablas de la imagen
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  password: { type: String },
  name: String,
  pin: String
}, { collection: 'users' }));

const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}, { collection: 'logs' }));

// 2. RUTAS PARA QUE LA APP RECIBA LOS DATOS (Sin esto el login falla)
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        console.log("Usuarios en DB encontrados:", users.length);
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(10);
        res.json(logs);
    } catch (e) { res.status(500).json([]); }
});

// 3. LÓGICA TUYA Y MAPEOS ( switch_1 al switch_4 )
const TUYA_CLIENT_ID = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID = "3800887034ab9509bc60";

async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();

    const headers = { 'client_id': TUYA_CLIENT_ID, 'sign': signature, 't': t, 'nonce': nonce, 'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json' };
    if (token) headers['access_token'] = token;
    const res = await fetch('https://openapi.tuyaeu.com' + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    // MAPEADO COMPLETO REVISADO
    const mapping = { 'disarm':'switch_1', 'arm_home':'switch_2', 'arm_away':'switch_3', 'sos':'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, tokenData.result.access_token);

        if(result.success) {
            // Esto creará el LOG dentro de la carpeta logs
            await new Log({ usuario: user || 'Sistema', accion: action }).save();
        }
        res.json({ success: result.success });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
