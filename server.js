const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error DB:", err));

// Esquema exacto para tu tabla 'users'
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}, { collection: 'users' }));

const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}, { collection: 'logs' }));

// Rutas API
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        console.log("Usuarios enviados a la app:", users); // Esto saldrá en tu log de Railway
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(10);
        res.json(logs);
    } catch (e) { res.status(500).json([]); }
});

// Control Tuya
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();
    const headers = { 'client_id': process.env.TUYA_CLIENT_ID, 'sign': signature, 't': t, 'nonce': nonce, 'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json' };
    if (token) headers['access_token'] = token;
    const res = await fetch('https://openapi.tuyaeu.com' + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    const mapping = { 'disarm':'switch_1', 'arm_home':'switch_2', 'arm_away':'switch_3', 'sos':'switch_4' };
    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        await tuyaRequest('POST', `/v1.0/devices/3800887034ab9509bc60/commands`, {
            commands: [{ code: mapping[action], value: true }]
        }, tokenData.result.access_token);
        await new Log({ usuario: user, accion: action }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
