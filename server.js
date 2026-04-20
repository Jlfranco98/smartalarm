const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN A MONGODB (Usando tu variable de Railway)
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error DB:", err));

// 2. MODELO DE USUARIO (Forzamos la tabla 'users' que ya tienes)
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

// 3. ESTA RUTA ES LA QUE TE DEJARÁ ENTRAR
// Cuando abras la app, ella pedirá los usuarios aquí y ya los tendrá listos
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

// 4. CONTROL DE LA ALARMA (Con tu dispositivo y mapeo)
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (process.env.TUYA_CLIENT_ID + token + t + nonce + strToSign) : (process.env.TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', process.env.TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();
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
