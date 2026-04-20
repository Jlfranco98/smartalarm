const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // <--- ESTO ES LO QUE FALTABA Y DABA EL ERROR

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN A MONGO
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("¡CONECTADO A MONGODB!"))
  .catch(err => console.error("Error DB:", err));

// Esquema de Usuario
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}, { collection: 'users' }));

// 2. RUTA PARA CREAR USUARIOS (REGISTRO)
app.post('/api/usuarios', async (req, res) => {
    try {
        const { name, username, password, pin } = req.body;
        
        // Encriptamos la clave para que no se vea el "123"
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            username,
            password: hashedPassword,
            pin
        });

        await newUser.save();
        res.json({ success: true });
    } catch (e) {
        console.error("Error al crear:", e);
        res.status(500).json({ success: false, error: "El usuario ya existe" });
    }
});

// 3. RUTA PARA LEER USUARIOS (LOGIN)
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

// 4. LÓGICA DE TUYA (Tus 4 botones originales)
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
    const mapping = { 'disarm':'switch_1', 'arm_home':'switch_2', 'arm_away':'switch_3', 'sos':'switch_4' };
    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: mapping[action], value: true }]
        }, tokenData.result.access_token);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
