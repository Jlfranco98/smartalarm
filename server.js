const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// 1. CONEXIÓN REFORZADA A MONGODB
// Asegúrate de que tu variable MONGO_URL en Railway termine en /nombre_de_tu_bd
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("¡AUTENTICADO EN MONGODB!"))
.catch(err => console.error("Fallo de autenticación:", err));

// Definimos el modelo explícitamente
const userSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  pin: String
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// 2. RUTA DE CREACIÓN (Con comprobación real)
app.post('/api/usuarios', async (req, res) => {
    try {
        const { name, username, password, pin } = req.body;
        
        // Verificamos si la base de datos está conectada antes de seguir
        if (mongoose.connection.readyState !== 1) {
            throw new Error("La base de datos no está lista");
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            username,
            password: hashedPassword,
            pin
        });

        // 'await' asegura que el código no siga hasta que MongoDB confirme el guardado
        const savedUser = await newUser.save();
        console.log("CONFIRMADO: Usuario guardado en la DB física:", savedUser.username);
        
        res.json({ success: true });
    } catch (e) {
        console.error("ERROR REAL AL GUARDAR:", e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

// Ruta para el login (lee de la DB)
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

// RUTA PARA HISTORIAL
app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(20);
        res.json(logs);
    } catch (e) { res.status(500).json([]); }
});

// 3. CONTROL DE ALARMA (BOTONES TUYA)
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
    const mapping = { 
        'disarm':   'switch_1',
        'arm_home': 'switch_2',
        'arm_away': 'switch_3',
        'sos':      'switch_4'
    };
    const code = mapping[action] || 'switch_1';

    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, tokenData.result.access_token);

        if(result.success) {
            await new Log({ usuario: user || 'Sistema', accion: action }).save();
        }
        res.json({ success: result.success });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
