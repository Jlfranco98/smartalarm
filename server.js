const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN A MONGODB (Base de datos: test)
mongoose.connect(process.env.MONGO_URL, {
    dbName: 'test' 
})
.then(() => console.log("¡Conectado con éxito a la base de datos 'test'!"))
.catch(err => console.error("Error de conexión:", err));

// Esquemas de Base de Datos
const userSchema = new mongoose.Schema({
    name: String,
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    pin: String
}, { collection: 'users' });

const logSchema = new mongoose.Schema({
    usuario: String,
    accion: String,
    fecha: { type: Date, default: Date.now }
}, { collection: 'logs' });

const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);

// 2. RUTAS DE USUARIOS
app.post('/api/usuarios', async (req, res) => {
    try {
        const { name, username, password, pin } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            username,
            password: hashedPassword,
            pin
        });

        await newUser.save();
        console.log("Usuario guardado en 'test.users':", username);
        res.json({ success: true });
    } catch (e) {
        console.error("Error al crear usuario:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

// 3. RUTA DEL HISTORIAL (Para tu tabla de 'Últimos eventos')
app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(20);
        res.json(logs);
    } catch (e) {
        console.error("Error al leer historial:", e);
        res.status(500).json([]);
    }
});

// 4. CONTROL DE ALARMA (TUYA SMART)
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

    const headers = { 
        'client_id': TUYA_CLIENT_ID, 
        'sign': signature, 
        't': t, 
        'nonce': nonce, 
        'sign_method': 'HMAC-SHA256', 
        'Content-Type': 'application/json' 
    };
    if (token) headers['access_token'] = token;
    const res = await fetch('https://openapi.tuyaeu.com' + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    
    // MAPEADO DE BOTONES
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
            // Guardar registro en la colección 'logs' de la DB 'test'
            await new Log({ 
                usuario: user || 'Sistema', 
                accion: action 
            }).save();
        }
        res.json({ success: result.success });
    } catch (e) {
        console.error("Error en control:", e);
        res.status(500).json({ success: false });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor activo en puerto ${PORT}`);
});
