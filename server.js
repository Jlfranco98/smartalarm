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

// --- 1. CONFIGURACIÓN DE VARIABLES DE ENTORNO ---
// Railway inyecta estas variables automáticamente si están en el panel
const MONGO_URI = process.env.MONGO_URL || process.env.MONGODB_URI;
const TUYA_CLIENT_ID = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_KEY; // Usamos la variable que tienes en la captura
const TUYA_REGION = process.env.TUYA_REGION || 'eu'; // 'eu' según tu captura

// --- 2. CONEXIÓN A MONGODB ---
// Eliminamos dbName: 'test' porque la URL de Railway ya suele incluir los parámetros necesarios
mongoose.connect(MONGO_URI)
.then(() => console.log("¡Conectado con éxito a MongoDB Railway!"))
.catch(err => console.error("Error de conexión a MongoDB:", err));

// Esquemas de Base de Datos
const userSchema = new mongoose.Schema({
    name: String,
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    pin: String
}, { collection: 'users', timestamps: true });

const logSchema = new mongoose.Schema({
    usuario: String,
    accion: String,
    fecha: { type: Date, default: Date.now }
}, { collection: 'logs' });

const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);

// --- 3. RUTAS DE USUARIOS ---
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
        res.json({ success: true });
    } catch (e) {
        console.error("Error al crear usuario:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find({}, '-password'); // No enviamos la contraseña al frontend
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(20);
        res.json(logs);
    } catch (e) {
        res.status(500).json([]);
    }
});

// --- 4. CONTROL DE ALARMA (TUYA SMART) ---
async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    
    // Firma Tuya v2
    const strToSign = [
        method.toUpperCase(),
        crypto.createHash('sha256').update(bodyStr).digest('hex'),
        '',
        urlPath
    ].join('\n');
    
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

    const baseUrl = `https://openapi.tuya${TUYA_REGION}.com`;
    const response = await fetch(baseUrl + urlPath, { method, headers, body: bodyStr || undefined });
    return response.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    
    const mapping = { 
        'disarm':   'switch_1',
        'arm_home': 'switch_2',
        'arm_away': 'switch_3',
        'sos':      'switch_4'
    };
    const code = mapping[action];

    try {
        // 1. Obtener Token
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        if (!tokenData.success) throw new Error("Error obteniendo token de Tuya");

        // 2. Enviar Comando
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, tokenData.result.access_token);

        if(result.success) {
            await new Log({ 
                usuario: user || 'Sistema', 
                accion: action 
            }).save();
        }
        res.json({ success: result.success, result: result.result });
    } catch (e) {
        console.error("Error en control:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- RUTAS DE MONGODB ---

// LOGIN: Verifica credenciales
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            res.json({ success: true, user: { name: user.name, username: user.username, role: user.role, pin: user.pin } });
        } else {
            res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos' });
        }
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// CREAR: Guarda nuevo usuario con rol
app.post('/api/usuarios', async (req, res) => {
    try {
        const { name, username, password, pin, role } = req.body;
        const salt = await bcrypt.getSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            username,
            password: hashedPassword,
            pin,
            role: role || 'user'
        });

        await newUser.save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// LISTAR: Obtiene todos los usuarios para la tabla
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (e) {
        res.status(500).json([]);
    }
});

// --- INICIO DEL SERVIDOR (Solo una vez al final) ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Servidor activo en el puerto ${PORT}`);
});
