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
const MONGO_URI = process.env.MONGO_URL || process.env.MONGODB_URI;
const TUYA_CLIENT_ID = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_KEY; 
const TUYA_REGION = process.env.TUYA_REGION || 'eu';

// --- 2. CONEXIÓN A MONGODB ---
mongoose.connect(MONGO_URI)
.then(() => console.log("¡Conectado con éxito a MongoDB Railway!"))
.catch(err => console.error("Error de conexión a MongoDB:", err));

// --- 3. ESQUEMAS Y MODELOS ---
const userSchema = new mongoose.Schema({
    name: String,
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    pin: String,
    role: { type: String, default: 'user' }
}, { collection: 'users', timestamps: true });

const logSchema = new mongoose.Schema({
    usuario: String,
    accion: String,
    fecha: { type: Date, default: Date.now }
}, { collection: 'logs' });

const configSchema = new mongoose.Schema({
    id: { type: String, default: 'global_config', unique: true },
    backendUrl: String,
    deviceId: String
    alarmStatus: { type: String, default: 'disarmed' }
}, { collection: 'configs' });

const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);
const Config = mongoose.model('Config', configSchema);

// --- 4. RUTAS DE USUARIOS (CRUD) ---

// LISTAR: Obtiene todos los usuarios
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (e) {
        res.status(500).json([]);
    }
});

// CREAR: Guarda nuevo usuario
app.post('/api/usuarios', async (req, res) => {
    try {
        const { name, username, password, pin, role } = req.body; 
        const salt = await bcrypt.genSalt(10);
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
        console.error("Error al crear usuario:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// ELIMINAR: Borra un usuario
app.delete('/api/usuarios/:username', async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') {
            return res.status(403).json({ success: false, message: 'No se puede eliminar al admin principal' });
        }
        await User.findOneAndDelete({ username });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- 5. AUTENTICACIÓN ---

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

// CAMBIAR CONTRASEÑA
app.post('/api/change-password', async (req, res) => {
    try {
        const { username, currentPassword, newPassword } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) return res.json({ success: false, message: 'Contraseña actual incorrecta' });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();

        res.json({ success: true, message: 'Contraseña actualizada correctamente' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// --- 6. CONTROL DE ALARMA (TUYA SMART) ---

async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();

    const headers = { 
        'client_id': TUYA_CLIENT_ID, 'sign': signature, 't': t, 'nonce': nonce, 
        'sign_method': 'HMAC-SHA256', 'Content-Type': 'application/json' 
    };
    if (token) headers['access_token'] = token;

    const baseUrl = `https://openapi.tuya${TUYA_REGION}.com`;
    const response = await fetch(baseUrl + urlPath, { method, headers, body: bodyStr || undefined });
    return response.json();
}

app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    const mapping = { 'disarm': 'switch_1', 'arm_home': 'switch_2', 'arm_away': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action];

    try {
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        if (!tokenData.success) throw new Error("Error obteniendo token de Tuya");

        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, tokenData.result.access_token);

        if(result.success) {
            await new Log({ usuario: user || 'Sistema', accion: action }).save();
        }
        res.json({ success: result.success, result: result.result });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- 7. HISTORIAL Y CONFIGURACIÓN GLOBAL ---

app.get('/api/historial', async (req, res) => {
    try {
        const logs = await Log.find().sort({ fecha: -1 }).limit(20);
        res.json(logs);
    } catch (e) {
        res.status(500).json([]);
    }
});

// Ruta para obtener la configuración
app.get('/api/config', async (req, res) => {
    try {
        const config = await Config.findOne({ id: 'global_config' });
        res.json(config || { backendUrl: '', deviceId: '' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Ruta para guardar/actualizar la configuración
app.post('/api/config', async (req, res) => {
    try {
        const { backendUrl, deviceId } = req.body;
        await Config.findOneAndUpdate(
            { id: 'global_config' },
            { backendUrl, deviceId },
            { upsert: true, new: true }
        );
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Ejemplo de lógica en el servidor al recibir /api/control
app.post('/api/control', async (req, res) => {
  const { action, alarmStatus, deviceId } = req.body;
  
  // A. Aquí envías el comando real a TUYA
  // B. Aquí guardas el estado en MongoDB (Colección 'status' o similar)
  await db.collection('status').updateOne(
    { deviceId: deviceId }, 
    { $set: { alarmStatus: alarmStatus, updatedAt: new Date() } },
    { upsert: true }
  );
  
  res.sendStatus(200);
});

// Ruta para controlar la alarma y guardar el estado en MongoDB
app.post('/api/control', async (req, res) => {
    try {
        const { action, alarmStatus } = req.body;

        // 1. Aquí iría tu lógica actual que conecta con Tuya...
        
        // 2. GUARDAR EN MONGODB (La clave de la sincronización)
        // Usamos la misma lógica de tu 'global_config' pero para el estado
        await Config.findOneAndUpdate(
            { id: 'global_config' }, 
            { alarmStatus: alarmStatus }, // Guardamos el nuevo estado (armed/disarmed)
            { upsert: true }
        );

        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Ruta para que el móvil pregunte: ¿Cómo está la alarma?
app.get('/api/status', async (req, res) => {
    try {
        const config = await Config.findOne({ id: 'global_config' });
        res.json({ alarmStatus: config ? config.alarmStatus : 'disarmed' });
    } catch (e) {
        res.status(500).send(e.message);
    }
});

// --- 8. INICIO DEL SERVIDOR ---
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Servidor activo en el puerto ${PORT}`);
});
