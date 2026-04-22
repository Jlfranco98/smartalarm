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
    role: { type: String, default: 'user' },
    isNew: { type: Boolean, default: true }
}, { collection: 'users', timestamps: true });

const logSchema = new mongoose.Schema({
    usuario: String,
    accion: String,
    fecha: { type: Date, default: Date.now }
}, { collection: 'logs' });

const configSchema = new mongoose.Schema({
    id: { type: String, default: 'global_config', unique: true },
    backendUrl: String,
    deviceId: String,
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

// Ruta para obtener el historial de todos los usuarios
app.get('/api/logs', async (req, res) => {
    try {
        // Traemos los últimos 30 logs, ordenados por fecha descendente
        const logs = await Log.find().sort({ fecha: -1 }).limit(30);
        res.json(logs);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- 5. AUTENTICACIÓN ---

// LOGIN: Verifica credenciales
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
           res.json({ success: true, user: { name: user.name, username: user.username, role: user.role, pin: user.pin, isNew: user.isNew } });
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
        const { username, newPassword } = req.body;

        // 1. Prohibir contraseñas débiles
        const forbiddenPass = ['password', '123456', 'admin', 'qwerty', '12345'];
        if (forbiddenPass.includes(newPassword.toLowerCase())) {
            return res.json({ success: false, message: 'Contraseña demasiado común. Elige otra.' });
        }

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });

        // 2. Validar que la NUEVA no sea igual a la que ya tiene (Opcional, pero recomendado)
        const isSame = await bcrypt.compare(newPassword, user.password);
        if (isSame) {
            return res.json({ success: false, message: 'La nueva contraseña debe ser diferente a la anterior.' });
        }

        // 3. Guardar directamente la nueva contraseña
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        user.isNew = false; // Marcamos que el usuario ya configuró su seguridad
        await user.save();

        res.json({ success: true, message: 'Contraseña actualizada correctamente' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});

// CAMBIAR PIN USUARIO
app.post('/api/change-pin', async (req, res) => {
    try {
        const { username, currentPin, newPin } = req.body;

        // 1. Prohibir PINs débiles
        const forbiddenPins = ['0000', '1234', '1111', '2222', '123456'];
        if (forbiddenPins.includes(newPin)) {
            return res.json({ success: false, message: 'Este PIN no está permitido por seguridad.' });
        }

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });

        // 2. Validar PIN actual
        if (user.pin !== currentPin) {
            return res.json({ success: false, message: 'PIN actual incorrecto' });
        }

        // 3. Validar que el NUEVO no sea igual al ACTUAL
        if (newPin === currentPin) {
            return res.json({ success: false, message: 'El nuevo PIN debe ser diferente al actual.' });
        }

        user.pin = newPin;
        user.isNew = false; // También lo marcamos aquí por si acaso solo cambia el PIN
        await user.save();
        
        res.json({ success: true, message: 'PIN actualizado correctamente' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Error al cambiar PIN' });
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
    // 1. Extraemos datos
    const { action, user, alarmStatus } = req.body; 
    
    // Mapeo técnico para Tuya
    const mapping = { 'disarm': 'switch_1', 'arm_home': 'switch_2', 'arm_away': 'switch_3', 'sos': 'switch_4' };
    
    // NUEVO: Mapeo de nombres legibles para el Historial
    const nombresLegibles = {
        'disarm': 'Desarmado',
        'arm_home': 'Armado en casa',
        'arm_away': 'Armado total',
        'sos': 'Pánico / SOS'
    };

    const code = mapping[action];

    try {
        // --- Lógica de Tuya ---
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        if (!tokenData.success) throw new Error("Error obteniendo token de Tuya");

        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, tokenData.result.access_token);

        if(result.success) {
            // --- AQUÍ GUARDAMOS LOS DATOS LIMPIOS ---
            
            // A. Guardamos el Log con el NOMBRE BONITO (ej: "Desarmado")
            await new Log({ 
                usuario: user || 'Sistema', 
                accion: nombresLegibles[action] || action, // <--- Traducción aquí
                fecha: new Date() // Aseguramos que se guarde la fecha actual
            }).save();

            // B. Actualizamos el estado global para la sincronización
            await Config.findOneAndUpdate(
                { id: 'global_config' }, 
                { $set: { alarmStatus: alarmStatus } }, 
                { upsert: true }
            );
            
            console.log(`Log guardado: ${nombresLegibles[action]} por ${user}`);
        }
        
        res.json({ success: result.success, result: result.result });

    } catch (e) {
        console.error("Error en control:", e.message);
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
  const { action, alarmStatus, deviceId, user } = req.body;

  try {
    // A. Aquí envías el comando a TUYA (lo que ya tienes)
    
    // B. Aquí actualizas el estado general (lo que ya tienes)
    await db.collection('status').updateOne(
      { deviceId: deviceId },
      { $set: { alarmStatus: alarmStatus, updatedAt: new Date() } },
      { upsert: true }
    );

    // === CREAR EL REGISTRO REAL ===
    const nuevoLog = new Log({
      usuario: user || 'Usuario', // El nombre que viene del móvil
      accion: action === 'arm' ? 'Armado' : 'Desarmado',
      fecha: new Date() // <--- ESTA FECHA SE QUEDA GRABADA A FUEGO
    });
    
    await nuevoLog.save(); // Se guarda en la colección 'logs' de MongoDB
    // ======================================================

    res.sendStatus(200);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send("Error");
  }
});

// Ruta para controlar la alarma y guardar el estado en MongoDB
app.post('/api/control', async (req, res) => {
    try {
        const { action, alarmStatus } = req.body;

        // 1. Aquí va tu lógica de Tuya...
        
        // 2. GUARDAR EN MONGODB DE FORMA SEGURA
        await Config.findOneAndUpdate(
            { id: 'global_config' }, 
            { $set: { alarmStatus: alarmStatus } }, 
            { upsert: true, new: true }
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
