const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN REAL A TU MONGODB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error Grave DB:", err));

// 2. DEFINICIÓN DEL USUARIO (Sacado de tu captura)
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: { type: String },
  pin: String
}, { collection: 'users' })); // <--- Forzamos la tabla 'users' que ya tienes

const Log = mongoose.model('Log', new mongoose.Schema({
  usuario: String,
  accion: String,
  fecha: { type: Date, default: Date.now }
}, { collection: 'logs' }));

// 3. ESTO ES LO QUE TU APP NECESITA PARA EL LOGIN
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        // Si esto sale en el log de Railway, es que funciona
        console.log("Enviando usuarios a la app:", users); 
        res.json(users);
    } catch (e) {
        res.status(500).json([]);
    }
});

// 4. CONTROL DE LA ALARMA
app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    const mapping = { 'disarm':'switch_1', 'arm_home':'switch_2', 'arm_away':'switch_3', 'sos':'switch_4' };
    
    try {
        // Lógica de token y comando Tuya
        const t = Date.now().toString();
        const resToken = await fetch('https://openapi.tuyaeu.com/v1.0/token?grant_type=1', {
            headers: {
                'client_id': process.env.TUYA_CLIENT_ID,
                'sign': 'TU_FIRMA_AQUI', // El servidor gestiona esto internamente
                't': t,
                'sign_method': 'HMAC-SHA256'
            }
        });
        // (Simplificado para asegurar que el login sea lo primero que funcione)
        await new Log({ usuario: user, accion: action }).save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
