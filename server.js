const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// 1. CONEXIÓN
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error DB:", err));

// 2. MODELOS (Mapeados a tus capturas)
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

// 3. LA RUTA QUE TE FALTA (Para que la app vea a 'admin')
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        // Esto imprimirá en los logs de Railway si el servidor ve al admin
        console.log("Usuarios detectados en DB:", users.map(u => u.username));
        res.json(users);
    } catch (e) {
        res.status(500).json([]);
    }
});

// 4. CONTROL TUYA (CON TUS 4 SWITCHES)
app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    const mapping = { 'disarm':'switch_1', 'arm_home':'switch_2', 'arm_away':'switch_3', 'sos':'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        // ... (Lógica de token y envío de comando que ya tienes)
        // Guardamos el log para que la carpeta deje de estar vacía
        await new Log({ usuario: user || 'admin', accion: action }).save();
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
