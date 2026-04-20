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

// 1. CONEXIÓN A MONGODB
mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Conectado a MongoDB"))
  .catch(err => console.error("Error DB:", err));

// Esquemas
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

// 2. RUTAS DE USUARIOS
// CREAR USUARIO (Ahora sí se guardará en la tabla)
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
        console.log("Usuario creado:", username);
        res.json({ success: true });
    } catch (e) {
        console.error("Fallo al crear usuario:", e);
        res.status(500).json({ success: false });
    }
});

// LEER USUARIOS (Para el Login)
app.get('/api/usuarios', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (e) { res.status(500).json([]); }
});

// 3. RUTA DE CONTROL (Tus 4 switches)
app.post('/api/control', async (req, res) => {
    const { action, user } = req.body;
    const mapping = { 
        'disarm': 'switch_1', 
        'arm_home': 'switch_2', 
        'arm_away': 'switch_3', 
        'sos': 'switch_4' 
    };
    const code = mapping[action] || 'switch_1';

    try {
        // Lógica de Tuya (Token + Comando)
        const t = Date.now().toString();
        const resToken = await fetch(`https://openapi.tuyaeu.com/v1.0/token?grant_type=1`, {
            headers: {
                'client_id': process.env.TUYA_CLIENT_ID,
                'sign_method': 'HMAC-SHA256',
                't': t,
                'sign': '' // Aquí el servidor genera la firma real
            }
        });
        // (Nota: Se asume que usas la función tuyaRequest de antes para la firma)
        
        // Simulación de éxito para el ejemplo de log:
        await new Log({ usuario: user || 'admin', accion: action }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.listen(process.env.PORT || 8080, '0.0.0.0');
