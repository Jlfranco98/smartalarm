const express = require('express');
const TuyaDevice = require('tuyapi');
const path = require('path');
const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Ruta para armar/desarmar que usará tu móvil
app.post('/control', async (req, res) => {
    const { action } = req.body; // Ejemplo: 'arm', 'disarm'
    
    const device = new TuyaDevice({
        id: req.headers['device-id'],
        key: process.env.TUYA_CLIENT_SECRET, // O la Local Key si la tienes
        ip: req.headers['device-ip'] 
    });

    try {
        await device.find();
        await device.connect();
        // Aquí se envía el comando según la acción
        // El valor 1 suele ser armar, 0 desarmar (depende del modelo)
        await device.set({set: action === 'arm' ? true : false}); 
        device.disconnect();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => console.log(`Server listo en puerto ${port}`));
