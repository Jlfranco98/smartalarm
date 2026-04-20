const express = require('express');
const TuyaDevice = require('tuyapi');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Esta es la ruta que activa los botones
app.post('/api/control', async (req, res) => {
    const { action, deviceId, localKey } = req.body;
    
    const device = new TuyaDevice({
        id: deviceId,
        key: localKey,
        issueRefreshOnConnect: true
    });

    try {
        await device.find();
        await device.connect();
        
        // El '1' suele ser el DP (Data Point) de armado en muchas alarmas
        // Esto puede variar según tu modelo
        await device.set({dps: 1, set: action === 'arm'}); 
        
        device.disconnect();
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

app.listen(process.env.PORT || 8080);
