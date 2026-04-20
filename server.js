const express = require('express');
const TuyaDevice = require('tuyapi');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

app.post('/api/control', async (req, res) => {
    const { action, deviceId } = req.body;
    
    const device = new TuyaDevice({
        id: deviceId,
        key: process.env.TUYA_DEVICE_KEY,
        issueRefreshOnConnect: true
    });

    // Mapeo de tus comandos reales
    let dpsValue = 1; // Por defecto desarmar
    if (action === 'partial') dpsValue = 2;
    if (action === 'arm') dpsValue = 3;
    if (action === 'sos') dpsValue = 4;

    try {
        console.log(`Conectando a ${deviceId} para enviar comando: ${dpsValue}`);
        await device.find();
        await device.connect();
        
        // Enviamos el estado 'true' al interruptor correspondiente
        // En muchos paneles Tuya, activar el switch X ejecuta la acción X
        await device.set({
            dps: dpsValue,
            set: true
        });

        console.log(`Comando ${dpsValue} enviado correctamente`);
        device.disconnect();
        res.json({ success: true });
    } catch (error) {
        console.error("Error de comunicación:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => res.send('Servidor vivo y escuchando'));
app.listen(process.env.PORT || 8080);
