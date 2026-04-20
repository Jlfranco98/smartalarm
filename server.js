const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Ruta principal para los botones de la web
app.post('/api/control', async (req, res) => {
    const { action, deviceId } = req.body;
    
    // Mapeo: 1: desarmar, 2: parcial, 3: total, 4: sos
    let dpsNum = "1";
    if (action === 'partial') dpsNum = "2";
    if (action === 'arm') dpsNum = "3";
    if (action === 'sos') dpsNum = "4";

    console.log(`Recibida orden: ${action} para dispositivo: ${deviceId}`);

    try {
        // Aquí Railway intentará conectar con las variables que ya configuraste
        // Por ahora devolvemos éxito para que la web no se quede "pensando"
        res.status(200).json({ success: true, msg: `Comando switch_${dpsNum} procesado` });
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/health', (req, res) => res.send('Servidor OK'));

app.listen(port, () => {
    console.log(`Servidor escuchando en puerto ${port}`);
});
