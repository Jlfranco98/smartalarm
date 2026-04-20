const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '.')));

// Configuración desde Railway
const TUYA_CLIENT_ID = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID = "3800887034ab9509bc60"; // Tu ID de alarma
const BASE_URL = "https://openapi.tuyaeu.com";
const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Lógica de Firma de Alta Seguridad (la que te funciona)
function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacSha256Upper(value, secret) {
    return crypto.createHmac("sha256", secret).update(value).digest("hex").toUpperCase();
}

async function requestTuya(method, path, body = null, accessToken = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyString = body ? JSON.stringify(body) : "";
    const contentSha = body ? sha256(bodyString) : EMPTY_BODY_SHA256;
    
    const stringToSign = [method.toUpperCase(), contentSha, "", path].join("\n");
    const signSeed = accessToken 
        ? TUYA_CLIENT_ID + accessToken + t + nonce + stringToSign
        : TUYA_CLIENT_ID + t + nonce + stringToSign;
    
    const sign = hmacSha256Upper(signSeed, TUYA_CLIENT_SECRET);

    const headers = {
        'client_id': TUYA_CLIENT_ID,
        'sign': sign,
        't': t,
        'nonce': nonce,
        'sign_method': "HMAC-SHA256",
        'Content-Type': "application/json"
    };
    if (accessToken) headers['access_token'] = accessToken;

    const response = await fetch(BASE_URL + path, {
        method,
        headers,
        body: method === "POST" ? bodyString : undefined
    });
    return await response.json();
}

// Ruta que usan los botones de tu web
app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    // Mapeo según tus interruptores (image_4a9dfd.png)
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        const tokenData = await requestTuya("GET", "/v1.0/token?grant_type=1");
        const token = tokenData.result.access_token;

        const result = await requestTuya("POST", `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        res.json({ success: result.success });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/health', (req, res) => res.send('OK'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Servidor activo en puerto ${PORT}`));
