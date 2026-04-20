const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Configuración desde Railway
const clientId = process.env.TUYA_CLIENT_ID;
const secret = process.env.TUYA_CLIENT_SECRET;
const deviceId = "3800887034ab9509bc60"; 
const baseUrl = "https://openapi.tuyaeu.com";
const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacSha256Upper(value, key) {
    return crypto.createHmac("sha256", key).update(value).digest("hex").toUpperCase();
}

async function requestTuya(method, path, body = null, accessToken = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyString = body ? JSON.stringify(body) : "";
    const contentSha = body ? sha256(bodyString) : EMPTY_BODY_SHA256;
    
    const stringToSign = [method, contentSha, "", path].join("\n");
    const signSeed = accessToken 
        ? clientId + accessToken + t + nonce + stringToSign
        : clientId + t + nonce + stringToSign;
    
    const sign = hmacSha256Upper(signSeed, secret);

    const headers = {
        'client_id': clientId,
        'sign': sign,
        't': t,
        'nonce': nonce,
        'sign_method': "HMAC-SHA256",
        'Content-Type': "application/json"
    };
    if (accessToken) headers['access_token'] = accessToken;

    const response = await fetch(baseUrl + path, {
        method,
        headers,
        body: method === "POST" ? bodyString : undefined
    });
    return await response.json();
}

// Ruta principal para los botones
app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        const tokenRes = await requestTuya("GET", "/v1.0/token?grant_type=1");
        const token = tokenRes.result.access_token;

        const result = await requestTuya("POST", `/v1.0/devices/${deviceId}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        res.json({ success: result.success });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/health', (req, res) => res.json({ status: "OK" }));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Servidor activo en puerto ${PORT}`));
