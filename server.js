const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// --- CONFIGURACIÓN ---
const clientId = process.env.TUYA_CLIENT_ID;
const secret = process.env.TUYA_CLIENT_SECRET;
const deviceId = "3800887034ab9509bc60"; // Tu ID de alarma
const baseUrl = "https://openapi.tuyaeu.com";

const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// --- FUNCIONES DE SEGURIDAD (Tu código adaptado) ---
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
    
    const stringToSign = [method, contentSha, "", path].join("\n");
    const signSeed = accessToken 
        ? `${clientId}${accessToken}${t}${nonce}${stringToSign}`
        : `${clientId}${t}${nonce}${stringToSign}`;
    
    const sign = hmacSha256Upper(signSeed, secret);

    const headers = {
        client_id: clientId,
        sign,
        t,
        nonce,
        sign_method: "HMAC-SHA256",
        "Content-Type": "application/json",
    };
    if (accessToken) headers.access_token = accessToken;

    const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body: method === "POST" ? bodyString : undefined,
    });
    return await response.json();
}

// --- RUTA DE CONTROL ---
app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    
    // Mapeo: 1:desarmar, 2:parcial, 3:total, 4:sos
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        // 1. Obtener Token
        const tokenData = await requestTuya("GET", "/v1.0/token?grant_type=1");
        const token = tokenData.result.access_token;

        // 2. Enviar Comando
        const result = await requestTuya("POST", `/v1.0/devices/${deviceId}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        console.log(`Orden ${code} enviada. Resultado:`, result.success);
        res.json({ success: result.success });
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => res.send('Servidor OK'));
app.listen(process.env.PORT || 8080);
