const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// --- CONFIGURACIÓN DESDE RAILWAY ---
const config = {
    tuyaClientId: process.env.TUYA_CLIENT_ID,
    tuyaClientSecret: process.env.TUYA_CLIENT_SECRET,
    tuyaRegion: "eu", // Forzado a Europa por tu captura
    tuyaDeviceId: "3800887034ab9509bc60" // Tu ID de alarma
};

const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// --- FUNCIONES DE SEGURIDAD TUYA ---
function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function hmacSha256Upper(value, secret) {
    return crypto.createHmac("sha256", secret).update(value).digest("hex").toUpperCase();
}

async function requestTuya(opts) {
    const baseUrl = "https://openapi.tuyaeu.com";
    const bodyString = opts.body ? JSON.stringify(opts.body) : "";
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    
    const contentSha = bodyString ? sha256(bodyString) : EMPTY_BODY_SHA256;
    const stringToSign = [opts.method.toUpperCase(), contentSha, "", opts.path].join("\n");

    const signSeed = opts.accessToken
        ? `${config.tuyaClientId}${opts.accessToken}${t}${nonce}${stringToSign}`
        : `${config.tuyaClientId}${t}${nonce}${stringToSign}`;
    
    const sign = hmacSha256Upper(signSeed, config.tuyaClientSecret);

    const headers = {
        client_id: config.tuyaClientId,
        sign,
        t,
        nonce,
        sign_method: "HMAC-SHA256",
        "Content-Type": "application/json",
    };
    if (opts.accessToken) headers.access_token = opts.accessToken;

    const response = await fetch(`${baseUrl}${opts.path}`, {
        method: opts.method,
        headers,
        body: opts.method === "POST" ? bodyString : undefined,
    });

    return await response.json();
}

// --- RUTAS DEL SERVIDOR ---
app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    
    // Mapeo según tus instrucciones
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const channelCode = mapping[action] || 'switch_1';

    try {
        console.log(`Ejecutando ${action} via ${channelCode}`);
        
        // 1. Obtener Token
        const tokenRes = await requestTuya({ method: "GET", path: "/v1.0/token?grant_type=1" });
        const accessToken = tokenRes.result.access_token;

        // 2. Enviar Comando
        const result = await requestTuya({
            method: "POST",
            path: `/v1.0/devices/${config.tuyaDeviceId}/commands`,
            accessToken,
            body: { commands: [{ code: channelCode, value: true }] }
        });

        res.json({ success: result.success });
    } catch (error) {
        console.error("Error crítico:", error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/health', (req, res) => res.send('OK'));
app.listen(process.env.PORT || 8080);
