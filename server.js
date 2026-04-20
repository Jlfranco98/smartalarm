const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const clientId = process.env.TUYA_CLIENT_ID;
const secret = process.env.TUYA_CLIENT_SECRET;
const deviceId = "3800887034ab9509bc60"; 
const baseUrl = "https://openapi.tuyaeu.com";

// ESTO ES LO QUE FALTA: Ruta raíz para que Railway no mate el proceso
app.get('/', (req, res) => res.send('Backend Online'));

function sign(t, nonce, method, path, body = '', accessToken = '') {
    const contentSha = crypto.createHash('sha256').update(body).digest('hex');
    const stringToSign = [method, contentSha, "", path].join('\n');
    const signSeed = accessToken ? (clientId + accessToken + t + nonce + stringToSign) : (clientId + t + nonce + stringToSign);
    return crypto.createHmac('sha256', secret).update(signSeed).digest('hex').toUpperCase();
}

app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        const t = Date.now().toString();
        const nonce = crypto.randomUUID();
        
        // 1. Obtener Token
        const tokenPath = "/v1.0/token?grant_type=1";
        const tokenRes = await fetch(baseUrl + tokenPath, {
            headers: { 'client_id': clientId, 'sign': sign(t, nonce, 'GET', tokenPath), 't': t, 'nonce': nonce, 'sign_method': 'HMAC-SHA256' }
        });
        const tokenData = await tokenRes.json();
        const token = tokenData.result.access_token;

        // 2. Enviar Comando
        const cmdPath = `/v1.0/devices/${deviceId}/commands`;
        const body = JSON.stringify({ commands: [{ code, value: true }] });
        const resTuya = await fetch(baseUrl + cmdPath, {
            method: 'POST',
            headers: { 'client_id': clientId, 'sign': sign(t, nonce, 'POST', cmdPath, body, token), 't': t, 'nonce': nonce, 'sign_method': 'HMAC-SHA256', 'access_token': token, 'Content-Type': 'application/json' },
            body
        });
        const finalData = await resTuya.json();
        res.json({ success: finalData.success });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`Servidor activo en puerto ${PORT}`));
