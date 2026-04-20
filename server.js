const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Configuración desde tus variables de Railway
const conf = {
    clientId: process.env.TUYA_CLIENT_ID,
    secret: process.env.TUYA_CLIENT_SECRET,
    region: 'https://openapi.tuyaeu.com' // Europa
};

async function getTuyaToken() {
    const timestamp = Date.now().toString();
    const sign = crypto.createHmac('sha256', conf.secret).update(conf.clientId + timestamp).digest('hex').toUpperCase();
    const res = await axios.get(`${conf.region}/v1.0/token?grant_type=1`, {
        headers: { t: timestamp, sign_method: 'HMAC-SHA256', client_id: conf.clientId, sign }
    });
    return res.data.result.access_token;
}

app.post('/api/control', async (req, res) => {
    const { action, deviceId } = req.body;
    let dpsNum = action === 'arm' ? 3 : (action === 'partial' ? 2 : 1);
    if (action === 'sos') dpsNum = 4;

    try {
        const token = await getTuyaToken();
        const timestamp = Date.now().toString();
        const method = 'POST';
        const url = `/v1.0/devices/${deviceId}/commands`;
        const body = JSON.stringify({"commands":[{"code": `switch_${dpsNum}`, "value": true}]});
        const contentHash = crypto.createHash('sha256').update(body).digest('hex');
        const stringToSign = [method, contentHash, "", url].join('\n');
        const sign = crypto.createHmac('sha256', conf.secret).update(conf.clientId + token + timestamp + stringToSign).digest('hex').toUpperCase();

        await axios.post(conf.region + url, body, {
            headers: { t: timestamp, sign, client_id: conf.clientId, access_token: token, 'Content-Type': 'application/json' }
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/health', (req, res) => res.send('Servidor vivo'));
app.listen(process.env.PORT || 8080);
