const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// --- Configuración ---
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = "3800887034ab9509bc60"; 
const APP_SECRET         = process.env.APP_SECRET || 'SDRED2026';
const PORT               = process.env.PORT || 8080;

const TUYA_HOST = 'https://openapi.tuyaeu.com';

// --- RUTAS DE SALUD (Vital para Railway) ---
app.get('/', (req, res) => res.send('Servidor SmartAlarm Activo y Operativo'));
app.get('/health', (req, res) => res.json({ ok: true }));

// --- Lógica de Tuya (Firma Robusta) ---
function sign(clientId, secret, t, accessToken, method, path, body = '') {
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const strToSign = [method.toUpperCase(), bodyHash, '', path].join('\n');
    const signStr = accessToken ? (clientId + accessToken + t + strToSign) : (clientId + t + strToSign);
    return crypto.createHmac('sha256', secret).update(signStr).digest('hex').toUpperCase();
}

async function tuyaRequest(method, path, body = null) {
    const t = String(Date.now());
    const bodyStr = body ? JSON.stringify(body) : '';
    
    // Obtener token si no es la petición de token misma
    let token = '';
    if (!path.includes('/token')) {
        const tokenRes = await fetch(`${TUYA_HOST}/v1.0/token?grant_type=1`, {
            headers: {
                'client_id': TUYA_CLIENT_ID,
                'sign': sign(TUYA_CLIENT_ID, TUYA_CLIENT_SECRET, t, '', 'GET', '/v1.0/token?grant_type=1'),
                't': t,
                'sign_method': 'HMAC-SHA256'
            }
        });
        const tokenData = await tokenRes.json();
        token = tokenData.result.access_token;
    }

    const signature = sign(TUYA_CLIENT_ID, TUYA_CLIENT_SECRET, t, token, method, path, bodyStr);
    const headers = {
        'client_id': TUYA_CLIENT_ID,
        'sign': signature,
        't': t,
        'sign_method': 'HMAC-SHA256',
        'Content-Type': 'application/json',
    };
    if (token) headers['access_token'] = token;

    const res = await fetch(TUYA_HOST + path, { method, headers, body: bodyStr || undefined });
    return res.json();
}

// --- Tu ruta de Control ---
app.post('/api/control', async (req, res) => {
    const { action } = req.body;
    // Mapeo: 1:desarmar, 2:parcial, 3:total, 4:sos
    const mapping = { 'disarm': 'switch_1', 'partial': 'switch_2', 'arm': 'switch_3', 'sos': 'switch_4' };
    const code = mapping[action] || 'switch_1';

    try {
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        });
        res.json({ success: result.success });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => console.log(`Servidor activo en puerto ${PORT}`));
