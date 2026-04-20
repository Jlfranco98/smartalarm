const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Servir archivos estáticos (esto hará que se vea tu index.html)
app.use(express.static(path.join(__dirname, '.')));

// --- Configuración desde variables de entorno ---
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID;
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET;
const TUYA_DEVICE_ID     = "3800887034ab9509bc60"; 
const TUYA_HOST          = 'https://openapi.tuyaeu.com';
const PORT               = process.env.PORT || 8080;

// --- Ruta Raíz: Carga tu aplicación de botones ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Ruta de salud para Railway
app.get('/health', (req, res) => res.json({ status: "OK" }));

// --- Lógica de Firma Tuya V2 (Alta Seguridad) ---
function sign(clientId, secret, t, nonce, method, urlPath, body = '') {
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    const strToSign = [method.toUpperCase(), bodyHash, '', urlPath].join('\n');
    const signSeed = clientId + (nonce ? '' : '') + t + (nonce || '') + strToSign; 
    // Nota: Si usas access_token, se añade entre clientId y t
    return crypto.createHmac('sha256', secret).update(signSeed).digest('hex').toUpperCase();
}

async function tuyaRequest(method, urlPath, body = null, token = "") {
    const t = Date.now().toString();
    const nonce = crypto.randomUUID();
    const bodyStr = body ? JSON.stringify(body) : '';
    
    // Generar firma específica
    const strToSign = [method.toUpperCase(), crypto.createHash('sha256').update(bodyStr).digest('hex'), '', urlPath].join('\n');
    const signSeed = token ? (TUYA_CLIENT_ID + token + t + nonce + strToSign) : (TUYA_CLIENT_ID + t + nonce + strToSign);
    const signature = crypto.createHmac('sha256', TUYA_CLIENT_SECRET).update(signSeed).digest('hex').toUpperCase();

    const headers = {
        'client_id': TUYA_CLIENT_ID,
        'sign': signature,
        't': t,
        'nonce': nonce,
        'sign_method': 'HMAC-SHA256',
        'Content-Type': 'application/json',
    };
    if (token) headers['access_token'] = token;

    const res = await fetch(TUYA_HOST + urlPath, { method, headers, body: bodyStr || undefined });
    return res.json();
}

// --- Ruta de Control de la Alarma ---
app.post(['/api/control', '/alarm/command'], async (req, res) => {
    const { action } = req.body;
    
    // Mapeo: 1:Desarmar, 2:Parcial, 3:Total, 4:SOS
    const mapping = { 
    'disarm':   'switch_1', // Canal 1 -> Desarmar
    'arm_home':  'switch_2', // Canal 2 -> En casa 
    'arm_away': 'switch_3', // Canal 3 -> Armado TOTAL
    'sos':      'switch_4'  // Canal 4 -> Botón de Pánico / SOS
    };
    const code = mapping[action] || 'switch_1';

    try {
        // 1. Obtener Token
        const tokenData = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
        const token = tokenData.result.access_token;

        // 2. Enviar Comando
        const result = await tuyaRequest('POST', `/v1.0/devices/${TUYA_DEVICE_ID}/commands`, {
            commands: [{ code: code, value: true }]
        }, token);

        res.json({ success: result.success });
    } catch (e) {
        console.error("Error Tuya:", e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor de Alarma corriendo en puerto ${PORT}`);
});
