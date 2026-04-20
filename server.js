const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// ─── Config desde variables de entorno ───────────────────────────────────────
const TUYA_CLIENT_ID     = process.env.TUYA_CLIENT_ID     || '';
const TUYA_CLIENT_SECRET = process.env.TUYA_CLIENT_SECRET || '';
const TUYA_DEVICE_ID     = process.env.TUYA_DEVICE_ID     || '';
const TUYA_REGION        = process.env.TUYA_REGION        || 'eu';
const APP_SECRET         = process.env.APP_SECRET         || 'cambia_esto_en_produccion';
const PORT               = process.env.PORT               || 3000;

const TUYA_HOSTS = {
  eu: 'https://openapi.tuyaeu.com',
  us: 'https://openapi.tuyaus.com',
  cn: 'https://openapi.tuyacn.com',
  in: 'https://openapi.tuyain.com',
};

// ─── Token cache ─────────────────────────────────────────────────────────────
let tokenCache = { access_token: '', expire_at: 0 };

// ─── Firma Tuya ──────────────────────────────────────────────────────────────
function sign(clientId, secret, t, accessToken, method, path, body = '') {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const strToSign = [method.toUpperCase(), bodyHash, '', path].join('\n');
  const signStr = clientId + accessToken + t + strToSign;
  return crypto.createHmac('sha256', secret).update(signStr).digest('hex').toUpperCase();
}

async function tuyaRequest(method, path, body = null) {
  const host = TUYA_HOSTS[TUYA_REGION] || TUYA_HOSTS.eu;
  const t = String(Date.now());
  const bodyStr = body ? JSON.stringify(body) : '';
  const token = path.includes('/token') ? '' : (await getToken());
  const signature = sign(TUYA_CLIENT_ID, TUYA_CLIENT_SECRET, t, token, method, path, bodyStr);

  const headers = {
    'client_id': TUYA_CLIENT_ID,
    'sign': signature,
    't': t,
    'sign_method': 'HMAC-SHA256',
    'access_token': token,
    'Content-Type': 'application/json',
  };

  const res = await fetch(host + path, {
    method,
    headers,
    body: bodyStr || undefined,
  });

  return res.json();
}

async function getToken() {
  if (tokenCache.access_token && Date.now() < tokenCache.expire_at) {
    return tokenCache.access_token;
  }
  const data = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
  if (data.success) {
    tokenCache = {
      access_token: data.result.access_token,
      expire_at: Date.now() + (data.result.expire_time - 60) * 1000,
    };
    return tokenCache.access_token;
  }
  throw new Error('No se pudo obtener token de Tuya: ' + JSON.stringify(data));
}

// ─── Middleware de API key simple ─────────────────────────────────────────────
function requireSecret(req, res, next) {
  const key = req.headers['x-app-secret'];
  if (key !== APP_SECRET) return res.status(401).json({ ok: false, error: 'No autorizado' });
  next();
}

// ─── Rutas ────────────────────────────────────────────────────────────────────

// Health check (sin auth)
app.get('/health', (req, res) => res.json({ ok: true, region: TUYA_REGION }));

// Estado actual de la alarma
app.get('/alarm/status', requireSecret, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || TUYA_DEVICE_ID;
    const data = await tuyaRequest('GET', `/v1.0/devices/${deviceId}/status`);
    if (!data.success) return res.status(502).json({ ok: false, error: data.msg });

    // Busca el código master_state o similar
    const statusProp = data.result.find(p =>
      ['master_state', 'alarm_state', 'maser_mode'].includes(p.code)
    );
    res.json({ ok: true, raw: data.result, status: statusProp?.value || 'unknown' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Enviar comando (armar / desarmar)
app.post('/alarm/command', requireSecret, async (req, res) => {
  try {
    const { action, deviceId } = req.body;
    const target = deviceId || TUYA_DEVICE_ID;

    const commandMap = {
      arm_away: [{ code: 'master_state', value: 'arm'      }],
      arm_home: [{ code: 'master_state', value: 'home'     }],
      disarm:   [{ code: 'master_state', value: 'disarmed' }],
    };

    if (!commandMap[action]) {
      return res.status(400).json({ ok: false, error: 'Acción no válida: ' + action });
    }

    const data = await tuyaRequest('POST', `/v1.0/devices/${target}/commands`, {
      commands: commandMap[action],
    });

    if (!data.success) return res.status(502).json({ ok: false, error: data.msg });
    res.json({ ok: true, result: data.result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Info del dispositivo
app.get('/alarm/device', requireSecret, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || TUYA_DEVICE_ID;
    const data = await tuyaRequest('GET', `/v1.0/devices/${deviceId}`);
    if (!data.success) return res.status(502).json({ ok: false, error: data.msg });
    res.json({ ok: true, device: data.result });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => console.log(`Alarm backend corriendo en puerto ${PORT}`));
