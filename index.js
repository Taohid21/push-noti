const express     = require('express');
const admin       = require('firebase-admin');
const bodyParser  = require('body-parser');
const cors        = require('cors');
const crypto      = require('crypto');
const fs          = require('fs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ── Firebase Admin initialize (Fixed for Render & \n PEM Key issue) ──
let serviceAccount;

try {
  if (fs.existsSync('./serviceAccountKey.json')) {
    serviceAccount = require('./serviceAccountKey.json');
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    serviceAccount = typeof process.env.FIREBASE_SERVICE_ACCOUNT === 'string' 
      ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) 
      : process.env.FIREBASE_SERVICE_ACCOUNT;
  }
} catch (err) {
  console.error('Error loading Service Account:', err.message);
}
if (serviceAccount) {
  // Fix for 'invalid_grant / Invalid JWT Signature' on Render & Docker
  if (typeof serviceAccount.private_key === 'string') {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin initialized successfully!');
  } catch (e) {
    console.error('Firebase Admin init error:', e.message);
  }
} else {
  console.error('CRITICAL: No Service Account Key found!');
}

const db = admin.firestore();

// ════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════

function isValidAppId(appId) {
  return appId && /^[a-zA-Z0-9._\-]{3,100}$/.test(appId);
}

function tokenDocId(token) {
  return token.replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
}

function devicesRef(appId) {
  return db.collection('push_tokens').doc(appId).collection('devices');
}

function appMetaRef(appId) {
  return db.collection('push_app_meta').doc(appId);
}

// Password → SHA-256 hash
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Password verify করো Firestore থেকে
async function verifyPassword(appId, password) {
  if (!password) return { ok: false, reason: 'password_required' };
  const doc = await appMetaRef(appId).get();
  if (!doc.exists) return { ok: false, reason: 'app_not_registered' };
  const stored = doc.data().passwordHash;
  if (!stored) return { ok: false, reason: 'no_password_set' };
  if (stored !== hashPassword(password)) return { ok: false, reason: 'invalid_password' };
  return { ok: true };
}

// ════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.send('Wevlo Push Notification Server is Running Successfully!');
});

// ── Register App ──
app.post('/register-app', async (req, res) => {
  const { appId, password } = req.body;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });
  if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'password min 6 chars' });

  try {
    const ref = appMetaRef(appId);
    const doc = await ref.get();

    if (doc.exists && doc.data().passwordHash) {
      const { currentPassword } = req.body;
      if (!currentPassword) {
        if (doc.data().passwordHash === hashPassword(password)) {
          return res.json({ success: true, message: 'already registered' });
        }
        return res.status(409).json({ success: false, error: 'app_already_registered' });
      }
      if (doc.data().passwordHash !== hashPassword(currentPassword)) {
        return res.status(401).json({ success: false, error: 'invalid_current_password' });
      }
    }

    await ref.set({
      appId,
      passwordHash: hashPassword(password),
      registeredAt: doc.exists ? doc.data().registeredAt : Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appId}] App registered/updated`);
    res.json({ success: true, message: 'app registered' });
  } catch (e) {
    console.error('Register-app error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Register Token ──
app.post('/register-token', async (req, res) => {
  const { token, appId, userAgent, password } = req.body;

  if (!token)               return res.status(400).json({ success: false, error: 'token required' });
  const appIdentifier = isValidAppId(appId) ? appId : 'cricton_web_app';

  if (password && isValidAppId(appId)) {
    const auth = await verifyPassword(appId, password);
    if (!auth.ok && auth.reason === 'invalid_password') {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
  }

  try {
    await devicesRef(appIdentifier).doc(tokenDocId(token)).set({
      token,
      appId: appIdentifier,
      userAgent:    userAgent || '',
      registeredAt: Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appIdentifier}] Token registered: ${token.substring(0, 20)}...`);
    res.json({ success: true });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Get tokens by appId ──
app.get('/tokens', async (req, res) => {
  const { appId, password } = req.query;
  const appIdentifier = isValidAppId(appId) ? appId : 'cricton_web_app';

  if (password && isValidAppId(appId)) {
    const auth = await verifyPassword(appId, password);
    if (!auth.ok && auth.reason !== 'app_not_registered' && auth.reason !== 'no_password_set') {
      return res.status(401).json({ success: false, error: auth.reason });
    }
  }

  try {
    const snap   = await devicesRef(appIdentifier).get();
    const tokens = snap.docs.map(d => ({
      token:        d.data().token,
      registeredAt: d.data().registeredAt,
      userAgent:    d.data().userAgent || ''
    }));
    res.json({ success: true, appId: appIdentifier, count: tokens.length, tokens });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send Notification (Individual or Broadcast 'all') ──
app.post('/send-notification', async (req, res) => {
  let { token, title, body, message, imageUrl, image, url, link, password, appId } = req.body;

  const t = title || 'Notification';
  const b = body || message || '';
  const img = imageUrl || image || '';
  const targetUrl = url || link || 'https://cricton.top/';

  // 🔴 যদি token 'all' বা 'broadcast' আসে - তবে ডাটাবেসের সবাইকে ব্রডকাস্ট পাঠানো হবে
  if (token === 'all' || token === 'broadcast' || (!token && appId)) {
    try {
      const appIdentifier = isValidAppId(appId) ? appId : 'cricton_web_app';
      const snap = await devicesRef(appIdentifier).get();

      if (snap.empty) {
        return res.json({ success: true, message: 'No registered tokens found to broadcast', total: 0 });
      }

      const tokens = snap.docs.map(d => d.data().token).filter(Boolean);
      const messages = tokens.map(tkn => ({
        token: tkn,
        data: { title: t, body: b, ...(img ? { imageUrl: img } : {}), url: targetUrl },
        notification: { title: t, body: b, ...(img ? { image: img } : {}) },
        android: { priority: 'high' }
      }));

      const result = await admin.messaging().sendEach(messages);
      console.log(`[${appIdentifier}] Broadcast Sent: ${result.successCount} ok, ${result.failureCount} failed`);

      return res.json({
        success:      true,
        appId:        appIdentifier,
        total:        tokens.length,
        successCount: result.successCount,
        failureCount: result.failureCount
      });
    } catch (e) {
      console.error('Broadcast error:', e.message);
      return res.status(500).json({ success: false, error: e.message });
    }
  }

  if (!token) return res.status(400).json({ success: false, error: 'token required' });

  // 🟢 একক ডিভাইসে পাঠানো
  try {
    const msg = {
      token,
      data: { title: t, body: b, ...(img ? { imageUrl: img } : {}), url: targetUrl },
      notification: { title: t, body: b, ...(img ? { image: img } : {}) },
      android: { priority: 'high' }
    };

    const msgId = await admin.messaging().send(msg);
    res.json({ success: true, messageId: msgId });
  } catch (e) {
    console.error('Send error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send to ALL tokens of an appId ──
app.post('/send-all', async (req, res) => {
  const { appId, title, body, imageUrl, password } = req.body;
  const appIdentifier = isValidAppId(appId) ? appId : 'cricton_web_app';

  if (password && isValidAppId(appId)) {
    const auth = await verifyPassword(appIdentifier, password);
    if (!auth.ok) return res.status(401).json({ success: false, error: auth.reason });
  }

  try {
    const snap = await devicesRef(appIdentifier).get();
    if (snap.empty) return res.json({ success: false, error: 'No tokens found for this app' });

    const tokens = snap.docs.map(d => d.data().token).filter(Boolean);
    const t = title || 'Notification';
    const b = body  || '';
    const messages = tokens.map(token => ({
      token,
      data: { title: t, body: b, ...(imageUrl ? { imageUrl } : {}) },
      android: { priority: 'high' }
    }));

    const result = await admin.messaging().sendEach(messages);
    console.log(`[${appIdentifier}] Sent: ${result.successCount} ok, ${result.failureCount} failed`);

    const batch = db.batch();
    let removed = 0;
    result.responses.forEach((r, i) => {
      if (!r.success) { batch.delete(snap.docs[i].ref); removed++; }
    });
    if (removed > 0) await batch.commit();

    res.json({
      success:      true,
      appId:        appIdentifier,
      total:        tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount
    });
  } catch (e) {
    console.error('Send-all error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Delete a token ──
app.delete('/token', async (req, res) => {
  const { appId, token, password } = req.query;
  const appIdentifier = isValidAppId(appId) ? appId : 'cricton_web_app';

  if (!token) return res.status(400).json({ success: false, error: 'token required' });

  try {
    await devicesRef(appIdentifier).doc(tokenDocId(token)).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 7860;
app.listen(PORT, () => console.log(`Wevlo Push Server running on port ${PORT}`));
