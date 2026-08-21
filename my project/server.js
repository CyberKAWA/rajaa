/**
 * سيرفر بسيط بدون أي مكتبات خارجية (فقط Node.js الأساسي).
 * يشغّل الموقع + API لإدارة "الطلبة الأوائل" + حماية بكلمة مرور مشفّرة.
 *
 * التشغيل:
 *   node server.js
 * ثم افتح: http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const DEFAULT_DB = {
  columns: [
    { id: 'name', label: 'اسم الطالب' },
    { id: 'grade', label: 'المعدل' },
    { id: 'school', label: 'المدرسة' }
  ],
  students: [
    { id: 's1', values: { name: '[اسم الطالب الأول]', grade: '99.2', school: '[اسم المدرسة]' } },
    { id: 's2', values: { name: '[اسم الطالب الثاني]', grade: '98.7', school: '[اسم المدرسة]' } },
    { id: 's3', values: { name: '[اسم الطالب الثالث]', grade: '98.1', school: '[اسم المدرسة]' } }
  ]
};

const DEFAULT_PASSWORD = 'admin123'; // غيّريها من لوحة التحكم بعد أول تشغيل

/* ---------- تهيئة ملفات البيانات عند أول تشغيل ---------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), 'utf8');
}
if (!fs.existsSync(CONFIG_FILE)) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(DEFAULT_PASSWORD, salt, 64).toString('hex');
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ salt, hash }, null, 2), 'utf8');
}

/* ---------- جلسات دخول مؤقتة في الذاكرة (بدون مكتبات JWT) ---------- */
const sessions = new Map(); // token -> expiryTimestamp
const SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 ساعات

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}
function isValidSession(token) {
  if (!token || !sessions.has(token)) return false;
  const expiry = sessions.get(token);
  if (Date.now() > expiry) { sessions.delete(token); return false; }
  return true;
}

/* ---------- أدوات مساعدة ---------- */
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
}
function verifyPassword(password) {
  const { salt, hash } = readJson(CONFIG_FILE);
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(attempt, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2_000_000) { // حد أقصى 2MB لمنع إساءة الاستخدام
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}
function getToken(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

function serveStatic(req, res) {
  let reqPath = decodeURIComponent(req.url.split('?')[0]);
  if (reqPath === '/') reqPath = '/index.html';
  const filePath = path.join(PUBLIC_DIR, reqPath);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1>404 - الصفحة غير موجودة</h1>');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(content);
  });
}

/* ---------- السيرفر ---------- */
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  try {
    /* بيانات الطلبة والأعمدة - عرض عام (بدون تسجيل دخول) */
    if (url === '/api/data' && req.method === 'GET') {
      return sendJson(res, 200, readJson(DB_FILE));
    }

    /* تسجيل الدخول للوحة التحكم */
    if (url === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      if (typeof body.password !== 'string') return sendJson(res, 400, { error: 'كلمة المرور مفقودة' });
      if (verifyPassword(body.password)) {
        const token = createSession();
        return sendJson(res, 200, { token });
      }
      return sendJson(res, 401, { error: 'كلمة المرور غير صحيحة' });
    }

    /* حفظ الطلبة والأعمدة - يتطلب تسجيل دخول */
    if (url === '/api/data' && req.method === 'PUT') {
      if (!isValidSession(getToken(req))) return sendJson(res, 401, { error: 'الجلسة غير صالحة، سجّلي الدخول مجدداً' });
      const body = await readBody(req);
      if (!Array.isArray(body.columns) || !Array.isArray(body.students)) {
        return sendJson(res, 400, { error: 'بيانات غير صالحة' });
      }
      writeJson(DB_FILE, { columns: body.columns, students: body.students });
      return sendJson(res, 200, { ok: true });
    }

    /* تغيير كلمة المرور - يتطلب تسجيل دخول */
    if (url === '/api/password' && req.method === 'POST') {
      if (!isValidSession(getToken(req))) return sendJson(res, 401, { error: 'الجلسة غير صالحة' });
      const body = await readBody(req);
      if (typeof body.newPassword !== 'string' || body.newPassword.length < 4) {
        return sendJson(res, 400, { error: 'كلمة المرور قصيرة جداً' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.scryptSync(body.newPassword, salt, 64).toString('hex');
      writeJson(CONFIG_FILE, { salt, hash });
      return sendJson(res, 200, { ok: true });
    }

    /* أي طلب آخر يبدأ بـ /api غير معروف */
    if (url.startsWith('/api')) {
      return sendJson(res, 404, { error: 'غير موجود' });
    }

    /* خلاف ذلك: خدمة ملفات الموقع الثابتة */
    return serveStatic(req, res);

  } catch (err) {
    return sendJson(res, 500, { error: 'خطأ في السيرفر' });
  }
});

server.listen(PORT, () => {
  console.log(`✅ السيرفر يعمل على http://localhost:${PORT}`);
  console.log(`   كلمة المرور الافتراضية (إن لم تُغيَّر بعد): ${DEFAULT_PASSWORD}`);
});
