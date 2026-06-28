// server.js — الخادم الرئيسي: تسجيل، تسجيل دخول، جلسات، حماية المسارات
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-this-in-production';

// ------------------------------------------------------------------
// إعدادات عامة
// ------------------------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: path.join(__dirname, 'db') }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  }
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// ------------------------------------------------------------------
// أدوات مساعدة للتحقق من المدخلات
// ------------------------------------------------------------------
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function redirectIfAuthed(req, res, next) {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  next();
}

// ------------------------------------------------------------------
// الصفحة الرئيسية
// ------------------------------------------------------------------
app.get('/', (req, res) => {
  res.render('home');
});

// ------------------------------------------------------------------
// إنشاء حساب
// ------------------------------------------------------------------
app.get('/register', redirectIfAuthed, (req, res) => {
  res.render('register', { error: null, old: {} });
});

app.post('/register', redirectIfAuthed, async (req, res) => {
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const passwordConfirm = req.body.passwordConfirm || '';

  if (!name || name.length < 2) {
    return res.render('register', { error: 'الاسم يجب أن يكون حرفين على الأقل.', old: { name, email } });
  }
  if (!isValidEmail(email)) {
    return res.render('register', { error: 'صيغة البريد الإلكتروني غير صحيحة.', old: { name, email } });
  }
  if (password.length < 8) {
    return res.render('register', { error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل.', old: { name, email } });
  }
  if (password !== passwordConfirm) {
    return res.render('register', { error: 'كلمتا المرور غير متطابقتين.', old: { name, email } });
  }

  try {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.render('register', { error: 'هذا البريد الإلكتروني مسجّل مسبقًا.', old: { name, email } });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    ).run(name, email, passwordHash);

    req.session.user = { id: result.lastInsertRowid, name, email };
    res.redirect('/dashboard');

  } catch (err) {
    console.error('Register error:', err);
    res.render('register', { error: 'حدث خطأ غير متوقع، حاولي مرة أخرى.', old: { name, email } });
  }
});

// ------------------------------------------------------------------
// تسجيل الدخول
// ------------------------------------------------------------------
app.get('/login', redirectIfAuthed, (req, res) => {
  res.render('login', { error: null, old: {}, next: req.query.next || '/dashboard' });
});

app.post('/login', redirectIfAuthed, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const next = req.body.next || '/dashboard';

  if (!email || !password) {
    return res.render('login', { error: 'فضلاً أدخلي البريد وكلمة المرور.', old: { email }, next });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const genericError = 'البريد الإلكتروني أو كلمة المرور غير صحيحة.';

    if (!user) {
      return res.render('login', { error: genericError, old: { email }, next });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.render('login', { error: genericError, old: { email }, next });
    }

    req.session.user = { id: user.id, name: user.name, email: user.email };
    res.redirect(next);

  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'حدث خطأ غير متوقع، حاولي مرة أخرى.', old: { email }, next });
  }
});

// ------------------------------------------------------------------
// لوحة التحكم — محمية، تتطلب تسجيل دخول
// ------------------------------------------------------------------
app.get('/dashboard', requireAuth, (req, res) => {
  const user = db.prepare('SELECT name, email, created_at FROM users WHERE id = ?').get(req.session.user.id);
  res.render('dashboard', { profile: user });
});

// ------------------------------------------------------------------
// تسجيل الخروج
// ------------------------------------------------------------------
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ------------------------------------------------------------------
// صفحة 404
// ------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log(`✅ الخادم يعمل على http://localhost:${PORT}`);
});
