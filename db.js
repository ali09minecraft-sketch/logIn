// db.js — إعداد قاعدة بيانات SQLite وإنشاء جدول المستخدمين
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'db', 'app.db');
const db = new Database(dbPath);

// تفعيل وضع WAL لأداء أفضل مع الكتابة/القراءة المتزامنة
db.pragma('journal_mode = WAL');

// إنشاء جدول المستخدمين إذا لم يكن موجودًا
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

module.exports = db;
