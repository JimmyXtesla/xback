const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const DB_TYPE = process.env.DB_TYPE || 'mysql';

let db;
let pool;

console.log(`Initialising Database with type: ${DB_TYPE}`);

if (DB_TYPE === 'mysql') {
  pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'slide',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  const promisePool = pool.promise();

  db = {
    all: (sql, params, cb) => {
      pool.query(sql, params, (err, results) => {
        if (err) return cb(err);
        cb(null, results);
      });
    },
    get: (sql, params, cb) => {
      let actualParams = params;
      let actualCb = cb;
      if (typeof params === 'function') {
        actualCb = params;
        actualParams = [];
      }
      pool.query(sql, actualParams, (err, results) => {
        if (err) return actualCb(err);
        actualCb(null, results[0]);
      });
    },
    run: function (sql, params, cb) {
      let actualParams = params;
      let actualCb = cb;
      if (typeof params === 'function') {
        actualCb = params;
        actualParams = [];
      }
      pool.query(sql, actualParams, (err, results) => {
        if (err) {
          if (actualCb) actualCb(err);
          return;
        }
        const context = { lastID: results.insertId, changes: results.affectedRows };
        if (actualCb) actualCb.call(context, null);
      });
    }
  };

  // Log pool errors
  pool.on('error', (err) => {
    console.error('Unexpected error on idle database connection pool', err);
  });
} else {
  // SQLite - Only loaded if needed
  const sqlite3 = require('sqlite3').verbose();
  const dbPath = path.resolve(__dirname, 'slide.db');
  const sqliteDb = new sqlite3.Database(dbPath);
  db = sqliteDb;
}

const initDb = async () => {
  const hashedPass = await bcrypt.hash('admin123', 10);

  return new Promise((resolve) => {
    const runQuery = (sql, params = []) => {
      return new Promise((res) => {
        db.run(sql, params, (err) => res(err));
      });
    };

    const setup = async () => {
      // Create tables for SQLite if needed (MySQL handled by script)
      if (DB_TYPE === 'sqlite') {
        await runQuery(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'student', xp INTEGER DEFAULT 0, level INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS subjects (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, icon TEXT, color TEXT, modules_count INTEGER DEFAULT 0, students_count INTEGER DEFAULT 0)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS modules (id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER, name TEXT)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS topics (id INTEGER PRIMARY KEY AUTOINCREMENT, module_id INTEGER, name TEXT, duration TEXT, type TEXT, content_url TEXT)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS progress (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, topic_id INTEGER, completed BOOLEAN, score INTEGER, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, topic_id))`);
        await runQuery(`CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, author_name TEXT, user_id INTEGER, category TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, user_id INTEGER, author_name TEXT, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS questions (id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id INTEGER, topic_id INTEGER, question_text TEXT, options TEXT, correct_answer TEXT, explanation TEXT)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS achievements (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, icon TEXT, xp_reward INTEGER)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS user_achievements (user_id INTEGER, achievement_id INTEGER, unlocked_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (user_id, achievement_id))`);
        await runQuery(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
        await runQuery(`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id TEXT UNIQUE, user_name TEXT, plan TEXT, amount TEXT, status TEXT, type TEXT, created_at DATETIME)`);
      }

      // Check Admin
      db.get("SELECT * FROM users WHERE email = ?", ['admin@slide.edu'], (err, row) => {
        if (!row) {
          db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            ['System Admin', 'admin@slide.edu', hashedPass, 'admin']);
        }
      });

      console.log(`Database (${DB_TYPE}) initialized.`);
      resolve();
    };

    setup();
  });
};

module.exports = { db, initDb };
