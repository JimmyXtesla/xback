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
      // Create tables for BOTH SQLite and MySQL if needed
      const tables = [
        `CREATE TABLE IF NOT EXISTS users (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          name TEXT, 
          email VARCHAR(255) UNIQUE, 
          password TEXT, 
          role TEXT, 
          xp INT DEFAULT 0, 
          level INT DEFAULT 1, 
          school TEXT,
          class TEXT,
          location TEXT,
          study_hours INT DEFAULT 0,
          completed_lessons INT DEFAULT 0,
          is_science_major BOOLEAN DEFAULT 0,
          streak INT DEFAULT 0,
          last_activity_date DATE,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`.trim(),
        `CREATE TABLE IF NOT EXISTS subjects (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          name TEXT, 
          icon TEXT, 
          color TEXT, 
          category TEXT, 
          modules_count INT DEFAULT 0, 
          students_count INT DEFAULT 0,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS modules (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          subject_id INT, 
          name TEXT,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS topics (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          module_id INT, 
          name TEXT, 
          duration TEXT, 
          type TEXT, 
          content_url TEXT,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS posts (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          title TEXT, 
          content TEXT, 
          author_name TEXT, 
          user_id INT, 
          category TEXT, 
          likes_count INT DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS comments (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          post_id INT, 
          user_id INT, 
          author_name TEXT, 
          content TEXT, 
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS papers (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          title TEXT NOT NULL, 
          year TEXT, 
          type TEXT, 
          school TEXT, 
          subject TEXT, 
          content TEXT, 
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS flashcards (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          front TEXT, 
          back TEXT, 
          subject_id TEXT, 
          difficulty TEXT DEFAULT 'medium',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          ${DB_TYPE === 'mysql' ? 'PRIMARY KEY (id)' : ''}
        )`
      ];

      for (const sql of tables) {
        await runQuery(sql);
      }

      // Add missing columns if they don't exist (MySQL specific self-healing)
      if (DB_TYPE === 'mysql') {
        const migrations = [
          "ALTER TABLE posts ADD COLUMN IF NOT EXISTS user_id INT",
          "ALTER TABLE posts ADD COLUMN IF NOT EXISTS author_name TEXT",
          "ALTER TABLE posts ADD COLUMN IF NOT EXISTS category TEXT",
          "ALTER TABLE posts ADD COLUMN IF NOT EXISTS likes_count INT DEFAULT 0",
          "ALTER TABLE comments ADD COLUMN IF NOT EXISTS user_id INT",
          "ALTER TABLE comments ADD COLUMN IF NOT EXISTS author_name TEXT",
          "ALTER TABLE users ADD COLUMN IF NOT EXISTS streak INT DEFAULT 0",
          "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_activity_date DATE"
        ];
        // Note: IF NOT EXISTS for columns is MariaDB/MySQL 8.0.19+. 
        // For older MySQL, we try and ignore errors if column exists.
        for (const sql of migrations) {
           try { await runQuery(sql.replace('IF NOT EXISTS ', '')); } catch(e) { /* ignore existing column */ }
        }
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
