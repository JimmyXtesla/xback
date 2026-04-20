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
    connectionLimit: 100,
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
          name VARCHAR(255), 
          email VARCHAR(255) UNIQUE, 
          password TEXT, 
          role VARCHAR(50), 
          xp INT DEFAULT 0, 
          level INT DEFAULT 1, 
          school VARCHAR(255),
          class VARCHAR(100),
          location VARCHAR(255),
          study_hours INT DEFAULT 0,
          completed_lessons INT DEFAULT 0,
          is_science_major BOOLEAN DEFAULT 0,
          streak INT DEFAULT 0,
          last_activity_date DATE,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`.trim(),
        `CREATE TABLE IF NOT EXISTS subjects (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          name VARCHAR(255), 
          icon VARCHAR(100), 
          color VARCHAR(50), 
          category VARCHAR(100), 
          modules_count INT DEFAULT 0, 
          students_count INT DEFAULT 0
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS modules (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          subject_id INT, 
          name VARCHAR(255)
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS topics (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          module_id INT, 
          name VARCHAR(255), 
          duration VARCHAR(50), 
          type VARCHAR(50), 
          content_url TEXT
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS posts (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          title VARCHAR(255), 
          content TEXT, 
          author_name VARCHAR(255), 
          user_id INT, 
          category VARCHAR(100), 
          likes_count INT DEFAULT 0,
          views_count INT DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS post_likes (
          user_id INT,
          post_id INT,
          PRIMARY KEY (user_id, post_id)
        )`,
        `CREATE TABLE IF NOT EXISTS comments (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          post_id INT, 
          user_id INT, 
          author_name VARCHAR(255), 
          content TEXT, 
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS papers (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          title VARCHAR(255) NOT NULL, 
          year VARCHAR(20), 
          type VARCHAR(100), 
          school VARCHAR(255), 
          subject VARCHAR(255), 
          content TEXT, 
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS flashcards (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          front TEXT, 
          back TEXT, 
          subject_id VARCHAR(100), 
          difficulty VARCHAR(50) DEFAULT 'medium',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`,
        `CREATE TABLE IF NOT EXISTS progress (
          id ${DB_TYPE === 'mysql' ? 'INT AUTO_INCREMENT' : 'INTEGER PRIMARY KEY AUTOINCREMENT'}, 
          user_id INT,
          topic_id INT,
          completed BOOLEAN DEFAULT 0,
          score INT DEFAULT 0,
          last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP
          ${DB_TYPE === 'mysql' ? ', PRIMARY KEY (id)' : ''}
        )`
      ];

      for (const sql of tables) {
        await runQuery(sql);
      }

      // Create Indexes for Performance
      const indexQueries = [
        `CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
        `CREATE INDEX IF NOT EXISTS idx_progress_user_topic ON progress(user_id, topic_id)`,
        `CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)`,
        `CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)`,
        `CREATE INDEX IF NOT EXISTS idx_modules_subject_id ON modules(subject_id)`,
        `CREATE INDEX IF NOT EXISTS idx_topics_module_id ON topics(module_id)`
      ];

      for (const sql of indexQueries) {
        try {
          await runQuery(DB_TYPE === 'mysql' ? sql.replace('IF NOT EXISTS ', '') : sql);
        } catch (e) {
          // Ignore error if index already exists in MySQL
        }
      }

      // Add missing columns if they don't exist (Self-healing migrations)
      const migrations = [
        "ALTER TABLE posts ADD COLUMN user_id INT",
        "ALTER TABLE posts ADD COLUMN author_name VARCHAR(255)",
        "ALTER TABLE posts ADD COLUMN category VARCHAR(100)",
        "ALTER TABLE posts ADD COLUMN likes_count INT DEFAULT 0",
        "ALTER TABLE posts ADD COLUMN views_count INT DEFAULT 0",
        "ALTER TABLE comments ADD COLUMN user_id INT",
        "ALTER TABLE comments ADD COLUMN author_name VARCHAR(255)",
        "ALTER TABLE users ADD COLUMN streak INT DEFAULT 0",
        "ALTER TABLE users ADD COLUMN last_activity_date DATE",
        // Form level classification (Form 1, Form 2, Form 3, Form 4)
        "ALTER TABLE subjects ADD COLUMN form_level VARCHAR(20)",
        "ALTER TABLE papers ADD COLUMN form_level VARCHAR(20)",
        "ALTER TABLE flashcards ADD COLUMN form_level VARCHAR(20)",
        "ALTER TABLE posts ADD COLUMN form_level VARCHAR(20)"
      ];

      for (const sql of migrations) {
        try {
          await runQuery(sql);
        } catch (e) {
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
