require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const { body, validationResult } = require('express-validator');
const { db, initDb } = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// Initialize DB
initDb().then(() => {
  console.log('Database sync complete');
}).catch(err => {
  console.error('Database sync failed:', err);
});

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 5000 : 100, // higher limit in dev mode
  message: 'Too many requests from this IP, please try again after 15 minutes'
});
app.use('/api/', limiter);


// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Access denied. Token missing." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token." });
    req.user = user;
    next();
  });
};

// --- Error Handler Middleware ---
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  });
};



// --- Streak Management ---
const updateStreak = (userId) => {
  const today = new Date().toISOString().split('T')[0];
  db.get("SELECT streak, last_activity_date FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user) return;

    let newStreak = user.streak || 0;
    const lastDate = user.last_activity_date;

    if (!lastDate) {
      newStreak = 1;
    } else {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];

      if (lastDate === today) {
        return;
      } else if (lastDate === yesterdayStr) {
        newStreak += 1;
      } else {
        newStreak = 1;
      }
    }

    db.run("UPDATE users SET streak = ?, last_activity_date = ? WHERE id = ?", [newStreak, today, userId], (err) => {
      if (err) console.error(`[STREAK] Failed to update for user ${userId}:`, err.message);
      else console.log(`[STREAK] User ${userId} streak updated to ${newStreak}`);
    });
  });
};

// --- API Routes ---

// 1. Subjects
app.get('/api/subjects', (req, res) => {
  const query = `
    SELECT 
      s.*, 
      COUNT(DISTINCT m.id) as modules_count,
      COUNT(DISTINCT p.user_id) as students_count
    FROM subjects s
    LEFT JOIN modules m ON s.id = m.subject_id
    LEFT JOIN topics t ON m.id = t.module_id
    LEFT JOIN progress p ON t.id = p.topic_id
    GROUP BY s.id
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 2. Modules for a Subject
app.get('/api/subjects/:id/modules', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM modules WHERE subject_id = ?", [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 3. Topics for a Module
app.get('/api/modules/:id/topics', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM topics WHERE module_id = ?", [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 4. Users (Admin view)
app.get('/api/users', (req, res) => {
  db.all("SELECT * FROM users ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
// 5. Global Search
app.get('/api/search', (req, res) => {
  const queryText = req.query.q;
  if (!queryText) return res.json([]);

  const searchQuery = `%${queryText}%`;

  // Search across subjects, topics, and posts
  const results = [];

  db.all("SELECT id, name as title, 'subject' as type, 'Subject' as subtitle FROM subjects WHERE name LIKE ?", [searchQuery], (err, subjects) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all("SELECT t.id, t.name as title, 'topic' as type, s.name as subtitle, t.module_id FROM topics t JOIN modules m ON t.module_id = m.id JOIN subjects s ON m.subject_id = s.id WHERE t.name LIKE ?", [searchQuery], (err, topics) => {
      if (err) return res.status(500).json({ error: err.message });

      db.all("SELECT id, title, 'forum' as type, author as subtitle FROM posts WHERE title LIKE ? OR content LIKE ?", [searchQuery, searchQuery], (err, posts) => {
        if (err) return res.status(500).json({ error: err.message });

        res.json([...subjects, ...topics, ...posts]);
      });
    });
  });
});

// 6. Leaderboard
app.get('/api/leaderboard', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  const offset = parseInt(req.query.offset) || 0;
  const userId = req.user.id;

  // Query 1: Get top leaderboard
  db.all("SELECT id, name, xp, level, role FROM users ORDER BY xp DESC, name ASC LIMIT ? OFFSET ?", [limit, offset], (err, topUsers) => {
    if (err) return res.status(500).json({ error: err.message });

    // Query 2: Get specific user's rank
    const rankQuery = `
      SELECT COUNT(*) + 1 as rank 
      FROM users 
      WHERE xp > (SELECT xp FROM users WHERE id = ?)
      OR (xp = (SELECT xp FROM users WHERE id = ?) AND name < (SELECT name FROM users WHERE id = ?))
    `;
    
    db.get(rankQuery, [userId, userId, userId], (err, rankRow) => {
      const userRank = rankRow ? rankRow.rank : 0;
      res.json({
        topScholars: topUsers,
        userRank: userRank
      });
    });
  });
});

// 7. Notifications (Mock for now but connected)
app.get('/api/notifications', authenticateToken, (req, res) => {
  // In a real app, this would be a table. For now, returning system notifications.
  const notifications = [
    { id: 1, title: 'Welcome to SLIDE!', message: 'Start your learning journey today.', type: 'info', created_at: new Date() },
    { id: 2, title: 'XP Earned', message: 'You earned 50 XP for completing your first lesson!', type: 'success', created_at: new Date() }
  ];
  res.json(notifications);
});

// 8. Past Papers
app.get('/api/papers', (req, res) => {
  db.all("SELECT * FROM papers ORDER BY year DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});


// 9. User Achievements
app.get('/api/users/:id/achievements', authenticateToken, (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT a.*, ua.unlocked_at 
    FROM achievements a
    JOIN user_achievements ua ON a.id = ua.achievement_id
    WHERE ua.user_id = ?
  `;
  db.all(query, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 5. Dashboard Stats (Admin view)
app.get('/api/admin/stats', (req, res) => {
  const stats = {
    totalUsers: 0,
    totalSubjects: 0,
    totalTopics: 0,
    activeNow: 42,
    totalRevenue: 0,
    pendingRevenue: 0
  };

  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (row) stats.totalUsers = row.count;
    db.get("SELECT COUNT(*) as count FROM subjects", (err, row) => {
      if (row) stats.totalSubjects = row.count;
      db.get("SELECT COUNT(*) as count FROM topics", (err, row) => {
        if (row) stats.totalTopics = row.count;
        db.get("SELECT SUM(CAST(REPLACE(REPLACE(amount, '$', ''), ',', '') AS FLOAT)) as total FROM transactions WHERE status = 'PAID'", (err, row) => {
          if (row && row.total) stats.totalRevenue = row.total;
          db.get("SELECT SUM(CAST(REPLACE(REPLACE(amount, '$', ''), ',', '') AS FLOAT)) as pending FROM transactions WHERE status = 'PENDING'", (err, row) => {
            if (row && row.pending) stats.pendingRevenue = row.pending;
            res.json(stats);
          });
        });
      });
    });
  });
});


// 6. Student Progress
app.post('/api/progress', (req, res) => {
  const { user_id, topic_id, completed, score } = req.body;
  if (!user_id || !topic_id) {
    return res.status(400).json({ error: "user_id and topic_id are required" });
  }

  // Normalise completed to integer for MySQL compatibility
  const completedInt = completed ? 1 : 0;
  const scoreInt = parseInt(score) || 0;

  console.log(`[PROGRESS] user=${user_id} topic=${topic_id} completed=${completedInt} score=${scoreInt}`);

  db.get("SELECT id, completed FROM progress WHERE user_id = ? AND topic_id = ?", [user_id, topic_id], (err, row) => {
    if (err) {
      console.error("[PROGRESS] Lookup error:", err.message);
      return res.status(500).json({ error: err.message });
    }

    if (row) {
      const wasCompleted = row.completed === 1 || row.completed === true;
      db.run("UPDATE progress SET completed = ?, score = ? WHERE id = ?",
        [completedInt, scoreInt, row.id], (err) => {
          if (err) return res.status(500).json({ error: err.message });

          // Grant XP only if this is the first time completing
          if (completedInt === 1 && !wasCompleted) {
            db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?",
              [user_id], (err) => {
                if (err) console.error("[XP] Update failed:", err.message);
                else console.log(`[XP] +50 XP granted to user ${user_id}`);
              });
          }

          // Update streak on every progress update
          updateStreak(user_id);

          res.json({ success: true, message: "Progress updated" });
        });
    } else {
      db.run("INSERT INTO progress (user_id, topic_id, completed, score) VALUES (?, ?, ?, ?)",
        [user_id, topic_id, completedInt, scoreInt], (err) => {
          if (err) return res.status(500).json({ error: err.message });

          if (completedInt === 1) {
            db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?",
              [user_id], (err) => {
                if (err) console.error("[XP] Update failed:", err.message);
                else console.log(`[XP] +50 XP granted to user ${user_id}`);
              });
          }

          // Update streak on new progress
          updateStreak(user_id);

          res.json({ success: true, message: "Progress created" });
        });
    }
  });
});

// 7. Get user progress for a subject (completed topic IDs)
app.get('/api/progress/:userId/subject/:subjectId', (req, res) => {
  const { userId, subjectId } = req.params;
  const query = `
    SELECT p.topic_id, p.completed, p.score
    FROM progress p
    JOIN topics t ON p.topic_id = t.id
    JOIN modules m ON t.module_id = m.id
    WHERE p.user_id = ? AND m.subject_id = ? AND p.completed = 1
  `;
  db.all(query, [userId, subjectId], (err, rows) => {
    if (err) {
      console.error("[PROGRESS GET] Error:", err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows || []);
  });
});

// 8. Papers CRUD
app.get('/api/papers', (req, res) => {
  db.all("SELECT * FROM papers ORDER BY year DESC, id DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.get('/api/papers/:id', (req, res) => {
  db.get("SELECT * FROM papers WHERE id = ?", [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: "Paper not found" });
    res.json(row);
  });
});

app.post('/api/papers', authenticateToken, (req, res) => {
  const { title, year, type, school, subject, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Title and content are required" });
  db.run(
    "INSERT INTO papers (title, year, type, school, subject, content) VALUES (?, ?, ?, ?, ?, ?)",
    [title, year || '', type || 'National', school || '', subject || '', content],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, title, year, type, school, subject });
    }
  );
});

app.put('/api/papers/:id', authenticateToken, (req, res) => {
  const { title, year, type, school, subject, content } = req.body;
  db.run(
    "UPDATE papers SET title = ?, year = ?, type = ?, school = ?, subject = ?, content = ? WHERE id = ?",
    [title, year, type, school, subject, content, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, changes: this.changes });
    }
  );
});

app.delete('/api/papers/:id', authenticateToken, (req, res) => {
  db.run("DELETE FROM papers WHERE id = ?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, changes: this.changes });
  });
});

// --- Auth Endpoints ---

// Register
app.post('/api/auth/register', [
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('name').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, email, password, role, school, class: userClass, location } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (name, email, password, role, school, class, location) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [name, email, hashedPassword, role || 'student', school || '', userClass || '', location || ''], function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: "Email already exists" });
          }
          return res.status(500).json({ error: err.message });
        }
        res.status(201).json({
          id: this.lastID,
          name,
          email,
          role: role || 'student',
          school: school || '',
          class: userClass || '',
          location: location || ''
        });
      });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail(),
  body('password').exists()
], (req, res) => {
  let { email, password } = req.body;
  email = email.trim();

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) {
      console.log(`[DEBUG] User not found: ${email}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password || '');
    console.log(`[DEBUG] Login: ${email}, Match: ${validPassword}`);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' } // Increased to 24h for smoother experience
    );

    // Remove password from user object
    delete user.password;

    // Add additional info for store if missing
    user.school = user.school || '';
    user.class = user.class || '';
    user.location = user.location || '';

    // Trigger streak update on login
    updateStreak(user.id);

    res.json({ token, user });
  });
});

// Profile Update (Protected)
app.post('/api/auth/update-profile', authenticateToken, (req, res) => {
  const { school, class: userClass, location, is_science_major } = req.body;
  const userId = req.user.id;

  db.run(`UPDATE users SET 
          school = ?, 
          class = ?, 
          location = ?, 
          is_science_major = ? 
          WHERE id = ?`,
    [school, userClass, location, is_science_major ? 1 : 0, userId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Profile (Protected)
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  db.get("SELECT id, name, email, role, xp, level, school, class, location, study_hours, completed_lessons, is_science_major, streak, last_activity_date FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});


// 9. User Management (Protected)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, email, role, password } = req.body;

  try {
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      db.run("UPDATE users SET name = ?, email = ?, role = ?, password = ? WHERE id = ?",
        [name, email, role, hashedPassword, id], function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true });
        });
    } else {
      db.run("UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?",
        [name, email, role, id], function (err) {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ success: true });
        });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 10. Curriculum Management (Protected)

// Modules
app.post('/api/modules', authenticateToken, (req, res) => {
  const { subject_id, name } = req.body;
  db.run("INSERT INTO modules (subject_id, name) VALUES (?, ?)", [subject_id, name], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, success: true });
  });
});

app.delete('/api/modules/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM modules WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// Topics
app.post('/api/topics', authenticateToken, (req, res) => {
  const { module_id, name, type, duration, content_url } = req.body;
  db.run("INSERT INTO topics (module_id, name, type, duration, content_url) VALUES (?, ?, ?, ?, ?)",
    [module_id, name, type || 'text', duration || '00:00', content_url || ''], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    });
});

app.delete('/api/topics/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM topics WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 11. Delete Subject
app.delete('/api/subjects/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM subjects WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 11. Transactions
app.get('/api/transactions', (req, res) => {
  db.all("SELECT * FROM transactions ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 12. Analytics
app.get('/api/analytics', (req, res) => {
  const result = {
    metrics: [],
    engagement: [40, 65, 45, 80, 55, 90, 70] // Weekly engagement data
  };

  db.all("SELECT * FROM analytics", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    result.metrics = rows;
    res.json(result);
  });
});


// 13. Tickets
app.get('/api/tickets', (req, res) => {
  db.all("SELECT * FROM tickets ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 14. Reports
app.get('/api/reports', (req, res) => {
  db.all("SELECT * FROM reports ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 15. Settings
app.get('/api/settings', (req, res) => {
  db.all("SELECT * FROM settings", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const settings = {};
    rows.forEach(r => settings[r.key] = r.value);
    res.json(settings);
  });
});

app.post('/api/settings', (req, res) => {
  const settings = req.body;
  const keys = Object.keys(settings);
  let completed = 0;

  if (keys.length === 0) return res.json({ success: true });

  keys.forEach(key => {
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", [key, String(settings[key])], (err) => {
      completed++;
      if (completed === keys.length) {
        res.json({ success: true });
      }
    });
  });
});

// 16. Activity Logs
app.get('/api/activity', (req, res) => {
  db.all("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 10", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// --- APP ENDPOINTS ---



// 19. Quiz Questions
app.get('/api/topics/:id/questions', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM questions WHERE topic_id = ?", [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    // Parse options JSON
    const parsed = rows.map(r => ({
      ...r,
      options: r.options ? JSON.parse(r.options) : []
    }));
    res.json(parsed);
  });
});

app.post('/api/questions', authenticateToken, (req, res) => {
  const { subject_id, topic_id, question_text, options, correct_answer, explanation } = req.body;
  db.run("INSERT INTO questions (subject_id, topic_id, question_text, options, correct_answer, explanation) VALUES (?, ?, ?, ?, ?, ?)",
    [subject_id, topic_id, question_text, options, correct_answer, explanation], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    });
});

app.delete('/api/questions/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM questions WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 21. Forum Management (Protected)
app.delete('/api/forum/posts/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM posts WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});
app.get('/api/users/:id/mistakes', authenticateToken, (req, res) => {
  const { id } = req.params;
  // Verify if requesting user is the same as ID or admin
  if (req.user.id != id && req.user.role !== 'admin') {
    return res.status(403).json({ error: "Access denied" });
  }

  const query = `
    SELECT m.*, q.question_text, q.correct_answer, s.name as subject_name 
    FROM mistakes_log m
    JOIN questions q ON m.question_id = q.id
    JOIN subjects s ON m.subject_id = s.id
    WHERE m.user_id = ?
    ORDER BY m.timestamp DESC
  `;
  db.all(query, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users/:id/mistakes', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { subject_id, question_id, user_answer } = req.body;
  db.run("INSERT INTO mistakes_log (user_id, subject_id, question_id, user_answer) VALUES (?, ?, ?, ?)",
    [id, subject_id, question_id, user_answer], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    });
});

// 21. Forum
app.get('/api/forum/posts', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const category = req.query.category;

  let query = "SELECT * FROM posts ";
  let params = [];

  if (category && category !== 'All') {
    query += "WHERE category = ? ";
    params.push(category);
  }

  query += "ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/forum/posts', authenticateToken, (req, res) => {
  const { title, content, category } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Title and content are required" });

  console.log(`[FORUM] Creating post: "${title}" by ${req.user.name} (${req.user.id})`);

  db.run("INSERT INTO posts (user_id, author_name, title, content, category) VALUES (?, ?, ?, ?, ?)",
    [req.user.id, req.user.name || 'Anonymous', title, content, category || 'General'], function (err) {
      if (err) {
        console.error("[FORUM] Database Error:", err.message);
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, success: true });
    });
});

app.post('/api/forum/posts/:id/like', authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  // Check if already liked using post_likes table
  db.run("INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)", [userId, id], function (err) {
    if (err) {
      if (err.message.includes('UNIQUE') || err.message.includes('Duplicate entry')) {
        return res.status(400).json({ error: "Already liked this post" });
      }
      return res.status(500).json({ error: err.message });
    }

    // Only increment if insertion was successful
    db.run("UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?", [id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, message: "Post liked" });
    });
  });
});

app.post('/api/forum/posts/:id/view', (req, res) => {
  const { id } = req.params;
  db.run("UPDATE posts SET views_count = views_count + 1 WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.get('/api/forum/posts/:id/comments', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC", [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/forum/posts/:id/comments', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  db.run("INSERT INTO comments (post_id, user_id, author_name, content) VALUES (?, ?, ?, ?)",
    [id, req.user.id, req.user.name || 'Anonymous', content], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    });
});

// 22. Achievements
app.get('/api/achievements', (req, res) => {
  db.all("SELECT * FROM achievements", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/users/:id/achievements', (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT a.*, ua.unlocked_at 
    FROM achievements a
    LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.user_id = ?
  `;
  db.all(query, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users/:id/achievements/:achievementId', authenticateToken, (req, res) => {
  const { id, achievementId } = req.params;
  db.run("INSERT OR IGNORE INTO user_achievements (user_id, achievement_id) VALUES (?, ?)",
    [id, achievementId], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
});

// 23. Flashcards
app.get('/api/flashcards', (req, res) => {
  db.all("SELECT * FROM flashcards ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/flashcards', authenticateToken, (req, res) => {
  const { front, back, subject_id, difficulty } = req.body;
  if (!front || !back) return res.status(400).json({ error: "Front and back content are required" });
  db.run(
    "INSERT INTO flashcards (front, back, subject_id, difficulty) VALUES (?, ?, ?, ?)",
    [front, back, subject_id || 'general', difficulty || 'medium'],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, front, back, subject_id, difficulty });
    }
  );
});

app.delete('/api/flashcards/:id', authenticateToken, (req, res) => {
  db.run("DELETE FROM flashcards WHERE id = ?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, changes: this.changes });
  });
});

// --- SOCKET.IO REAL-TIME FEATURES ---
const studyRooms = {}; // { subjectId: [{ userId, userName, socketId }] }
const activeBattles = {}; // { battleId: { players: [], questions: [], scores: {} } }

io.on('connection', (socket) => {
  console.log(`[SOCKET] User connected: ${socket.id}`);

  // 1. Study With Me Rooms
  socket.on('join_study_room', ({ userId, userName, subjectId }) => {
    socket.join(`room_${subjectId}`);
    if (!studyRooms[subjectId]) studyRooms[subjectId] = [];
    
    // Remove if already there (stale connection)
    studyRooms[subjectId] = studyRooms[subjectId].filter(u => u.userId !== userId);
    studyRooms[subjectId].push({ userId, userName, socketId: socket.id });
    
    io.to(`room_${subjectId}`).emit('room_update', studyRooms[subjectId]);
    console.log(`[ROOM] ${userName} joined room: ${subjectId}`);
  });

  socket.on('leave_study_room', ({ userId, subjectId }) => {
    if (studyRooms[subjectId]) {
      studyRooms[subjectId] = studyRooms[subjectId].filter(u => u.userId !== userId);
      io.to(`room_${subjectId}`).emit('room_update', studyRooms[subjectId]);
    }
    socket.leave(`room_${subjectId}`);
  });

  // 2. Peer-to-Peer Battles
  socket.on('challenge_search', ({ userId, userName, subjectId }) => {
    socket.join(`matching_${subjectId}`);
    // Simple matchmaking: just broadcast "who wants to play?"
    socket.to(`matching_${subjectId}`).emit('incoming_challenge', {
      challengerId: userId,
      challengerName: userName,
      subjectId,
      battleId: `battle_${Date.now()}_${userId}`
    });
  });

  socket.on('accept_challenge', ({ battleId, challengerId, acceptorId, acceptorName, subjectId }) => {
    socket.join(battleId);
    // Notify challenger
    io.to(`matching_${subjectId}`).emit('battle_started', {
      battleId,
      players: [challengerId, acceptorId],
      subjectId
    });
  });

  socket.on('disconnect', () => {
    // Cleanup presence
    for (const rid in studyRooms) {
      const initialCount = studyRooms[rid].length;
      studyRooms[rid] = studyRooms[rid].filter(u => u.socketId !== socket.id);
      if (studyRooms[rid].length !== initialCount) {
        io.to(`room_${rid}`).emit('room_update', studyRooms[rid]);
      }
    }
    console.log(`[SOCKET] User disconnected: ${socket.id}`);
  });
});

// Use Error Handler
app.use(errorHandler);

// Only listen if not being imported as a module (e.g. for Vercel)
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
    console.log(`Socket.io enabled and ready.`);
  });
}

module.exports = app;

