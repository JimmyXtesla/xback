require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
    const { body, validationResult } = require('express-validator');
    const { db, initDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

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

// Removed static file upload serving for stateless deployment.

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

// File upload functionality removed for stateless hosting.

// Initial database setup check moved to start script or conditional block


// --- API Routes ---

// 1. Subjects
app.get('/api/subjects', (req, res) => {
  const query = `
    SELECT s.*, 
    (SELECT COUNT(*) FROM modules m WHERE m.subject_id = s.id) as modules_count,
    (SELECT COUNT(DISTINCT user_id) FROM progress p JOIN topics t ON p.topic_id = t.id JOIN modules m ON t.module_id = m.id WHERE m.subject_id = s.id) as students_count
    FROM subjects s
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
app.get('/api/leaderboard', (req, res) => {
  db.all("SELECT id, name, xp, level FROM users ORDER BY xp DESC LIMIT 20", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
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

  const query = `INSERT INTO progress (user_id, topic_id, completed, score) 
                 VALUES (?, ?, ?, ?)
                 ON CONFLICT(user_id, topic_id) DO UPDATE SET
                 completed = excluded.completed,
                 score = excluded.score,
                 updated_at = CURRENT_TIMESTAMP`;

  // Note: SQLite doesn't support ON CONFLICT without UNIQUE constraint. 
  // For simplicity here, let's just insert or check existence first.
  db.get("SELECT id, completed FROM progress WHERE user_id = ? AND topic_id = ?", [user_id, topic_id], (err, row) => {
    if (row) {
      const previouslyCompleted = row.completed;
      db.run("UPDATE progress SET completed = ?, score = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [completed, score, row.id], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          
          // Update User XP if newly completed
          if (completed && !previouslyCompleted) {
            db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id]);
          }
          res.json({ success: true, message: "Progress updated" });
        });
    } else {
      db.run("INSERT INTO progress (user_id, topic_id, completed, score) VALUES (?, ?, ?, ?)",
        [user_id, topic_id, completed, score], (err) => {
          if (err) return res.status(500).json({ error: err.message });
          
          // Update User XP if completed
          if (completed) {
            db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id]);
          }
          res.json({ success: true, message: "Progress created" });
        });
    }
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

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    // Remove password from user object
    delete user.password;
    
    // Add additional info for store if missing
    user.school = user.school || '';
    user.class = user.class || '';
    user.location = user.location || '';
    
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
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// Profile (Protected)
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  db.get("SELECT id, name, email, role, xp, level, school, class, location, study_hours, completed_lessons, is_science_major FROM users WHERE id = ?", [req.user.id], (err, user) => {
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

// 18. Leaderboard
app.get('/api/leaderboard', (req, res) => {
  db.all("SELECT id, name, xp, level, role FROM users ORDER BY xp DESC LIMIT 20", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

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
  db.all("SELECT * FROM posts ORDER BY created_at DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/forum/posts', authenticateToken, (req, res) => {
  const { title, content, category } = req.body;
  db.run("INSERT INTO posts (user_id, author_name, title, content, category) VALUES (?, ?, ?, ?, ?)",
    [req.user.id, req.user.name || 'Anonymous', title, content, category], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
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

// Use Error Handler
app.use(errorHandler);

// Only listen if not being imported as a module (e.g. for Vercel)
if (require.main === module) {
  initDb().then(() => {
    app.listen(PORT, () => {
      console.log(`Backend server running on http://localhost:${PORT}`);
    });
  });
}

module.exports = app;

