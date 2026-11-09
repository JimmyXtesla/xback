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

// Initialize DB
initDb().then(() => {
  console.log('Database sync complete');
}).catch(err => {
  console.error('Database sync failed:', err);
});

// Security Middleware
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 5000 : 100,
  message: 'Too many requests from this IP, please try again after 15 minutes',
  validate: false
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
    });
  });
};

// --- API Routes ---

// 1. Subjects
app.get('/api/subjects', (req, res) => {
  const { form_level } = req.query;
  let baseQuery = `
    SELECT 
      s.*, 
      COUNT(DISTINCT m.id) as modules_count,
      COUNT(DISTINCT m.id) as modulesCount,
      COUNT(DISTINCT t.id) as topics_count,
      COUNT(DISTINCT t.id) as topicsCount,
      COUNT(DISTINCT p.user_id) as students_count
    FROM subjects s
    LEFT JOIN modules m ON s.id = m.subject_id
    LEFT JOIN topics t ON m.id = t.module_id
    LEFT JOIN progress p ON t.id = p.topic_id
  `;
  const params = [];
  if (form_level && form_level !== 'All') {
    baseQuery += ' WHERE (s.form_level = ? OR s.form_level IS NULL OR s.form_level = "")';
    params.push(form_level);
  }
  baseQuery += ' GROUP BY s.id';
  db.all(baseQuery, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/forms', (req, res) => {
  const query = `
    SELECT DISTINCT form_level FROM subjects WHERE form_level IS NOT NULL AND form_level != ""
    UNION
    SELECT DISTINCT form_level FROM papers WHERE form_level IS NOT NULL AND form_level != ""
    ORDER BY form_level ASC
  `;
  const STANDARD_FORMS = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];
  db.all(query, [], (err, rows) => {
    if (err || !rows) {
      return res.json(STANDARD_FORMS);
    }
    const dbForms = rows.map(r => r.form_level).filter(Boolean);
    const merged = [...new Set([...STANDARD_FORMS, ...dbForms])];
    merged.sort((a, b) => {
      const numA = parseInt(String(a).replace(/\D/g, ''), 10) || 0;
      const numB = parseInt(String(b).replace(/\D/g, ''), 10) || 0;
      return numA - numB;
    });
    res.json(merged);
  });
});

app.post('/api/subjects', authenticateToken, (req, res) => {
  const { name, icon, color, category, form_level } = req.body;
  if (!name) return res.status(400).json({ error: 'Subject name is required' });
  db.run(
    'INSERT INTO subjects (name, icon, color, category, form_level) VALUES (?, ?, ?, ?, ?)',
    [name, icon || 'graduation-cap', color || '#38bdf8', category || 'General', form_level || null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, name, icon, color, category, form_level });
    }
  );
});

// 2. Modules
app.get('/api/subjects/:id/modules', (req, res) => {
  db.all("SELECT * FROM modules WHERE subject_id = ?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 3. Topics
app.get('/api/modules/:id/topics', (req, res) => {
  db.all("SELECT * FROM topics WHERE module_id = ?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = (rows || []).map((t) => {
      let parsedImages = [];
      try {
        parsedImages = typeof t.images === 'string' ? JSON.parse(t.images) : (t.images || []);
      } catch (_) {
        parsedImages = [];
      }
      return {
        ...t,
        imageUrl: t.image_url || t.imageUrl || t.cover_image || undefined,
        coverImage: t.cover_image || t.coverImage || t.image_url || undefined,
        images: parsedImages,
      };
    });
    res.json(formatted);
  });
});

app.get('/api/topics', (req, res) => {
  const query = `
    SELECT t.*, m.name as module_name, m.subject_id, s.name as subject_name
    FROM topics t
    LEFT JOIN modules m ON t.module_id = m.id
    LEFT JOIN subjects s ON m.subject_id = s.id
    ORDER BY t.id DESC
  `;
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const formatted = (rows || []).map((t) => {
      let parsedImages = [];
      try {
        parsedImages = typeof t.images === 'string' ? JSON.parse(t.images) : (t.images || []);
      } catch (_) {
        parsedImages = [];
      }
      return {
        ...t,
        imageUrl: t.image_url || t.imageUrl || t.cover_image || undefined,
        coverImage: t.cover_image || t.coverImage || t.image_url || undefined,
        images: parsedImages,
      };
    });
    res.json(formatted);
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

  db.all("SELECT id, name as title, 'subject' as type, 'Subject' as subtitle FROM subjects WHERE name LIKE ?", [searchQuery], (err, subjects) => {
    if (err) return res.status(500).json({ error: err.message });

    db.all("SELECT t.id, t.name as title, 'topic' as type, s.name as subtitle, t.module_id FROM topics t JOIN modules m ON t.module_id = m.id JOIN subjects s ON m.subject_id = s.id WHERE t.name LIKE ?", [searchQuery], (err2, topics) => {
      if (err2) return res.status(500).json({ error: err2.message });

      db.all("SELECT id, title, 'forum' as type, author_name as subtitle FROM posts WHERE title LIKE ? OR content LIKE ?", [searchQuery, searchQuery], (err3, posts) => {
        if (err3) return res.status(500).json({ error: err3.message });

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

  db.all("SELECT id, name, xp, level, role FROM users ORDER BY xp DESC, name ASC LIMIT ? OFFSET ?", [limit, offset], (err, topUsers) => {
    if (err) return res.status(500).json({ error: err.message });

    const rankQuery = `
      SELECT COUNT(*) + 1 as rank 
      FROM users 
      WHERE xp > (SELECT xp FROM users WHERE id = ?)
      OR (xp = (SELECT xp FROM users WHERE id = ?) AND name < (SELECT name FROM users WHERE id = ?))
    `;

    db.get(rankQuery, [userId, userId, userId], (err2, rankRow) => {
      res.json({
        topScholars: topUsers,
        userRank: rankRow ? rankRow.rank : 0
      });
    });
  });
});

// 7. Notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
  db.all("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/notifications/token', authenticateToken, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Token is required" });

  db.run("UPDATE users SET push_token = ? WHERE id = ?", [token, req.user.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: "Push token saved" });
  });
});

// 8. User Achievements
app.get('/api/users/:id/achievements', (req, res) => {
  const query = `
    SELECT a.*, ua.unlocked_at 
    FROM achievements a
    LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.user_id = ?
  `;
  db.all(query, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// 9. Dashboard Stats
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
    db.get("SELECT COUNT(*) as count FROM subjects", (err2, row2) => {
      if (row2) stats.totalSubjects = row2.count;
      db.get("SELECT COUNT(*) as count FROM topics", (err3, row3) => {
        if (row3) stats.totalTopics = row3.count;
        res.json(stats);
      });
    });
  });
});

// 10. Student Progress
app.post('/api/progress', (req, res) => {
  const { user_id, topic_id, completed, score } = req.body;
  if (!user_id || !topic_id) {
    return res.status(400).json({ error: "user_id and topic_id are required" });
  }

  const completedInt = completed ? 1 : 0;
  const scoreInt = parseInt(score) || 0;

  db.get("SELECT id, completed FROM progress WHERE user_id = ? AND topic_id = ?", [user_id, topic_id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });

    if (row) {
      const wasCompleted = row.completed === 1;
      db.run("UPDATE progress SET completed = ?, score = ? WHERE id = ?", [completedInt, scoreInt, row.id], (updErr) => {
        if (updErr) return res.status(500).json({ error: updErr.message });

        if (completedInt === 1 && !wasCompleted) {
          db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id]);
        }
        updateStreak(user_id);
        res.json({ success: true, message: "Progress updated" });
      });
    } else {
      db.run("INSERT INTO progress (user_id, topic_id, completed, score) VALUES (?, ?, ?, ?)",
        [user_id, topic_id, completedInt, scoreInt], (insErr) => {
          if (insErr) return res.status(500).json({ error: insErr.message });

          if (completedInt === 1) {
            db.run("UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id]);
          }
          updateStreak(user_id);
          res.json({ success: true, message: "Progress created" });
        });
    }
  });
});

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
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

// 11. Papers CRUD
app.get('/api/papers', (req, res) => {
  const { form_level } = req.query;
  let query = 'SELECT * FROM papers';
  const params = [];
  if (form_level && form_level !== 'All') {
    query += ' WHERE (form_level = ? OR form_level IS NULL OR form_level = "")';
    params.push(form_level);
  }
  query += ' ORDER BY year DESC, id DESC';
  db.all(query, params, (err, rows) => {
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
  const { title, year, type, school, subject, content, form_level } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Title and content are required" });
  db.run(
    "INSERT INTO papers (title, year, type, school, subject, content, form_level) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [title, year || '', type || 'National', school || '', subject || '', content, form_level || null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, title, year, type, school, subject, form_level });
    }
  );
});

app.put('/api/papers/:id', authenticateToken, (req, res) => {
  const { title, year, type, school, subject, content, form_level } = req.body;
  db.run(
    "UPDATE papers SET title = ?, year = ?, type = ?, school = ?, subject = ?, content = ?, form_level = ? WHERE id = ?",
    [title, year, type, school, subject, content, form_level || null, req.params.id],
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

// 12. Auth Endpoints
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
          if (err.message.includes('UNIQUE') || err.message.includes('Duplicate')) {
            return res.status(400).json({ error: "Email already exists" });
          }
          return res.status(500).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID, name, email, role: role || 'student' });
      });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', [
  body('email').isEmail(),
  body('password').exists()
], (req, res) => {
  let { email, password } = req.body;
  email = (email || '').trim();

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.password || '');
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    delete user.password;
    updateStreak(user.id);
    res.json({ token, user });
  });
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  db.get("SELECT id, name, email, role, xp, level, school, class, location, study_hours, completed_lessons, is_science_major, streak, last_activity_date FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});

app.post('/api/auth/update-profile', authenticateToken, (req, res) => {
  const { school, class: userClass, location, is_science_major } = req.body;
  db.run(`UPDATE users SET school = ?, class = ?, location = ?, is_science_major = ? WHERE id = ?`,
    [school, userClass, location, is_science_major ? 1 : 0, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// 13. Questions
app.get('/api/topics/:id/questions', (req, res) => {
  db.all("SELECT * FROM questions WHERE topic_id = ?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const parsed = (rows || []).map(r => {
      let options = [];
      try {
        options = typeof r.options === 'string' ? JSON.parse(r.options) : (r.options || []);
      } catch (_) {
        options = typeof r.options === 'string' ? r.options.split(',') : [];
      }
      return { ...r, options };
    });
    res.json(parsed);
  });
});

app.get('/api/questions', (req, res) => {
  const { topic_id, subject_id } = req.query;
  let query = `
    SELECT q.*, t.name as topic_name, s.name as subject_name
    FROM questions q
    LEFT JOIN topics t ON q.topic_id = t.id
    LEFT JOIN subjects s ON q.subject_id = s.id
  `;
  const conditions = [];
  const params = [];
  if (topic_id) {
    conditions.push('q.topic_id = ?');
    params.push(topic_id);
  }
  if (subject_id) {
    conditions.push('q.subject_id = ?');
    params.push(subject_id);
  }
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  query += ' ORDER BY q.id DESC';

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const parsed = (rows || []).map(r => {
      let options = [];
      try {
        options = typeof r.options === 'string' ? JSON.parse(r.options) : (r.options || []);
      } catch (_) {
        options = typeof r.options === 'string' ? r.options.split(',') : [];
      }
      return { ...r, options };
    });
    res.json(parsed);
  });
});

// 14. Forum
app.get('/api/forum/posts', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const { category, form_level } = req.query;

  let conditions = [];
  let params = [];

  if (category && category !== 'All') {
    conditions.push('category = ?');
    params.push(category);
  }
  if (form_level && form_level !== 'All') {
    conditions.push('(form_level = ? OR form_level IS NULL OR form_level = "")');
    params.push(form_level);
  }

  let query = 'SELECT * FROM posts';
  if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/forum/posts', authenticateToken, (req, res) => {
  const { title, content, category, form_level } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Title and content are required" });

  db.run("INSERT INTO posts (user_id, author_name, title, content, category, form_level) VALUES (?, ?, ?, ?, ?, ?)",
    [req.user.id, req.user.name || 'Anonymous', title, content, category || 'General', form_level || null], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, success: true });
    });
});

// 15. Flashcards
app.get('/api/flashcards', (req, res) => {
  const { form_level } = req.query;
  let query = 'SELECT * FROM flashcards';
  const params = [];
  if (form_level && form_level !== 'All') {
    query += ' WHERE (form_level = ? OR form_level IS NULL OR form_level = "")';
    params.push(form_level);
  }
  query += ' ORDER BY created_at DESC';
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/flashcards', authenticateToken, (req, res) => {
  const { front, back, subject_id, difficulty, form_level } = req.body;
  if (!front || !back) return res.status(400).json({ error: "Front and back content are required" });
  db.run(
    "INSERT INTO flashcards (front, back, subject_id, difficulty, form_level) VALUES (?, ?, ?, ?, ?)",
    [front, back, subject_id || 'general', difficulty || 'medium', form_level || null],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, front, back, subject_id, difficulty, form_level });
    }
  );
});

app.delete('/api/flashcards/:id', authenticateToken, (req, res) => {
  db.run("DELETE FROM flashcards WHERE id = ?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, changes: this.changes });
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  });
});

// Only listen locally, export for Vercel / serverless
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
  });
}

module.exports = app;
