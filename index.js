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
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 5000 : 100, // higher limit in dev mode
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

// 1.1 Get unique Form Levels
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

// Create Subject (Admin)
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

// 3.1 All Topics (for Admin & metadata)
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

// 7. Notifications
app.get('/api/notifications', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC", [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.post('/api/notifications/token', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Token is required" });

  db.run("UPDATE users SET push_token = ? WHERE id = ?", [token, userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: "Push token saved" });
  });
});

app.post('/api/notifications/send', authenticateToken, async (req, res) => {
  // Example admin-only or specific logic
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Access denied" });
  
  const { title, message, user_id } = req.body;
  if (!title || !message) return res.status(400).json({ error: "Title and message are required" });

  if (user_id) {
    db.run("INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)", 
      [user_id, title, message, 'info']);
      
    // Send via Expo Push API
    db.get("SELECT push_token FROM users WHERE id = ?", [user_id], async (err, row) => {
      if (row && row.push_token) {
        try {
          await fetch('https://exp.host/--/api/v2/push/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: row.push_token, title, body: message })
          });
        } catch (e) {
          console.error('Push notification failed:', e);
        }
      }
    });
  }
  res.json({ success: true, message: "Notification queued" });
});

// 8. Past Papers (with optional form_level filter)
app.get('/api/papers', (req, res) => {
  const { form_level } = req.query;
  let query = 'SELECT * FROM papers';
  const params = [];
  if (form_level && form_level !== 'All') {
    query += ' WHERE (form_level = ? OR form_level IS NULL OR form_level = "")';
    params.push(form_level);
  }
  query += ' ORDER BY year DESC';
  db.all(query, params, (err, rows) => {
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

// 7. Get user progress for a subject 
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
  console.log(`[ADMIN] Creating module: "${name}" for subject: ${subject_id}`);
  db.run("INSERT INTO modules (subject_id, name) VALUES (?, ?)", [subject_id, name], function (err) {
    if (err) {
      console.error("[ADMIN] Module creation failed:", err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json({ id: this.lastID, success: true });
  });
});

app.delete('/api/modules/:id', authenticateToken, (req, res) => {
  const { id } = r
