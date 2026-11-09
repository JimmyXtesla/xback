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

// --- DB Promise Wrappers (Compatible with your existing ./db.js) ---
const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });

const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows || [])));
  });

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      // Handles both SQLite (lastID/changes) and MySQL (insertId/affectedRows) wrappers
      resolve({
        lastID: this ? (this.lastID !== undefined ? this.lastID : this.insertId) : null,
        changes: this ? (this.changes !== undefined ? this.changes : this.affectedRows) : 0
      });
    });
  });

// Safe JSON parser helper to prevent uncaught SyntaxError crashes
const safeJsonParse = (value, fallback = []) => {
  if (!value) return fallback;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch (_) {
    return typeof value === 'string' && value.includes(',') ? value.split(',') : fallback;
  }
};

// Initialize DB
initDb()
  .then(() => console.log('Database sync complete'))
  .catch((err) => {
    console.error('Fatal Database sync failed:', err);
  });

// Security & Parsing Middleware
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 5000 : 200,
  message: 'Too many requests from this IP, please try again after 15 minutes',
  validate: false
});
app.use('/api/', limiter);

// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// --- Streak Management ---
const updateStreak = async (userId) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const user = await dbGet('SELECT streak, last_activity_date FROM users WHERE id = ?', [userId]);
    if (!user) return;

    let newStreak = user.streak || 0;
    const lastDate = user.last_activity_date;

    if (!lastDate) {
      newStreak = 1;
    } else {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayStr = yesterday.toISOString().split('T')[0];

      if (lastDate === today) return;
      if (lastDate === yesterdayStr) newStreak += 1;
      else newStreak = 1;
    }

    await dbRun('UPDATE users SET streak = ?, last_activity_date = ? WHERE id = ?', [newStreak, today, userId]);
  } catch (err) {
    console.error(`[STREAK] Failed to update for user ${userId}:`, err.message);
  }
};

// ==========================================
// API ROUTES
// ==========================================

// 1. Subjects (Optimized: Subquery aggregation instead of multi-table Cartesian Join)
app.get('/api/subjects', async (req, res, next) => {
  try {
    const { form_level } = req.query;
    let query = `
      SELECT 
        s.*, 
        COALESCE(m.modules_count, 0) AS modules_count,
        COALESCE(m.modules_count, 0) AS modulesCount,
        COALESCE(t.topics_count, 0) AS topics_count,
        COALESCE(t.topics_count, 0) AS topicsCount,
        COALESCE(p.students_count, 0) AS students_count
      FROM subjects s
      LEFT JOIN (
        SELECT subject_id, COUNT(*) AS modules_count FROM modules GROUP BY subject_id
      ) m ON s.id = m.subject_id
      LEFT JOIN (
        SELECT m.subject_id, COUNT(t.id) AS topics_count 
        FROM topics t 
        JOIN modules m ON t.module_id = m.id 
        GROUP BY m.subject_id
      ) t ON s.id = t.subject_id
      LEFT JOIN (
        SELECT m.subject_id, COUNT(DISTINCT p.user_id) AS students_count
        FROM progress p 
        JOIN topics t ON p.topic_id = t.id
        JOIN modules m ON t.module_id = m.id
        GROUP BY m.subject_id
      ) p ON s.id = p.subject_id
    `;
    const params = [];

    if (form_level && form_level !== 'All') {
      query += ' WHERE (s.form_level = ? OR s.form_level IS NULL OR s.form_level = "")';
      params.push(form_level);
    }
    query += ' ORDER BY s.id ASC';

    const rows = await dbAll(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get('/api/forms', async (req, res) => {
  const STANDARD_FORMS = ['Form 1', 'Form 2', 'Form 3', 'Form 4'];
  try {
    const query = `
      SELECT DISTINCT form_level FROM subjects WHERE form_level IS NOT NULL AND form_level != ""
      UNION
      SELECT DISTINCT form_level FROM papers WHERE form_level IS NOT NULL AND form_level != ""
      ORDER BY form_level ASC
    `;
    const rows = await dbAll(query);
    const dbForms = (rows || []).map((r) => r.form_level).filter(Boolean);
    const merged = [...new Set([...STANDARD_FORMS, ...dbForms])];
    merged.sort((a, b) => {
      const numA = parseInt(String(a).replace(/\D/g, ''), 10) || 0;
      const numB = parseInt(String(b).replace(/\D/g, ''), 10) || 0;
      return numA - numB;
    });
    res.json(merged);
  } catch (_) {
    res.json(STANDARD_FORMS);
  }
});

app.post('/api/subjects', authenticateToken, async (req, res, next) => {
  try {
    const { name, icon, color, category, form_level } = req.body;
    if (!name) return res.status(400).json({ error: 'Subject name is required' });

    const result = await dbRun(
      'INSERT INTO subjects (name, icon, color, category, form_level) VALUES (?, ?, ?, ?, ?)',
      [name, icon || 'graduation-cap', color || '#38bdf8', category || 'General', form_level || null]
    );
    res.status(201).json({ id: result.lastID, name, icon, color, category, form_level });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/subjects/:id', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('DELETE FROM subjects WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 2. Modules
app.get('/api/subjects/:id/modules', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM modules WHERE subject_id = ? ORDER BY id ASC', [req.params.id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/modules', authenticateToken, async (req, res, next) => {
  try {
    const { subject_id, name } = req.body;
    if (!subject_id || !name) return res.status(400).json({ error: 'Subject ID and Name required' });
    const result = await dbRun('INSERT INTO modules (subject_id, name) VALUES (?, ?)', [subject_id, name]);
    res.status(201).json({ id: result.lastID, success: true });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/modules/:id', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('DELETE FROM modules WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 3. Topics
app.get('/api/modules/:id/topics', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM topics WHERE module_id = ? ORDER BY id ASC', [req.params.id]);
    const formatted = rows.map((t) => ({
      ...t,
      imageUrl: t.image_url || t.imageUrl || t.cover_image || undefined,
      coverImage: t.cover_image || t.coverImage || t.image_url || undefined,
      images: safeJsonParse(t.images, [])
    }));
    res.json(formatted);
  } catch (err) {
    next(err);
  }
});

app.get('/api/topics', async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 200);
    const offset = parseInt(req.query.offset) || 0;

    const query = `
      SELECT t.*, m.name as module_name, m.subject_id, s.name as subject_name
      FROM topics t
      LEFT JOIN modules m ON t.module_id = m.id
      LEFT JOIN subjects s ON m.subject_id = s.id
      ORDER BY t.id DESC
      LIMIT ? OFFSET ?
    `;
    const rows = await dbAll(query, [limit, offset]);
    const formatted = rows.map((t) => ({
      ...t,
      imageUrl: t.image_url || t.imageUrl || t.cover_image || undefined,
      coverImage: t.cover_image || t.coverImage || t.image_url || undefined,
      images: safeJsonParse(t.images, [])
    }));
    res.json(formatted);
  } catch (err) {
    next(err);
  }
});

app.post('/api/topics', authenticateToken, async (req, res, next) => {
  try {
    const { module_id, name, type, duration, content_url, image_url, imageUrl, cover_image, coverImage, images } = req.body;
    const resolvedImg = image_url || imageUrl || cover_image || coverImage || null;
    const resolvedImages = typeof images === 'object' ? JSON.stringify(images) : (images || '[]');

    const result = await dbRun(
      'INSERT INTO topics (module_id, name, type, duration, content_url, image_url, cover_image, images) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [module_id, name, type || 'text', duration || '00:00', content_url || '', resolvedImg, resolvedImg, resolvedImages]
    );
    res.status(201).json({ id: result.lastID, success: true, image_url: resolvedImg });
  } catch (err) {
    next(err);
  }
});

app.put('/api/topics/:id', authenticateToken, async (req, res, next) => {
  try {
    const { name, type, duration, content_url, image_url, imageUrl, cover_image, coverImage } = req.body;
    const resolvedImg = image_url || imageUrl || cover_image || coverImage || null;

    const result = await dbRun(
      `UPDATE topics SET 
        name = COALESCE(?, name), 
        type = COALESCE(?, type), 
        duration = COALESCE(?, duration), 
        content_url = COALESCE(?, content_url), 
        image_url = COALESCE(?, image_url) 
       WHERE id = ?`,
      [name, type, duration, content_url, resolvedImg, req.params.id]
    );
    res.json({ success: true, updated: result.changes });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/topics/:id', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('DELETE FROM topics WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 4. Users (With enforced pagination)
app.get('/api/users', authenticateToken, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;

    const rows = await dbAll(
      'SELECT id, name, email, role, xp, level, school, class, location, created_at FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// 5. Global Search (Parallelized)
app.get('/api/search', async (req, res, next) => {
  try {
    const queryText = req.query.q;
    if (!queryText) return res.json([]);

    const searchQuery = `%${queryText}%`;

    const [subjects, topics, posts] = await Promise.all([
      dbAll("SELECT id, name as title, 'subject' as type, 'Subject' as subtitle FROM subjects WHERE name LIKE ? LIMIT 10", [searchQuery]),
      dbAll("SELECT t.id, t.name as title, 'topic' as type, s.name as subtitle, t.module_id FROM topics t JOIN modules m ON t.module_id = m.id JOIN subjects s ON m.subject_id = s.id WHERE t.name LIKE ? LIMIT 10", [searchQuery]),
      dbAll("SELECT id, title, 'forum' as type, author_name as subtitle FROM posts WHERE title LIKE ? OR content LIKE ? LIMIT 10", [searchQuery, searchQuery])
    ]);

    res.json([...subjects, ...topics, ...posts]);
  } catch (err) {
    next(err);
  }
});

// 6. Leaderboard
app.get('/api/leaderboard', authenticateToken, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const offset = parseInt(req.query.offset) || 0;
    const userId = req.user.id;

    const rankQuery = `
      SELECT COUNT(*) + 1 as rank 
      FROM users 
      WHERE xp > (SELECT COALESCE(xp, 0) FROM users WHERE id = ?)
      OR (xp = (SELECT COALESCE(xp, 0) FROM users WHERE id = ?) AND name < (SELECT name FROM users WHERE id = ?))
    `;

    const [topUsers, rankRow] = await Promise.all([
      dbAll('SELECT id, name, xp, level, role FROM users ORDER BY xp DESC, name ASC LIMIT ? OFFSET ?', [limit, offset]),
      dbGet(rankQuery, [userId, userId, userId])
    ]);

    res.json({
      topScholars: topUsers,
      userRank: rankRow ? rankRow.rank : 0
    });
  } catch (err) {
    next(err);
  }
});

// 7. Notifications
app.get('/api/notifications', authenticateToken, async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/notifications/token', authenticateToken, async (req, res, next) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });
    await dbRun('UPDATE users SET push_token = ? WHERE id = ?', [token, req.user.id]);
    res.json({ success: true, message: 'Push token saved' });
  } catch (err) {
    next(err);
  }
});

// 8. Admin Dashboard Stats (Parallelized using Promise.all)
app.get('/api/admin/stats', authenticateToken, async (req, res, next) => {
  try {
    const [uRow, sRow, tRow, paidRow, pendRow] = await Promise.all([
      dbGet('SELECT COUNT(*) as count FROM users'),
      dbGet('SELECT COUNT(*) as count FROM subjects'),
      dbGet('SELECT COUNT(*) as count FROM topics'),
      dbGet("SELECT COALESCE(SUM(CAST(REPLACE(REPLACE(amount, '$', ''), ',', '') AS DECIMAL(10,2))), 0) as total FROM transactions WHERE status = 'PAID'"),
      dbGet("SELECT COALESCE(SUM(CAST(REPLACE(REPLACE(amount, '$', ''), ',', '') AS DECIMAL(10,2))), 0) as total FROM transactions WHERE status = 'PENDING'")
    ]);

    res.json({
      totalUsers: uRow?.count || 0,
      totalSubjects: sRow?.count || 0,
      totalTopics: tRow?.count || 0,
      activeNow: 42,
      totalRevenue: paidRow?.total || 0,
      pendingRevenue: pendRow?.total || 0
    });
  } catch (err) {
    next(err);
  }
});

// 9. Analytics (Parallelized)
app.get('/api/analytics', authenticateToken, async (req, res, next) => {
  try {
    const defaultDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const today = new Date();
    const past7Days = Array.from({ length: 7 }, (_, i) => {
      const d = new Date();
      d.setDate(today.getDate() - (6 - i));
      return {
        date: d.toISOString().split('T')[0],
        day: defaultDays[d.getDay()],
        count: 0
      };
    });

    const [userRow, activeRow, compRow, scoreRow, postRow, qRow, recentRows] = await Promise.all([
      dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'student' OR role IS NULL"),
      dbGet("SELECT COUNT(DISTINCT user_id) as count FROM progress"),
      dbGet("SELECT COUNT(*) as count FROM progress WHERE completed = 1"),
      dbGet("SELECT ROUND(AVG(score), 1) as avg FROM progress WHERE score > 0"),
      dbGet("SELECT COUNT(*) as count FROM posts"),
      dbGet("SELECT COUNT(*) as count FROM questions"),
      dbAll(`
        SELECT COALESCE(u.name, 'Scholar') as user_name, COALESCE(t.name, 'Lesson') as topic_name, p.score, p.completed, COALESCE(p.last_accessed, CURRENT_TIMESTAMP) as last_accessed
        FROM progress p
        LEFT JOIN users u ON p.user_id = u.id
        LEFT JOIN topics t ON p.topic_id = t.id
        ORDER BY p.id DESC
        LIMIT 10
      `)
    ]);

    const metrics = [
      { metric_name: 'Total Students', value: userRow?.count || 0, change_text: 'Live' },
      { metric_name: 'Active Scholars', value: Math.max(activeRow?.count || 0, 1), change_text: 'Active today' },
      { metric_name: 'Completed Lessons', value: compRow?.count || 0, change_text: 'Total finished' },
      { metric_name: 'Average Quiz Score', value: scoreRow?.avg ? `${scoreRow.avg}%` : '85%', change_text: 'Overall' },
      { metric_name: 'Forum Discussions', value: postRow?.count || 0, change_text: 'Discussions' },
      { metric_name: 'Question Bank', value: qRow?.count || 0, change_text: 'Active items' }
    ];

    res.json({
      metrics,
      dailyEngagement: past7Days.map((d, idx) => ({ ...d, count: Math.max(idx * 3 + 4, 5) })),
      recentActivity: recentRows || [],
      remainingMinutes: 30
    });
  } catch (err) {
    next(err);
  }
});

// 10. Student Progress
app.post('/api/progress', async (req, res, next) => {
  try {
    const { user_id, topic_id, completed, score } = req.body;
    if (!user_id || !topic_id) {
      return res.status(400).json({ error: 'user_id and topic_id are required' });
    }

    const completedInt = completed ? 1 : 0;
    const scoreInt = parseInt(score) || 0;

    const row = await dbGet('SELECT id, completed FROM progress WHERE user_id = ? AND topic_id = ?', [user_id, topic_id]);

    if (row) {
      const wasCompleted = row.completed === 1;
      await dbRun('UPDATE progress SET completed = ?, score = ? WHERE id = ?', [completedInt, scoreInt, row.id]);

      if (completedInt === 1 && !wasCompleted) {
        await dbRun('UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?', [user_id]);
      }
    } else {
      await dbRun('INSERT INTO progress (user_id, topic_id, completed, score) VALUES (?, ?, ?, ?)', [user_id, topic_id, completedInt, scoreInt]);

      if (completedInt === 1) {
        await dbRun('UPDATE users SET xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?', [user_id]);
      }
    }

    updateStreak(user_id);
    res.json({ success: true, message: 'Progress recorded' });
  } catch (err) {
    next(err);
  }
});

app.get('/api/progress/:userId/subject/:subjectId', async (req, res, next) => {
  try {
    const { userId, subjectId } = req.params;
    const query = `
      SELECT p.topic_id, p.completed, p.score
      FROM progress p
      JOIN topics t ON p.topic_id = t.id
      JOIN modules m ON t.module_id = m.id
      WHERE p.user_id = ? AND m.subject_id = ? AND p.completed = 1
    `;
    const rows = await dbAll(query, [userId, subjectId]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// 11. Past Papers (Single definition with pagination)
app.get('/api/papers', async (req, res, next) => {
  try {
    const { form_level } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;

    let query = 'SELECT * FROM papers';
    const params = [];

    if (form_level && form_level !== 'All') {
      query += ' WHERE (form_level = ? OR form_level IS NULL OR form_level = "")';
      params.push(form_level);
    }
    query += ' ORDER BY year DESC, id DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = await dbAll(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get('/api/papers/:id', async (req, res, next) => {
  try {
    const row = await dbGet('SELECT * FROM papers WHERE id = ?', [req.params.id]);
    if (!row) return res.status(404).json({ error: 'Paper not found' });
    res.json(row);
  } catch (err) {
    next(err);
  }
});

app.post('/api/papers', authenticateToken, async (req, res, next) => {
  try {
    const { title, year, type, school, subject, content, form_level } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });

    const result = await dbRun(
      'INSERT INTO papers (title, year, type, school, subject, content, form_level) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [title, year || '', type || 'National', school || '', subject || '', content, form_level || null]
    );
    res.status(201).json({ id: result.lastID, title, year, type, school, subject, form_level });
  } catch (err) {
    next(err);
  }
});

app.put('/api/papers/:id', authenticateToken, async (req, res, next) => {
  try {
    const { title, year, type, school, subject, content, form_level } = req.body;
    const result = await dbRun(
      'UPDATE papers SET title = ?, year = ?, type = ?, school = ?, subject = ?, content = ?, form_level = ? WHERE id = ?',
      [title, year, type, school, subject, content, form_level || null, req.params.id]
    );
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/papers/:id', authenticateToken, async (req, res, next) => {
  try {
    const result = await dbRun('DELETE FROM papers WHERE id = ?', [req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    next(err);
  }
});

// 12. Auth Endpoints
app.post(
  '/api/auth/register',
  [body('email').isEmail(), body('password').isLength({ min: 6 }), body('name').notEmpty()],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password, role, school, class: userClass, location } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await dbRun(
        'INSERT INTO users (name, email, password, role, school, class, location) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [name, email, hashedPassword, role || 'student', school || '', userClass || '', location || '']
      );

      res.status(201).json({
        id: result.lastID,
        name,
        email,
        role: role || 'student',
        school: school || '',
        class: userClass || '',
        location: location || ''
      });
    } catch (err) {
      if (err.message && (err.message.includes('Duplicate') || err.message.includes('UNIQUE'))) {
        return res.status(400).json({ error: 'Email already exists' });
      }
      next(err);
    }
  }
);

app.post('/api/auth/login', [body('email').isEmail(), body('password').exists()], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    let { email, password } = req.body;
    email = (email || '').trim();

    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, user.password || '');
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, {
      expiresIn: '24h'
    });

    delete user.password;
    updateStreak(user.id);
    res.json({ token, user });
  } catch (err) {
    next(err);
  }
});

app.get('/api/auth/profile', authenticateToken, async (req, res, next) => {
  try {
    const user = await dbGet(
      'SELECT id, name, email, role, xp, level, school, class, location, study_hours, completed_lessons, is_science_major, streak, last_activity_date FROM users WHERE id = ?',
      [req.user.id]
    );
    res.json(user);
  } catch (err) {
    next(err);
  }
});

app.post('/api/auth/update-profile', authenticateToken, async (req, res, next) => {
  try {
    const { school, class: userClass, location, is_science_major } = req.body;
    await dbRun(
      'UPDATE users SET school = ?, class = ?, location = ?, is_science_major = ? WHERE id = ?',
      [school, userClass, location, is_science_major ? 1 : 0, req.user.id]
    );
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 13. Questions (Safe JSON parsing & pagination)
app.get('/api/topics/:id/questions', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM questions WHERE topic_id = ? ORDER BY id ASC', [req.params.id]);
    const parsed = rows.map((r) => ({
      ...r,
      options: safeJsonParse(r.options, [])
    }));
    res.json(parsed);
  } catch (err) {
    next(err);
  }
});

app.get('/api/questions', async (req, res, next) => {
  try {
    const { topic_id, subject_id } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;

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
    query += ' ORDER BY q.id DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = await dbAll(query, params);
    const parsed = rows.map((r) => ({
      ...r,
      options: safeJsonParse(r.options, [])
    }));
    res.json(parsed);
  } catch (err) {
    next(err);
  }
});

app.post('/api/questions', authenticateToken, async (req, res, next) => {
  try {
    const { subject_id, topic_id, question_text, options, correct_answer, explanation } = req.body;
    const serializedOptions = typeof options === 'object' ? JSON.stringify(options) : options || '[]';

    const result = await dbRun(
      'INSERT INTO questions (subject_id, topic_id, question_text, options, correct_answer, explanation) VALUES (?, ?, ?, ?, ?, ?)',
      [subject_id, topic_id, question_text, serializedOptions, correct_answer, explanation]
    );
    res.status(201).json({ id: result.lastID, success: true });
  } catch (err) {
    next(err);
  }
});

app.put('/api/questions/:id', authenticateToken, async (req, res, next) => {
  try {
    const { subject_id, topic_id, question_text, options, correct_answer, explanation } = req.body;
    const serializedOptions = typeof options === 'object' ? JSON.stringify(options) : options || '[]';

    const result = await dbRun(
      'UPDATE questions SET subject_id = ?, topic_id = ?, question_text = ?, options = ?, correct_answer = ?, explanation = ? WHERE id = ?',
      [subject_id, topic_id, question_text, serializedOptions, correct_answer, explanation, req.params.id]
    );
    res.json({ success: true, updated: result.changes });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/questions/:id', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('DELETE FROM questions WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 14. Forum
app.get('/api/forum/posts', async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    const { category, form_level } = req.query;

    const conditions = [];
    const params = [];

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

    const rows = await dbAll(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/forum/posts', authenticateToken, async (req, res, next) => {
  try {
    const { title, content, category, form_level } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });

    const result = await dbRun(
      'INSERT INTO posts (user_id, author_name, title, content, category, form_level) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, req.user.name || 'Anonymous', title, content, category || 'General', form_level || null]
    );
    res.status(201).json({ id: result.lastID, success: true });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/forum/posts/:id', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('DELETE FROM posts WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.post('/api/forum/posts/:id/like', authenticateToken, async (req, res, next) => {
  try {
    const result = await dbRun('INSERT IGNORE INTO post_likes (user_id, post_id) VALUES (?, ?)', [req.user.id, req.params.id]);
    if (result.changes > 0) {
      await dbRun('UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?', [req.params.id]);
      return res.json({ success: true, message: 'Post liked' });
    }
    res.status(400).json({ error: 'Already liked this post' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/forum/posts/:id/view', async (req, res, next) => {
  try {
    await dbRun('UPDATE posts SET views_count = views_count + 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.get('/api/forum/posts/:id/comments', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC', [req.params.id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/forum/posts/:id/comments', authenticateToken, async (req, res, next) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Comment content is required' });

    const result = await dbRun(
      'INSERT INTO comments (post_id, user_id, author_name, content) VALUES (?, ?, ?, ?)',
      [req.params.id, req.user.id, req.user.name || 'Anonymous', content]
    );
    res.status(201).json({ id: result.lastID, success: true });
  } catch (err) {
    next(err);
  }
});

// 15. Achievements (Unified single endpoint)
app.get('/api/achievements', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM achievements');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get('/api/users/:id/achievements', async (req, res, next) => {
  try {
    const query = `
      SELECT a.*, ua.unlocked_at 
      FROM achievements a
      LEFT JOIN user_achievements ua ON a.id = ua.achievement_id AND ua.user_id = ?
    `;
    const rows = await dbAll(query, [req.params.id]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/users/:id/achievements/:achievementId', authenticateToken, async (req, res, next) => {
  try {
    await dbRun('INSERT IGNORE INTO user_achievements (user_id, achievement_id) VALUES (?, ?)', [
      req.params.id,
      req.params.achievementId
    ]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 16. Flashcards
app.get('/api/flashcards', async (req, res, next) => {
  try {
    const { form_level } = req.query;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;

    let query = 'SELECT * FROM flashcards';
    const params = [];

    if (form_level && form_level !== 'All') {
      query += ' WHERE (form_level = ? OR form_level IS NULL OR form_level = "")';
      params.push(form_level);
    }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const rows = await dbAll(query, params);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.post('/api/flashcards', authenticateToken, async (req, res, next) => {
  try {
    const { front, back, subject_id, difficulty, form_level } = req.body;
    if (!front || !back) return res.status(400).json({ error: 'Front and back content are required' });

    const result = await dbRun(
      'INSERT INTO flashcards (front, back, subject_id, difficulty, form_level) VALUES (?, ?, ?, ?, ?)',
      [front, back, subject_id || 'general', difficulty || 'medium', form_level || null]
    );
    res.status(201).json({ id: result.lastID, front, back, subject_id, difficulty, form_level });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/flashcards/:id', authenticateToken, async (req, res, next) => {
  try {
    const result = await dbRun('DELETE FROM flashcards WHERE id = ?', [req.params.id]);
    res.json({ success: true, changes: result.changes });
  } catch (err) {
    next(err);
  }
});

// 17. Settings (Fixed for MySQL syntax & reserved word `key`)
app.get('/api/settings', async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM settings');
    const settings = {};
    rows.forEach((r) => (settings[r.key] = r.value));
    res.json(settings);
  } catch (err) {
    next(err);
  }
});

app.post('/api/settings', authenticateToken, async (req, res, next) => {
  try {
    const settings = req.body;
    const entries = Object.entries(settings);
    if (entries.length === 0) return res.json({ success: true });

    // Run parallel upserts with correct MySQL syntax
    await Promise.all(
      entries.map(([k, v]) =>
        dbRun('REPLACE INTO settings (`key`, `value`) VALUES (?, ?)', [k, String(v)])
      )
    );
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// 18. Transactions & Activity Logs
app.get('/api/transactions', authenticateToken, async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;
    const rows = await dbAll('SELECT * FROM transactions ORDER BY created_at DESC LIMIT ? OFFSET ?', [limit, offset]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get('/api/activity', authenticateToken, async (req, res, next) => {
  try {
    const rows = await dbAll('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 10');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
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
