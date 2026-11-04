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
app.use(helmet());
app.use(cors());
app.use(morgan('dev'));
app.use(express.json({ limit: '6mb' }));

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

const requireAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' });
  next();
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

const getStudyQuest = (userId, callback) => {
  db.get(
    'SELECT quest_type AS type, target, progress, reward_xp AS rewardXp, started_at AS startedAt, completed_at AS completedAt FROM study_quests WHERE user_id = ?',
    [userId],
    (err, quest) => callback(err, quest || null)
  );
};

const getStudyStats = (userId, callback) => {
  db.get(
    'SELECT xp, level, streak, completed_lessons AS completedLessons, last_activity_date AS lastStudyDate FROM users WHERE id = ?',
    [userId],
    callback
  );
};

const sendStudyState = (res, userId, extra = {}) => {
  getStudyStats(userId, (statsErr, stats) => {
    if (statsErr) return res.status(500).json({ error: statsErr.message });
    getStudyQuest(userId, (questErr, quest) => {
      if (questErr) return res.status(500).json({ error: questErr.message });
      res.json({ success: true, stats, quest, ...extra });
    });
  });
};

const ACCOUNT_SYNC_FIELDS = new Set([
  'studyGoalHours', 'mistakesLog', 'achievements', 'savedTopicIds', 'activityLogs',
  'flashcards', 'downloadedTopicIds', 'offlineLessons', 'blockedForumUserIds',
  'notificationSettings', 'leaguePoints', 'leagueTier', 'inPromotionZone', 'lastProgress', 'themePreferences'
]);

app.get('/api/account/sync', authenticateToken, (req, res) => {
  db.get('SELECT payload, updated_at AS updatedAt FROM user_sync_data WHERE user_id = ?', [req.user.id], (err, row) => {

    if (!row) return res.json({ values: {}, versions: {}, updatedAt: 0 });
    try {
      const data = JSON.parse(row.payload || '{}');
      res.json({ values: data.values || {}, versions: data.versions || {}, updatedAt: Number(row.updatedAt || 0) });
    } catch (parseErr) {
      console.error('[ACCOUNT_SYNC] Invalid stored sync data for user', req.user.id);
      res.status(500).json({ error: 'Could not read saved account data.' });
    }
  });
});

app.put('/api/account/sync', authenticateToken, (req, res) => {
  const incomingValues = req.body?.values;
  const incomingVersions = req.body?.versions;
  if (!incomingValues || typeof incomingValues !== 'object' || Array.isArray(incomingValues) ||
      !incomingVersions || typeof incomingVersions !== 'object' || Array.isArray(incomingVersions)) {
    return res.status(400).json({ error: 'Account sync data is invalid.' });
  }

  const allowedValues = {};
  const allowedVersions = {};
  for (const key of ACCOUNT_SYNC_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(incomingValues, key)) continue;
    const version = Number(incomingVersions[key]);
    if (!Number.isFinite(version) || version < 0) continue;
    allowedValues[key] = incomingValues[key];
    allowedVersions[key] = version;
  }
  const serializedInput = JSON.stringify({ values: allowedValues, versions: allowedVersions });
  if (Buffer.byteLength(serializedInput, 'utf8') > 5 * 1024 * 1024) {
    return res.status(413).json({ error: 'Saved account data is too large to sync.' });
  }

  const userId = req.user.id;
  db.get('SELECT payload FROM user_sync_data WHERE user_id = ?', [userId], (lookupErr, row) => {
    if (lookupErr) return res.status(500).json({ error: lookupErr.message });
    let current = { values: {}, versions: {} };
    if (row?.payload) {
      try { current = JSON.parse(row.payload); } catch (_) { /* replace malformed legacy payload */ }
    }
    current.values ||= {};
    current.versions ||= {};
    for (const [key, value] of Object.entries(allowedValues)) {
      if (allowedVersions[key] >= Number(current.versions[key] || 0)) {
        current.values[key] = value;
        current.versions[key] = allowedVersions[key];
      }
    }
    const updatedAt = Date.now();
    const payload = JSON.stringify(current);
    const sql = process.env.DB_TYPE === 'sqlite'
      ? 'INSERT INTO user_sync_data (user_id, payload, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at'
      : 'INSERT INTO user_sync_data (user_id, payload, updated_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE payload = VALUES(payload), updated_at = VALUES(updated_at)';
    db.run(sql, [userId, payload, updatedAt], (saveErr) => {
      if (saveErr) return res.status(500).json({ error: saveErr.message });
      res.json({ ...current, updatedAt });
    });
  });
});

// Study quests and rewards are stored per account, not only on the device.
app.get('/api/study/quest', authenticateToken, (req, res) => {
  getStudyQuest(req.user.id, (err, quest) => {

    res.json({ quest });
  });
});

app.post('/api/study/quest', authenticateToken, (req, res) => {
  const { type } = req.body;
  if (!['lesson', 'quiz'].includes(type)) {
    return res.status(400).json({ error: 'Quest type must be lesson or quiz.' });
  }

  const userId = req.user.id;
  const startedAt = Date.now();
  const values = [type, 1, 0, 25, startedAt, userId];
  db.get('SELECT user_id FROM study_quests WHERE user_id = ?', [userId], (lookupErr, row) => {
    if (lookupErr) return res.status(500).json({ error: lookupErr.message });
    const sql = row
      ? 'UPDATE study_quests SET quest_type = ?, target = ?, progress = ?, reward_xp = ?, started_at = ?, completed_at = NULL WHERE user_id = ?'
      : 'INSERT INTO study_quests (quest_type, target, progress, reward_xp, started_at, user_id) VALUES (?, ?, ?, ?, ?, ?)';
    db.run(sql, values, (err) => {
  
      sendStudyState(res, userId);
    });
  });
});

app.post('/api/study/activity', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { type, eventId } = req.body;
  const xpAward = Math.max(0, Math.min(5000, Math.floor(Number(req.body.xpAward) || 0)));
  if (!['lesson', 'quiz'].includes(type)) return res.status(400).json({ error: 'Activity type must be lesson or quiz.' });
  if (typeof eventId !== 'string' || eventId.length < 6 || eventId.length > 100) {
    return res.status(400).json({ error: 'A valid activity event ID is required.' });
  }

  db.get('SELECT event_id, xp_awarded, quest_xp_awarded FROM study_activity_events WHERE user_id = ? AND event_id = ?', [userId, eventId], (existingErr, existing) => {
    if (existingErr) return res.status(500).json({ error: existingErr.message });
    if (existing) return sendStudyState(res, userId, {
      duplicate: true,
      xpAwarded: Number(existing.xp_awarded || 0) + Number(existing.quest_xp_awarded || 0),
      questXpAwarded: Number(existing.quest_xp_awarded || 0),
    });

    const eventSql = 'INSERT INTO study_activity_events (user_id, event_id, activity_type, xp_awarded, quest_xp_awarded) VALUES (?, ?, ?, ?, 0)';
    db.run(eventSql, [userId, eventId, type, xpAward], function (insertErr) {
      if (insertErr) {
        // A simultaneous retry can win the unique key between the read and insert.
        return db.get('SELECT event_id, xp_awarded, quest_xp_awarded FROM study_activity_events WHERE user_id = ? AND event_id = ?', [userId, eventId], (retryErr, duplicate) => {
          if (!retryErr && duplicate) return sendStudyState(res, userId, {
            duplicate: true,
            xpAwarded: Number(duplicate.xp_awarded || 0) + Number(duplicate.quest_xp_awarded || 0),
            questXpAwarded: Number(duplicate.quest_xp_awarded || 0),
          });
          res.status(500).json({ error: insertErr.message });
        });
      }

      const applyActivity = (questBonus) => {
        const now = new Date();
        const today = now.toISOString().slice(0, 10);
        db.get('SELECT xp, streak, last_activity_date FROM users WHERE id = ?', [userId], (userErr, user) => {
          if (userErr) return res.status(500).json({ error: userErr.message });
          if (!user) return res.status(404).json({ error: 'Student account not found.' });
          const previousDate = user.last_activity_date instanceof Date
            ? user.last_activity_date.toISOString().slice(0, 10)
            : String(user.last_activity_date || '').slice(0, 10);
          const yesterday = new Date(now);
          yesterday.setUTCDate(yesterday.getUTCDate() - 1);
          const yesterdayString = yesterday.toISOString().slice(0, 10);
          const streak = previousDate === today
            ? Number(user.streak || 0)
            : previousDate === yesterdayString ? Number(user.streak || 0) + 1 : 1;
          const newXp = Number(user.xp || 0) + xpAward + questBonus;
          const level = Math.floor(newXp / 500) + 1;

          db.run(
            'UPDATE users SET xp = ?, level = ?, streak = ?, last_activity_date = ? WHERE id = ?',
            [newXp, level, streak, today, userId],
            (updateErr) => {
              if (updateErr) return res.status(500).json({ error: updateErr.message });
              if (questBonus > 0) {
                db.run('UPDATE study_activity_events SET quest_xp_awarded = ? WHERE user_id = ? AND event_id = ?', [questBonus, userId, eventId], (ledgerErr) => {
                  if (ledgerErr) return res.status(500).json({ error: ledgerErr.message });
                  sendStudyState(res, userId, { duplicate: false, xpAwarded: xpAward + questBonus, questXpAwarded: questBonus });
                });
              } else {
                sendStudyState(res, userId, { duplicate: false, xpAwarded: xpAward, questXpAwarded: 0 });
              }
            }
          );
        });
      };

      getStudyQuest(userId, (questErr, quest) => {
        if (questErr) return res.status(500).json({ error: questErr.message });
        if (!quest || quest.type !== type || quest.completedAt) return applyActivity(0);

        const nextProgress = Math.min(Number(quest.progress || 0) + 1, Number(quest.target || 1));
        const completedAt = nextProgress >= Number(quest.target || 1) ? Date.now() : null;
        db.run(
          'UPDATE study_quests SET progress = ?, completed_at = ? WHERE user_id = ? AND quest_type = ? AND completed_at IS NULL',
          [nextProgress, completedAt, userId, type],
          function (questUpdateErr) {
            if (questUpdateErr) return res.status(500).json({ error: questUpdateErr.message });
            const questCompletedHere = completedAt !== null && this.changes > 0;
            const bonus = questCompletedHere ? Number(quest.rewardXp || 25) : 0;
            applyActivity(bonus);
          }
        );
      });
    });
  });
});

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

    const dbForms = rows.map(r => r.form_level);
    // Always include all standard forms, plus any extra from DB
    const merged = [...new Set([...STANDARD_FORMS, ...dbForms])];
    merged.sort();
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
  
      res.status(201).json({ id: this.lastID, name, icon, color, category, form_level });
    }
  );
});

// 2. Modules for a Subject
app.get('/api/subjects/:id/modules', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM modules WHERE subject_id = ?", [id], (err, rows) => {

    res.json(rows);
  });
});

// 3. Topics for a Module
app.get('/api/modules/:id/topics', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM topics WHERE module_id = ?", [id], (err, rows) => {

    res.json(rows);
  });
});

// 4. Users (Admin view)
app.get('/api/users', (req, res) => {
  db.all("SELECT * FROM users ORDER BY created_at DESC", [], (err, rows) => {

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


    db.all("SELECT t.id, t.name as title, 'topic' as type, s.name as subtitle, t.module_id FROM topics t JOIN modules m ON t.module_id = m.id JOIN subjects s ON m.subject_id = s.id WHERE t.name LIKE ?", [searchQuery], (err, topics) => {
  

      db.all("SELECT id, title, 'forum' as type, author as subtitle FROM posts WHERE title LIKE ? OR content LIKE ?", [searchQuery, searchQuery], (err, posts) => {
    

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

    res.json(rows || []);
  });
});

app.post('/api/notifications/token', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: "Token is required" });

  db.run("UPDATE users SET push_token = ? WHERE id = ?", [token, userId], function (err) {

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
app.post('/api/progress', authenticateToken, (req, res) => {
  const { topic_id, completed, score } = req.body;
  const user_id = req.user.id;
  if (!topic_id) {
    return res.status(400).json({ error: "topic_id is required" });
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
      db.run("UPDATE progress SET completed = CASE WHEN completed = 1 THEN 1 ELSE ? END, score = ? WHERE id = ?",
        [completedInt, scoreInt, row.id], (err) => {
      

          const finish = () => getStudyStats(user_id, (statsErr, stats) => {
            if (statsErr) return res.status(500).json({ error: statsErr.message });
            res.json({ success: true, message: "Progress updated", stats });
          });
          // Grant lesson XP only on the first transition to completed.
          if (completedInt === 1 && !wasCompleted) {
            db.run("UPDATE users SET level = FLOOR((xp + 50) / 500) + 1, xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id], (xpErr) => {
              if (xpErr) return res.status(500).json({ error: xpErr.message });
              finish();
            });
          } else {
            finish();
          }
        });
    } else {
      db.run("INSERT INTO progress (user_id, topic_id, completed, score) VALUES (?, ?, ?, ?)",
        [user_id, topic_id, completedInt, scoreInt], (err) => {
      

          const finish = () => getStudyStats(user_id, (statsErr, stats) => {
            if (statsErr) return res.status(500).json({ error: statsErr.message });
            res.json({ success: true, message: "Progress created", stats });
          });
          if (completedInt === 1) {
            db.run("UPDATE users SET level = FLOOR((xp + 50) / 500) + 1, xp = xp + 50, completed_lessons = completed_lessons + 1 WHERE id = ?", [user_id], (xpErr) => {
              if (xpErr) return res.status(500).json({ error: xpErr.message });
              finish();
            });
          } else {
            finish();
          }
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

    res.json(rows || []);
  });
});

app.get('/api/papers/:id', (req, res) => {
  db.get("SELECT * FROM papers WHERE id = ?", [req.params.id], (err, row) => {

    if (!row) return res.status(404).json({ error: "Paper not found" });
    res.json(row);
  });
});

app.post('/api/papers', authenticateToken, requireAdmin, (req, res) => {
  const { title, year, type, school, subject, content, form_level, pdf_url } = req.body;
  if (!title || (!String(content || '').trim() && !String(pdf_url || '').trim())) return res.status(400).json({ error: "Title and either paper text or a PDF are required" });
  db.run(
    "INSERT INTO papers (title, year, type, school, subject, content, form_level, pdf_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [title, year || '', type || 'National', school || '', subject || '', content || '', form_level || null, pdf_url || null],
    function (err) {
  
      res.status(201).json({ id: this.lastID, title, year, type, school, subject, form_level, pdf_url: pdf_url || null });
    }
  );
});

app.put('/api/papers/:id', authenticateToken, requireAdmin, (req, res) => {
  const { title, year, type, school, subject, content, form_level, pdf_url } = req.body;
  if (!title || (!String(content || '').trim() && !String(pdf_url || '').trim())) return res.status(400).json({ error: "Title and either paper text or a PDF are required" });
  db.run(
    "UPDATE papers SET title = ?, year = ?, type = ?, school = ?, subject = ?, content = ?, form_level = ?, pdf_url = ? WHERE id = ?",
    [title, year, type, school, subject, content || '', form_level || null, pdf_url || null, req.params.id],
    function (err) {
  
      res.json({ success: true, changes: this.changes });
    }
  );
});

app.delete('/api/papers/:id', authenticateToken, requireAdmin, (req, res) => {
  db.run("DELETE FROM papers WHERE id = ?", [req.params.id], function (err) {

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
  const age = Number(req.body.age);
  const guardianConsent = req.body.guardianConsent === true || req.body.guardian_consent === true;
  if (!Number.isInteger(age) || age < 13 || age > 100) {
    return res.status(400).json({ error: "SLIDE accounts are for students aged 13 and older. Enter a valid age." });
  }
  if (age < 18 && !guardianConsent) {
    return res.status(400).json({ error: "Parent or guardian permission is required for students under 18." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (name, email, password, role, school, class, location, age, guardian_consent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [name, email, hashedPassword, role || 'student', school || '', userClass || '', location || '', age, guardianConsent ? 1 : 0], function (err) {
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
          location: location || '',
          age,
          guardian_consent: guardianConsent ? 1 : 0
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
  
      res.json({ success: true });
    }
  );
});

// Profile (Protected)
app.get('/api/auth/profile', authenticateToken, (req, res) => {
  db.get("SELECT id, name, email, role, xp, level, school, class, location, study_hours, completed_lessons, is_science_major, streak, last_activity_date FROM users WHERE id = ?", [req.user.id], (err, user) => {

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
      
          res.json({ success: true });
        });
    } else {
      db.run("UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?",
        [name, email, role, id], function (err) {
      
          res.json({ success: true });
        });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM user_sync_data WHERE user_id = ?', [id], (syncErr) => {
    if (syncErr) return res.status(500).json({ error: syncErr.message });
    db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
  
      res.json({ success: true });
    });
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
  const { id } = req.params;
  db.run("DELETE FROM modules WHERE id = ?", [id], (err) => {

    res.json({ success: true });
  });
});

// Topics
app.get('/api/topics', (req, res) => {
  const query = `
    SELECT t.*, m.name as module_name, m.subject_id, s.name as subject_name
    FROM topics t
    LEFT JOIN modules m ON t.module_id = m.id
    LEFT JOIN subjects s ON m.subject_id = s.id
    ORDER BY t.id ASC
  `;
  db.all(query, [], (err, rows) => {

    res.json(rows || []);
  });
});
app.post('/api/topics', authenticateToken, (req, res) => {
  const { module_id, name, type, duration, content_url } = req.body;
  db.run("INSERT INTO topics (module_id, name, type, duration, content_url) VALUES (?, ?, ?, ?, ?)",
    [module_id, name, type || 'text', duration || '00:00', content_url || ''], function (err) {
  
      res.json({ id: this.lastID, success: true });
    });
});

app.delete('/api/topics/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM topics WHERE id = ?", [id], (err) => {

    res.json({ success: true });
  });
});

// 11. Delete Subject
app.delete('/api/subjects/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM subjects WHERE id = ?", [id], (err) => {

    res.json({ success: true });
  });
});

// 11. Transactions
app.get('/api/transactions', (req, res) => {
  db.all("SELECT * FROM transactions ORDER BY created_at DESC", [], (err, rows) => {

    res.json(rows);
  });
});

// 12. Real Dynamic Analytics
app.get('/api/analytics', (req, res) => {



  });

  const queryAsync = (sql, params = []) => new Promise((resolve) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        console.warn('[ANALYTICS_QUERY_WARN]', sql, err.message);
        resolve([]);
      } else {
        resolve(rows || []);
      }
    });
  });

  Promise.all([
    queryAsync("SELECT id, xp, streak, created_at, last_activity_date FROM users"),
    queryAsync("SELECT completed, score, last_accessed, topic_id, user_id FROM progress"),
    queryAsync("SELECT id, views, likes, created_at FROM posts"),
    queryAsync("SELECT id FROM comments"),
    queryAsync("SELECT id FROM questions"),
    queryAsync("SELECT id, name FROM subjects"),
    queryAsync(`
      SELECT p.last_accessed, u.name as user_name, t.name as topic_name, p.score, p.completed 
      FROM progress p 
      JOIN users u ON p.user_id = u.id 
      JOIN topics t ON p.topic_id = t.id 
      ORDER BY p.last_accessed DESC LIMIT 7
    `)
  ]).then(([users, progress, posts, comments, questions, subjects, recentActivity]) => {
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const activeUsersThisWeek = users.filter(u => {
      if (u.last_activity_date && new Date(u.last_activity_date) >= sevenDaysAgo) return true;
      if (u.created_at && new Date(u.created_at) >= sevenDaysAgo) return true;
      return false;
    }).length;

    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const dailyEngagement = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dateStr = d.toISOString().slice(0, 10);
      const dayName = days[d.getDay()];

      const count = progress.filter(p => p.last_accessed && String(p.last_accessed).slice(0, 10) === dateStr).length;
      dailyEngagement.push({
        date: dateStr,
        day: dayName,
        count: count
      });
    }

    const completedProgress = progress.filter(p => p.completed === 1 || p.completed === true);
    const scoredQuizzes = progress.filter(p => p.score > 0);
    const avgScore = scoredQuizzes.length > 0
      ? Math.round(scoredQuizzes.reduce((acc, p) => acc + Number(p.score || 0), 0) / scoredQuizzes.length)
      : 0;

    const totalViews = posts.reduce((acc, p) => acc + Number(p.views || 0), 0);
    const totalLikes = posts.reduce((acc, p) => acc + Number(p.likes || 0), 0);

    const metrics = [
      {
        metric_name: 'Total Students',
        value: users.length,
        change_text: `+${users.filter(u => u.created_at && new Date(u.created_at) >= sevenDaysAgo).length} joined this week`
      },
      {
        metric_name: 'Active Learners',
        value: Math.max(activeUsersThisWeek, 1),
        change_text: `${Math.round(((activeUsersThisWeek || 1) / Math.max(users.length, 1)) * 100)}% active rate`
      },
      {
        metric_name: 'Lessons & Quizzes Completed',
        value: completedProgress.length,
        change_text: `${progress.length} total attempts`
      },
      {
        metric_name: 'Forum Engagement',
        value: posts.length + comments.length,
        change_text: `${totalViews} views • ${totalLikes} likes`
      },
      {
        metric_name: 'Average Quiz Score',
        value: `${avgScore}%`,
        change_text: `${scoredQuizzes.length} quiz submissions`
      },
      {
        metric_name: 'Question Bank Size',
        value: questions.length,
        change_text: `${subjects.length} subjects covered`
      }
    ];

    res.json({
      metrics,
      dailyEngagement,
      engagement: dailyEngagement.map(d => d.count),
      recentActivity,
      summary: {
        totalUsers: users.length,
        activeThisWeek: activeUsersThisWeek,
        completedLessons: completedProgress.length,
        totalQuestions: questions.length,
        forumPosts: posts.length,
        forumComments: comments.length
      }
    });
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });





// 13. Tickets
app.get('/api/tickets', (req, res) => {
  db.all("SELECT * FROM tickets ORDER BY created_at DESC", [], (err, rows) => {

    res.json(rows);
  });
});

// 14. Reports
app.get('/api/reports', (req, res) => {
  db.all("SELECT * FROM reports ORDER BY created_at DESC", [], (err, rows) => {

    res.json(rows);
  });
});

// 15. Settings
app.get('/api/settings', (req, res) => {
  db.all("SELECT * FROM settings", [], (err, rows) => {

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

    res.json(rows);
  });
});

// --- APP ENDPOINTS ---



// 19. Quiz Questions & Management
const parseQuestionOptions = (options) => {
  if (!options) return [];
  if (Array.isArray(options)) return options;
  if (typeof options === 'string') {
    try {
      const parsed = JSON.parse(options);
      return Array.isArray(parsed) ? parsed : [options];
    } catch {
      if (options.includes(',')) {
        return options.split(',').map(s => s.trim());
      }
      return [options];
    }
  }
  return [];
};

// Get questions by topic (App & Web)
app.get('/api/topics/:id/questions', (req, res) => {
  const { id } = req.params;
  db.all("SELECT * FROM questions WHERE topic_id = ?", [id], (err, rows) => {

    const parsed = (rows || []).map(r => ({
      ...r,
      options: parseQuestionOptions(r.options)
    }));
    res.json(parsed);
  });
});

// Get all questions with filters for Admin Web
app.get('/api/questions', (req, res) => {
  const { topic_id, subject_id } = req.query;
  let query = `
    SELECT q.*, t.name as topic_name, s.name as subject_name
    FROM questions q
    LEFT JOIN topics t ON q.topic_id = t.id
    LEFT JOIN subjects s ON q.subject_id = s.id
  `;
  const params = [];
  if (topic_id) {
    query += ' WHERE q.topic_id = ?';
    params.push(topic_id);
  } else if (subject_id) {
    query += ' WHERE q.subject_id = ?';
    params.push(subject_id);
  }
  query += ' ORDER BY q.id DESC';

  db.all(query, params, (err, rows) => {

    const parsed = (rows || []).map(r => ({
      ...r,
      options: parseQuestionOptions(r.options)
    }));
    res.json(parsed);
  });
});

// Get single question by ID
app.get('/api/questions/:id', (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM questions WHERE id = ?", [id], (err, row) => {

    if (!row) return res.status(404).json({ error: "Question not found" });
    res.json({
      ...row,
      options: parseQuestionOptions(row.options)
    });
  });
});

// Create question (Admin & Contributors)
app.post('/api/questions', authenticateToken, (req, res) => {
  const { subject_id, topic_id, question_text, options, correct_answer, explanation } = req.body;
  if (!question_text) return res.status(400).json({ error: "Question text is required" });

  const serializedOptions = typeof options === 'object' ? JSON.stringify(options) : String(options || '[]');

  db.run("INSERT INTO questions (subject_id, topic_id, question_text, options, correct_answer, explanation) VALUES (?, ?, ?, ?, ?, ?)",
    [subject_id || null, topic_id || null, question_text, serializedOptions, correct_answer !== undefined ? String(correct_answer) : '0', explanation || ''], function (err) {
  
      res.json({ id: this.lastID, success: true });
    });
});

// Update question (Admin Web)
app.put('/api/questions/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { subject_id, topic_id, question_text, options, correct_answer, explanation } = req.body;

  const serializedOptions = typeof options === 'object' ? JSON.stringify(options) : String(options || '[]');

  db.run(
    "UPDATE questions SET subject_id = ?, topic_id = ?, question_text = ?, options = ?, correct_answer = ?, explanation = ? WHERE id = ?",
    [subject_id || null, topic_id || null, question_text, serializedOptions, correct_answer !== undefined ? String(correct_answer) : '0', explanation || '', id],
    function (err) {
  
      res.json({ success: true, updated: this.changes });
    }
  );
});

// Delete question
app.delete('/api/questions/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM questions WHERE id = ?", [id], (err) => {

    res.json({ success: true });
  });
});


// 21. Forum Management (Protected)
app.delete('/api/forum/posts/:id', authenticateToken, requireAdmin, (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM posts WHERE id = ?", [id], function (err) {

    if (!this.changes) return res.status(404).json({ error: 'Post not found.' });
    db.run("DELETE FROM forum_reports WHERE post_id = ?", [id], () => {});
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

    res.json(rows);
  });
});

app.post('/api/users/:id/mistakes', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { subject_id, question_id, user_answer } = req.body;
  db.run("INSERT INTO mistakes_log (user_id, subject_id, question_id, user_answer) VALUES (?, ?, ?, ?)",
    [id, subject_id, question_id, user_answer], function (err) {
  
      res.json({ id: this.lastID, success: true });
    });
});

// 21. Forum
app.get('/api/forum/posts', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  const category = req.query.category;
  const form_level = req.query.form_level;

  let conditions = ["COALESCE(p.moderation_status, 'active') = 'active'", 'COALESCE(u.forum_suspended, 0) = 0'];
  let params = [];

  if (category && category !== 'All') {
    conditions.push('p.category = ?');
    params.push(category);
  }

  if (form_level && form_level !== 'All') {
    conditions.push('(p.form_level = ? OR p.form_level IS NULL OR p.form_level = "")');
    params.push(form_level);
  }

  let query = 'SELECT p.* FROM posts p LEFT JOIN users u ON u.id = p.user_id';
  query += ' WHERE ' + conditions.join(' AND ');
  query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  db.all(query, params, (err, rows) => {

    res.json(rows);
  });
});

app.post('/api/forum/posts', authenticateToken, (req, res) => {
  const { title, content, category, form_level } = req.body;
  if (!title || !content) return res.status(400).json({ error: "Title and content are required" });

  db.get('SELECT forum_suspended FROM users WHERE id = ?', [req.user.id], (userErr, user) => {
    if (userErr) return res.status(500).json({ error: userErr.message });
    if (user?.forum_suspended) return res.status(403).json({ error: 'Your forum posting access is suspended.' });

  console.log(`[FORUM] Creating post: "${title}" by ${req.user.name} (${req.user.id})`);

  db.run("INSERT INTO posts (user_id, author_name, title, content, category, form_level) VALUES (?, ?, ?, ?, ?, ?)",
    [req.user.id, req.user.name || 'Anonymous', title, content, category || 'General', form_level || null], function (err) {
      if (err) {
        console.error("[FORUM] Database Error:", err.message);
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, success: true });
    });
  });
});

app.post('/api/forum/reports', authenticateToken, (req, res) => {
  const { target_type, post_id, target_user_id, reason, details } = req.body || {};
  const allowedReasons = ['spam', 'harassment', 'inappropriate', 'misinformation', 'other'];
  if (!['post', 'user'].includes(target_type) || !allowedReasons.includes(reason)) {
    return res.status(400).json({ error: 'Choose a valid report target and reason.' });
  }
  if (target_type === 'post' && !post_id) return res.status(400).json({ error: 'Post ID is required.' });
  if (target_type === 'user' && !target_user_id) return res.status(400).json({ error: 'User ID is required.' });
  if (target_type === 'user' && String(target_user_id) === String(req.user.id)) return res.status(400).json({ error: 'You cannot report your own account.' });
  const boundedDetails = typeof details === 'string' ? details.trim().slice(0, 1000) : '';

  const verifySql = target_type === 'post'
    ? 'SELECT id, user_id FROM posts WHERE id = ?'
    : 'SELECT id FROM users WHERE id = ?';
  const verifyId = target_type === 'post' ? post_id : target_user_id;
  db.get(verifySql, [verifyId], (lookupErr, target) => {
    if (lookupErr) return res.status(500).json({ error: lookupErr.message });
    if (!target) return res.status(404).json({ error: 'The reported content or account no longer exists.' });
    if (target_type === 'post' && String(target.user_id) === String(req.user.id)) return res.status(400).json({ error: 'You cannot report your own post.' });
    const resolvedPostId = target_type === 'post' ? post_id : null;
    const resolvedUserId = target_type === 'user' ? target_user_id : target.user_id;
    db.get("SELECT id FROM forum_reports WHERE reporter_id = ? AND target_type = ? AND COALESCE(post_id, 0) = COALESCE(?, 0) AND COALESCE(target_user_id, 0) = COALESCE(?, 0) AND status = 'open'", [req.user.id, target_type, resolvedPostId, resolvedUserId], (dupErr, existing) => {
      if (dupErr) return res.status(500).json({ error: dupErr.message });
      if (existing) return res.status(409).json({ error: 'You have already reported this item. It is in the moderation queue.' });
      db.run('INSERT INTO forum_reports (reporter_id, target_type, post_id, target_user_id, reason, details) VALUES (?, ?, ?, ?, ?, ?)',
        [req.user.id, target_type, resolvedPostId, resolvedUserId, reason, boundedDetails], function (insertErr) {
          if (insertErr) return res.status(500).json({ error: insertErr.message });
          res.status(201).json({ success: true, id: this.lastID, message: 'Report sent to the moderation team.' });
        });
    });
  });
});

app.get('/api/admin/forum/reports', authenticateToken, requireAdmin, (req, res) => {
  const status = ['open', 'resolved', 'dismissed'].includes(req.query.status) ? req.query.status : 'open';
  const query = `SELECT r.*, reporter.name AS reporter_name, target.name AS target_user_name,
      target.forum_suspended AS target_user_suspended,
      p.title AS post_title, p.content AS post_content, p.moderation_status AS post_status
    FROM forum_reports r
    LEFT JOIN users reporter ON reporter.id = r.reporter_id
    LEFT JOIN users target ON target.id = r.target_user_id
    LEFT JOIN posts p ON p.id = r.post_id
    WHERE r.status = ? ORDER BY r.created_at DESC LIMIT 200`;
  db.all(query, [status], (err, rows) => {

    res.json(rows || []);
  });
});

app.get('/api/admin/forum/suspended-users', authenticateToken, requireAdmin, (req, res) => {
  db.all('SELECT id, name, email FROM users WHERE forum_suspended = 1 ORDER BY name ASC', [], (err, rows) => {

    res.json(rows || []);
  });
});

app.patch('/api/admin/forum/users/:id/access', authenticateToken, requireAdmin, (req, res) => {
  const suspended = req.body?.suspended;
  if (typeof suspended !== 'boolean') return res.status(400).json({ error: 'suspended must be true or false.' });
  db.run('UPDATE users SET forum_suspended = ? WHERE id = ?', [suspended ? 1 : 0, req.params.id], function (err) {

    if (!this.changes) return res.status(404).json({ error: 'User not found.' });
    res.json({ success: true, suspended });
  });
});

app.patch('/api/admin/forum/reports/:id', authenticateToken, requireAdmin, (req, res) => {
  const { action, note } = req.body || {};
  const reportId = req.params.id;
  if (!['dismiss', 'resolve', 'hide_post', 'restore_post', 'remove_post', 'suspend_user', 'unsuspend_user'].includes(action)) {
    return res.status(400).json({ error: 'Unsupported moderation action.' });
  }
  db.get('SELECT * FROM forum_reports WHERE id = ?', [reportId], (lookupErr, report) => {
    if (lookupErr) return res.status(500).json({ error: lookupErr.message });
    if (!report) return res.status(404).json({ error: 'Report not found.' });
    const finish = (err) => {
  
      const status = action === 'dismiss' ? 'dismissed' : 'resolved';
      db.run('UPDATE forum_reports SET status = ?, moderator_id = ?, moderator_note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, req.user.id, typeof note === 'string' ? note.trim().slice(0, 1000) : '', reportId], function (updateErr) {
          if (updateErr) return res.status(500).json({ error: updateErr.message });
          res.json({ success: true, status, action });
        });
    };
    if (action === 'dismiss' || action === 'resolve') return finish(null);
    if (['hide_post', 'restore_post', 'remove_post'].includes(action)) {
      if (!report.post_id) return res.status(400).json({ error: 'This report is not linked to a post.' });
      if (action === 'remove_post') {
        return db.run('DELETE FROM posts WHERE id = ?', [report.post_id], function (err) {
      
          if (!this.changes) return res.status(404).json({ error: 'Post not found.' });
          db.run("UPDATE forum_reports SET status = 'resolved', moderator_id = ?, moderator_note = 'Post removed by moderator', updated_at = CURRENT_TIMESTAMP WHERE post_id = ? AND status = 'open'", [req.user.id, report.post_id], (reportErr) => {
            if (reportErr) return res.status(500).json({ error: reportErr.message });
            res.json({ success: true, status: 'resolved', action });
          });
        });
      }
      const moderationStatus = action === 'hide_post' ? 'hidden' : 'active';
      return db.run('UPDATE posts SET moderation_status = ? WHERE id = ?', [moderationStatus, report.post_id], function (err) {
    
        if (!this.changes) return res.status(404).json({ error: 'Post not found.' });
        finish(null);
      });
    }
    if (!report.target_user_id) return res.status(400).json({ error: 'This report is not linked to a user.' });
    const suspended = action === 'suspend_user' ? 1 : 0;
    db.run('UPDATE users SET forum_suspended = ? WHERE id = ?', [suspended, report.target_user_id], function (err) {
  
      if (!this.changes) return res.status(404).json({ error: 'User not found.' });
      finish(null);
    });
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
  
      res.json({ success: true, message: "Post liked" });
    });
  });
});

app.post('/api/forum/posts/:id/view', (req, res) => {
  const { id } = req.params;
  db.run("UPDATE posts SET views_count = views_count + 1 WHERE id = ?", [id], function (err) {

    res.json({ success: true });
  });
});

app.get('/api/forum/posts/:id/comments', (req, res) => {
  const { id } = req.params;
  db.all("SELECT c.* FROM comments c LEFT JOIN users u ON u.id = c.user_id WHERE c.post_id = ? AND COALESCE(u.forum_suspended, 0) = 0 ORDER BY c.created_at ASC", [id], (err, rows) => {

    res.json(rows);
  });
});

app.post('/api/forum/posts/:id/comments', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  if (typeof content !== 'string' || !content.trim() || content.length > 5000) return res.status(400).json({ error: 'Reply must be between 1 and 5000 characters.' });
  db.get('SELECT forum_suspended FROM users WHERE id = ?', [req.user.id], (userErr, user) => {
    if (userErr) return res.status(500).json({ error: userErr.message });
    if (user?.forum_suspended) return res.status(403).json({ error: 'Your forum posting access is suspended.' });
    db.get("SELECT p.id FROM posts p LEFT JOIN users u ON u.id = p.user_id WHERE p.id = ? AND COALESCE(p.moderation_status, 'active') = 'active' AND COALESCE(u.forum_suspended, 0) = 0", [id], (postErr, post) => {
      if (postErr) return res.status(500).json({ error: postErr.message });
      if (!post) return res.status(404).json({ error: 'This discussion is unavailable.' });
  db.run("INSERT INTO comments (post_id, user_id, author_name, content) VALUES (?, ?, ?, ?)",
    [id, req.user.id, req.user.name || 'Anonymous', content.trim()], function (err) {
  
      res.json({ id: this.lastID, success: true });
    });
    });
  });
});

// 22. Achievements
app.get('/api/achievements', (req, res) => {
  db.all("SELECT * FROM achievements", [], (err, rows) => {

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

    res.json(rows);
  });
});

app.post('/api/users/:id/achievements/:achievementId', authenticateToken, (req, res) => {
  const { id, achievementId } = req.params;
  db.run("INSERT OR IGNORE INTO user_achievements (user_id, achievement_id) VALUES (?, ?)",
    [id, achievementId], function (err) {
  
      res.json({ success: true });
    });
});

// 23. Flashcards
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
  
      res.status(201).json({ id: this.lastID, front, back, subject_id, difficulty, form_level });
    }
  );
});

app.delete('/api/flashcards/:id', authenticateToken, (req, res) => {
  db.run("DELETE FROM flashcards WHERE id = ?", [req.params.id], function (err) {

    res.json({ success: true, changes: this.changes });
  });
});

// 24. Community Contributions (Lessons, Summaries, Past Papers)
app.post('/api/contributions', authenticateToken, (req, res) => {
  const { title, type, subject, form_level, cover_image, images, content, status } = req.body;
  if (!title || !type || !subject) {
    return res.status(400).json({ error: "Title, type, and subject are required" });
  }

  const userId = req.user.id;
  const authorName = req.user.name || 'Contributor';
  const finalStatus = req.user.role === 'admin' ? 'approved' : (status || 'pending');
  const imagesStr = Array.isArray(images) ? JSON.stringify(images) : (images || '[]');

  db.run(
    `INSERT INTO contributions (title, type, subject, form_level, cover_image, images, content, status, author_id, author_name) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [title, type, subject, form_level || 'General', cover_image || null, imagesStr, content || '', finalStatus, userId, authorName],
    function (err) {
  
      res.status(201).json({
        id: this.lastID,
        title,
        type,
        subject,
        form_level,
        cover_image,
        images: Array.isArray(images) ? images : [],
        content,
        status: finalStatus,
        author_id: userId,
        author_name: authorName,
      });
    }
  );
});

app.get('/api/contributions', (req, res) => {
  const { form_level, subject, status } = req.query;
  let query = 'SELECT * FROM contributions WHERE 1=1';
  const params = [];

  if (status && status !== 'all') {
    query += ' AND status = ?';
    params.push(status);
  } else if (!status) {
    query += ' AND status = "approved"';
  }

  if (form_level && form_level !== 'All') {
    query += ' AND (form_level = ? OR form_level = "General" OR form_level IS NULL)';
    params.push(form_level);
  }

  if (subject) {
    query += ' AND (LOWER(subject) = LOWER(?) OR LOWER(subject) LIKE LOWER(?))';
    params.push(subject, `%${subject}%`);
  }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, rows) => {

    const formatted = (rows || []).map(r => {
      let parsedImages = [];
      try {
        parsedImages = typeof r.images === 'string' ? JSON.parse(r.images) : (r.images || []);
      } catch (e) {
        parsedImages = [];
      }
      return {
        ...r,
        images: parsedImages,
      };
    });
    res.json(formatted);
  });
});

app.patch('/api/contributions/:id/status', authenticateToken, (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: "Invalid status value" });
  }

  db.run("UPDATE contributions SET status = ? WHERE id = ?", [status, req.params.id], function (err) {

    res.json({ success: true, changes: this.changes });
  });
});

app.delete('/api/contributions/:id', authenticateToken, (req, res) => {
  db.run("DELETE FROM contributions WHERE id = ?", [req.params.id], function (err) {

    res.json({ success: true, changes: this.changes });
  });
});

// 25. Account Deletion Request
app.post('/api/auth/request-deletion', authenticateToken, (req, res) => {
  const { reason } = req.body;
  const userId = req.user.id;

  db.run(
    "INSERT INTO account_deletion_requests (user_id, reason) VALUES (?, ?)",
    [userId, reason || 'No reason provided'],
    function (err) {
  
      res.json({ success: true, message: "Deletion request scheduled for 24 hours" });
    }
  );
});

// Use Error Handler
app.use(errorHandler);

// Only listen if not being imported as a module (e.g. for Vercel)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
  });
}

module.exports = app;

