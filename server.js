const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const moment = require('moment-timezone');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('readin.db');

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'readin-concentration-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Initialize database
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        level INTEGER DEFAULT 3,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Training records table
    db.run(`CREATE TABLE IF NOT EXISTS training_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        actual_count INTEGER,
        user_answer INTEGER,
        is_correct BOOLEAN,
        level INTEGER,
        date TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Settings table
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )`);

    // Daily attempts table
    db.run(`CREATE TABLE IF NOT EXISTS daily_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        date TEXT,
        attempts INTEGER DEFAULT 0,
        bonus_attempts INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Create admin user if not exists
    db.get("SELECT * FROM users WHERE username = 'readin'", (err, row) => {
        if (!row) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                db.run("INSERT INTO users (username, password, is_admin, level) VALUES (?, ?, 1, 3)", 
                       ['readin', hash]);
            });
        }
    });

    // Initialize settings
    db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_signup', '0')");
    db.run("INSERT OR IGNORE INTO settings (key, value) VALUES ('allow_password_change', '1')");
});

// Helper functions
function getTodayKST() {
    return moment().tz('Asia/Seoul').format('YYYY-MM-DD');
}

function getDaysSinceStart() {
    const startDate = moment.tz('2024-01-01', 'Asia/Seoul');
    const today = moment().tz('Asia/Seoul');
    return today.diff(startDate, 'days');
}

function getDifficultyRange(level) {
    const days = getDaysSinceStart();
    
    switch(level) {
        case 1: // 초급
            const cycle1 = days % 3;
            const base1 = 10 + (cycle1 * 10);
            return { min: base1, max: base1 + 9 };
        
        case 2: // 중급
            const cycle2 = days % 6;
            const base2 = 10 + (cycle2 * 10);
            return { min: base2, max: base2 + 9 };
        
        case 3: // 기본
        default:
            const cycle3 = days % 16;
            const base3 = 30 + (cycle3 * 10);
            return { min: base3, max: base3 + 9 };
    }
}

function isCorrectAnswer(actual, answer) {
    return Math.abs(actual - answer) <= 1;
}

// Middleware to check authentication
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/');
    }
}

function requireAdmin(req, res, next) {
    if (req.session.userId && req.session.isAdmin) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}

// Routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        if (req.session.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        db.get("SELECT value FROM settings WHERE key = 'auto_signup'", (err, row) => {
            const autoSignup = row ? row.value === '1' : false;
            res.render('login', { error: null, autoSignup });
        });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (user) {
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.session.isAdmin = user.is_admin;
                    req.session.level = user.level;
                    
                    if (user.is_admin) {
                        res.redirect('/admin');
                    } else {
                        res.redirect('/dashboard');
                    }
                } else {
                    db.get("SELECT value FROM settings WHERE key = 'auto_signup'", (err, row) => {
                        const autoSignup = row ? row.value === '1' : false;
                        res.render('login', { error: '비밀번호가 올바르지 않습니다.', autoSignup });
                    });
                }
            });
        } else {
            // Check auto signup
            db.get("SELECT value FROM settings WHERE key = 'auto_signup'", (err, row) => {
                const autoSignup = row ? row.value === '1' : false;
                
                if (autoSignup && password === '123456') {
                    // Create new account
                    bcrypt.hash(password, 10, (err, hash) => {
                        db.run("INSERT INTO users (username, password, level) VALUES (?, ?, 3)", 
                               [username, hash], function(err) {
                            if (err) {
                                res.render('login', { error: '계정 생성에 실패했습니다.', autoSignup });
                            } else {
                                req.session.userId = this.lastID;
                                req.session.username = username;
                                req.session.isAdmin = false;
                                req.session.level = 3;
                                res.redirect('/dashboard');
                            }
                        });
                    });
                } else {
                    res.render('login', { error: '사용자를 찾을 수 없습니다.', autoSignup });
                }
            });
        }
    });
});

app.get('/dashboard', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    // Get today's attempts
    db.get("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?", 
           [userId, today], (err, attempts) => {
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        // Get user's training records
        db.all("SELECT * FROM training_records WHERE user_id = ? ORDER BY timestamp DESC", 
               [userId], (err, records) => {
            const difficultyRange = getDifficultyRange(req.session.level);
            
            res.render('dashboard', {
                username: req.session.username,
                remainingAttempts,
                records,
                difficultyRange
            });
        });
    });
});

app.get('/training', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    // Check remaining attempts
    db.get("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?", 
           [userId, today], (err, attempts) => {
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.redirect('/dashboard');
            return;
        }
        
        const difficultyRange = getDifficultyRange(req.session.level);
        const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
        
        res.render('training', {
            username: req.session.username,
            actualCount,
            level: req.session.level
        });
    });
});

app.post('/submit-answer', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.json({ success: false, message: '관리자는 훈련에 참여할 수 없습니다.' });
        return;
    }

    const { actualCount, userAnswer } = req.body;
    const today = getTodayKST();
    const userId = req.session.userId;
    
    // Check remaining attempts
    db.get("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?", 
           [userId, today], (err, attempts) => {
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
        const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        
        // Record the training
        db.run("INSERT INTO training_records (user_id, actual_count, user_answer, is_correct, level, date) VALUES (?, ?, ?, ?, ?, ?)",
               [userId, actualCount, userAnswer, isCorrect, req.session.level, today], (err) => {
            if (err) {
                res.json({ success: false, message: '기록 저장에 실패했습니다.' });
                return;
            }
            
            // Update daily attempts
            if (attempts) {
                db.run("UPDATE daily_attempts SET attempts = attempts + 1 WHERE user_id = ? AND date = ?",
                       [userId, today]);
            } else {
                db.run("INSERT INTO daily_attempts (user_id, date, attempts) VALUES (?, ?, 1)",
                       [userId, today]);
            }
            
            res.json({
                success: true,
                isCorrect,
                actualCount,
                userAnswer,
                remainingAttempts: remainingAttempts - 1
            });
        });
    });
});

app.get('/admin', requireAdmin, (req, res) => {
    // Get all participants
    db.all("SELECT id, username, level FROM users WHERE is_admin = 0 ORDER BY username COLLATE NOCASE",
           (err, users) => {
        db.all("SELECT key, value FROM settings", (err, settings) => {
            const settingsObj = {};
            settings.forEach(setting => {
                settingsObj[setting.key] = setting.value;
            });
            
            res.render('admin', {
                username: req.session.username,
                users,
                settings: settingsObj
            });
        });
    });
});

app.post('/admin/search', requireAdmin, (req, res) => {
    const { searchTerm } = req.body;
    
    db.all("SELECT id, username, level FROM users WHERE is_admin = 0 AND username LIKE ? ORDER BY username COLLATE NOCASE",
           [`%${searchTerm}%`], (err, users) => {
        res.json({ users });
    });
});

app.post('/admin/update-level', requireAdmin, (req, res) => {
    const { userId, level } = req.body;
    
    db.run("UPDATE users SET level = ? WHERE id = ?", [level, userId], (err) => {
        if (err) {
            res.json({ success: false, message: '레벨 업데이트에 실패했습니다.' });
        } else {
            res.json({ success: true });
        }
    });
});

app.post('/admin/bonus-attempt', requireAdmin, (req, res) => {
    const { userId } = req.body;
    const today = getTodayKST();
    
    db.get("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?", 
           [userId, today], (err, attempts) => {
        if (attempts) {
            db.run("UPDATE daily_attempts SET bonus_attempts = bonus_attempts + 1 WHERE user_id = ? AND date = ?",
                   [userId, today]);
        } else {
            db.run("INSERT INTO daily_attempts (user_id, date, bonus_attempts) VALUES (?, ?, 1)",
                   [userId, today]);
        }
        res.json({ success: true });
    });
});

app.post('/admin/toggle-setting', requireAdmin, (req, res) => {
    const { key } = req.body;
    
    db.get("SELECT value FROM settings WHERE key = ?", [key], (err, row) => {
        const newValue = row.value === '1' ? '0' : '1';
        db.run("UPDATE settings SET value = ? WHERE key = ?", [newValue, key], (err) => {
            if (err) {
                res.json({ success: false });
            } else {
                res.json({ success: true, newValue });
            }
        });
    });
});

app.get('/admin/records/:date', requireAdmin, (req, res) => {
    const date = req.params.date;
    
    db.all(`SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.date = ? 
            ORDER BY u.username COLLATE NOCASE, tr.timestamp`,
           [date], (err, records) => {
        res.json({ records });
    });
});

app.get('/change-password', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.render('change-password', { 
            username: req.session.username, 
            isAdmin: true,
            error: null 
        });
    } else {
        db.get("SELECT value FROM settings WHERE key = 'allow_password_change'", (err, row) => {
            const allowed = row ? row.value === '1' : true;
            if (allowed) {
                res.render('change-password', { 
                    username: req.session.username, 
                    isAdmin: false,
                    error: null 
                });
            } else {
                res.redirect('/dashboard');
            }
        });
    }
});

app.post('/change-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    db.get("SELECT password FROM users WHERE id = ?", [req.session.userId], (err, user) => {
        bcrypt.compare(currentPassword, user.password, (err, result) => {
            if (result) {
                bcrypt.hash(newPassword, 10, (err, hash) => {
                    db.run("UPDATE users SET password = ? WHERE id = ?", 
                           [hash, req.session.userId], (err) => {
                        if (err) {
                            res.render('change-password', { 
                                username: req.session.username, 
                                isAdmin: req.session.isAdmin,
                                error: '비밀번호 변경에 실패했습니다.' 
                            });
                        } else {
                            res.redirect(req.session.isAdmin ? '/admin' : '/dashboard');
                        }
                    });
                });
            } else {
                res.render('change-password', { 
                    username: req.session.username, 
                    isAdmin: req.session.isAdmin,
                    error: '현재 비밀번호가 올바르지 않습니다.' 
                });
            }
        });
    });
});

app.post('/admin/delete-user', requireAdmin, (req, res) => {
    const { userId } = req.body;
    
    // Delete related records first
    db.run("DELETE FROM training_records WHERE user_id = ?", [userId]);
    db.run("DELETE FROM daily_attempts WHERE user_id = ?", [userId]);
    db.run("DELETE FROM users WHERE id = ? AND is_admin = 0", [userId], (err) => {
        if (err) {
            res.json({ success: false, message: '사용자 삭제에 실패했습니다.' });
        } else {
            res.json({ success: true });
        }
    });
});

app.post('/admin/force-change-password', requireAdmin, (req, res) => {
    const { userId, newPassword } = req.body;
    
    bcrypt.hash(newPassword, 10, (err, hash) => {
        db.run("UPDATE users SET password = ? WHERE id = ? AND is_admin = 0", 
               [hash, userId], (err) => {
            if (err) {
                res.json({ success: false, message: '비밀번호 변경에 실패했습니다.' });
            } else {
                res.json({ success: true });
            }
        });
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
