const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// 데이터베이스 파일 경로 설정
const DB_PATH = path.join(__dirname, 'readin_database.db');

// 데이터베이스 백업 디렉토리 생성
const BACKUP_DIR = path.join(__dirname, 'db_backups');
if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    console.log('📁 데이터베이스 백업 폴더 생성됨:', BACKUP_DIR);
}

// Database setup with enhanced error handling
let db;
try {
    db = new sqlite3.Database(DB_PATH, (err) => {
        if (err) {
            console.error('❌ 데이터베이스 연결 실패:', err.message);
            process.exit(1);
        } else {
            console.log('✅ SQLite 데이터베이스 연결 성공:', DB_PATH);
        }
    });
} catch (error) {
    console.error('❌ 데이터베이스 초기화 실패:', error);
    process.exit(1);
}

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'readin-concentration-secret-key-v2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24시간
    }
}));

// 데이터베이스 백업 함수
function backupDatabase() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUP_DIR, `readin_backup_${timestamp}.db`);
    
    try {
        fs.copyFileSync(DB_PATH, backupPath);
        console.log('💾 데이터베이스 백업 완료:', backupPath);
        
        // 오래된 백업 파일 정리 (7일 이상된 파일 삭제)
        const files = fs.readdirSync(BACKUP_DIR);
        const weekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
        
        files.forEach(file => {
            const filePath = path.join(BACKUP_DIR, file);
            const stats = fs.statSync(filePath);
            if (stats.birthtime.getTime() < weekAgo) {
                fs.unlinkSync(filePath);
                console.log('🗑️ 오래된 백업 파일 삭제:', file);
            }
        });
    } catch (error) {
        console.error('❌ 데이터베이스 백업 실패:', error);
    }
}

// 강화된 데이터베이스 초기화
db.serialize(() => {
    console.log('🔧 데이터베이스 테이블 초기화 시작...');

    // Enable foreign keys
    db.run("PRAGMA foreign_keys = ON");
    
    // Users table - 사용자 정보
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        level INTEGER DEFAULT 3,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        status TEXT DEFAULT 'active' -- active, inactive, suspended
    )`, (err) => {
        if (err) {
            console.error('❌ users 테이블 생성 실패:', err);
        } else {
            console.log('✅ users 테이블 준비 완료');
        }
    });

    // Training records table - 훈련 기록
    db.run(`CREATE TABLE IF NOT EXISTS training_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        actual_count INTEGER NOT NULL,
        user_answer INTEGER NOT NULL,
        is_correct BOOLEAN NOT NULL,
        level INTEGER NOT NULL,
        date TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        session_duration INTEGER, -- 훈련 소요 시간 (초)
        difficulty_range TEXT, -- 난이도 범위 (예: "30-39")
        bpm INTEGER DEFAULT 100, -- 재생 속도
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('❌ training_records 테이블 생성 실패:', err);
        } else {
            console.log('✅ training_records 테이블 준비 완료');
        }
    });

    // Settings table - 시스템 설정
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT
    )`, (err) => {
        if (err) {
            console.error('❌ settings 테이블 생성 실패:', err);
        } else {
            console.log('✅ settings 테이블 준비 완료');
        }
    });

    // Daily attempts table - 일일 도전 기록
    db.run(`CREATE TABLE IF NOT EXISTS daily_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        bonus_attempts INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, date)
    )`, (err) => {
        if (err) {
            console.error('❌ daily_attempts 테이블 생성 실패:', err);
        } else {
            console.log('✅ daily_attempts 테이블 준비 완료');
        }
    });

    // System logs table - 시스템 로그
    db.run(`CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_type TEXT NOT NULL, -- login, logout, admin_action, error, etc.
        user_id INTEGER,
        message TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )`, (err) => {
        if (err) {
            console.error('❌ system_logs 테이블 생성 실패:', err);
        } else {
            console.log('✅ system_logs 테이블 준비 완료');
        }
    });

    // Password change history table - 비밀번호 변경 이력
    db.run(`CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        changed_by INTEGER, -- 누가 변경했는지 (관리자 강제 변경 시)
        change_type TEXT DEFAULT 'self', -- self, admin_force
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (changed_by) REFERENCES users (id) ON DELETE SET NULL
    )`, (err) => {
        if (err) {
            console.error('❌ password_history 테이블 생성 실패:', err);
        } else {
            console.log('✅ password_history 테이블 준비 완료');
        }
    });

    // 관리자 계정 생성
    db.get("SELECT * FROM users WHERE username = 'readin'", (err, row) => {
        if (!row) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                if (err) {
                    console.error('❌ 관리자 비밀번호 해시 실패:', err);
                    return;
                }
                db.run(`INSERT INTO users (username, password, is_admin, level, status) 
                        VALUES (?, ?, 1, 3, 'active')`, 
                       ['readin', hash], function(err) {
                    if (err) {
                        console.error('❌ 관리자 계정 생성 실패:', err);
                    } else {
                        console.log('👑 관리자 계정 생성 완료: readin / admin123');
                        
                        // 시스템 로그 기록
                        db.run(`INSERT INTO system_logs (log_type, user_id, message) 
                                VALUES ('system', ?, 'Admin account created')`, [this.lastID]);
                    }
                });
            });
        } else {
            console.log('👑 기존 관리자 계정 확인됨');
        }
    });

    // 기본 설정 초기화
    const defaultSettings = [
        ['auto_signup', '0', '자동 회원가입 허용 여부'],
        ['allow_password_change', '1', '참가자 비밀번호 변경 허용 여부'],
        ['max_daily_attempts', '2', '일일 기본 도전 횟수'],
        ['training_bpm', '100', '훈련 재생 속도 (BPM)'],
        ['difficulty_start_date', '2025-08-30', '난이도 시작 기준일'],
        ['system_maintenance', '0', '시스템 점검 모드']
    ];

    defaultSettings.forEach(([key, value, description]) => {
        db.run(`INSERT OR IGNORE INTO settings (key, value, description, updated_by) 
                VALUES (?, ?, ?, 'system')`, [key, value, description], (err) => {
            if (!err) {
                console.log(`⚙️ 기본 설정 초기화: ${key} = ${value}`);
            }
        });
    });

    console.log('🎉 데이터베이스 초기화 완료!');
    
    // 초기 백업 생성
    setTimeout(() => {
        backupDatabase();
    }, 1000);
});

// 시스템 로그 기록 함수
function logSystemEvent(logType, userId, message, req = null) {
    const ipAddress = req ? (req.ip || req.connection.remoteAddress) : null;
    const userAgent = req ? req.get('User-Agent') : null;
    
    db.run(`INSERT INTO system_logs (log_type, user_id, message, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?)`, 
           [logType, userId, message, ipAddress, userAgent], (err) => {
        if (err) {
            console.error('❌ 시스템 로그 기록 실패:', err);
        }
    });
}

// 사용자 업데이트 트리거 함수
function updateUserTimestamp(userId) {
    db.run("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [userId]);
}

// Helper functions - 8월 30일부터 시작, 내일 오전 9시부터 40-49
function getTodayKST() {
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000)); // UTC + 9시간
    return kstTime.toISOString().split('T')[0]; // YYYY-MM-DD
}

function getKSTTimestamp() {
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000)); // UTC + 9시간
    return kstTime.toISOString().replace('T', ' ').substring(0, 19); // YYYY-MM-DD HH:mm:ss
}

function getDaysSinceStart() {
    const startDate = new Date('2025-08-30T00:00:00Z'); // 8월 30일 UTC 기준 시작
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000)); // UTC + 9시간
    
    // KST 기준으로 오전 9시 이전이면 전날로 계산
    const kstHour = kstTime.getUTCHours();
    let adjustedKstTime = new Date(kstTime);
    if (kstHour < 9) {
        adjustedKstTime.setUTCDate(adjustedKstTime.getUTCDate() - 1);
    }
    
    const diffTime = adjustedKstTime.getTime() - startDate.getTime();
    return Math.max(0, Math.floor(diffTime / (1000 * 60 * 60 * 24)));
}

function getDifficultyRange(level) {
    const days = getDaysSinceStart();
    
    switch(level) {
        case 1: // 초급
            const cycle1 = days % 3;
            const base1 = 10 + (cycle1 * 10);
            return { min: base1, max: base1 + 9, range: `${base1}-${base1 + 9}` };
        
        case 2: // 중급
            const cycle2 = days % 6;
            const base2 = 10 + (cycle2 * 10);
            return { min: base2, max: base2 + 9, range: `${base2}-${base2 + 9}` };
        
        case 3: // 기본 - 오늘(8월 30일)은 30-39, 내일 오전 9시부터 40-49
        default:
            const base3 = 30 + (days * 10);
            return { min: base3, max: base3 + 9, range: `${base3}-${base3 + 9}` };
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
        logSystemEvent('unauthorized_access', req.session.userId, 
                      'Attempted to access admin panel without permission', req);
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
    
    db.get("SELECT * FROM users WHERE username = ? AND status = 'active'", [username], (err, user) => {
        if (user) {
            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.session.isAdmin = user.is_admin;
                    req.session.level = user.level;
                    
                    // 마지막 로그인 시간 업데이트
                    db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);
                    
                    // 로그인 로그 기록
                    logSystemEvent('login', user.id, `User logged in: ${username}`, req);
                    
                    if (user.is_admin) {
                        res.redirect('/admin');
                    } else {
                        res.redirect('/dashboard');
                    }
                } else {
                    logSystemEvent('login_failed', null, `Failed login attempt: ${username}`, req);
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
                        if (err) {
                            console.error('비밀번호 해시 실패:', err);
                            res.render('login', { error: '계정 생성에 실패했습니다.', autoSignup });
                            return;
                        }
                        
                        db.run("INSERT INTO users (username, password, level, status) VALUES (?, ?, 3, 'active')", 
                               [username, hash], function(err) {
                            if (err) {
                                console.error('사용자 생성 실패:', err);
                                res.render('login', { error: '계정 생성에 실패했습니다.', autoSignup });
                            } else {
                                req.session.userId = this.lastID;
                                req.session.username = username;
                                req.session.isAdmin = false;
                                req.session.level = 3;
                                
                                // 계정 생성 로그 기록
                                logSystemEvent('account_created', this.lastID, 
                                             `Auto-signup account created: ${username}`, req);
                                
                                res.redirect('/dashboard');
                            }
                        });
                    });
                } else {
                    logSystemEvent('login_failed', null, `User not found: ${username}`, req);
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
        db.all("SELECT * FROM training_records WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50", 
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
            logSystemEvent('training_blocked', userId, 'No remaining attempts for today');
            res.redirect('/dashboard');
            return;
        }
        
        const difficultyRange = getDifficultyRange(req.session.level);
        const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
        
        // 훈련 시작 로그
        logSystemEvent('training_started', userId, 
                      `Training started - Level: ${req.session.level}, Range: ${difficultyRange.range}, Count: ${actualCount}`);
        
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
    const kstTimestamp = getKSTTimestamp();
    const difficultyRange = getDifficultyRange(req.session.level);
    
    // Check remaining attempts
    db.get("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?", 
           [userId, today], (err, attempts) => {
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            logSystemEvent('training_blocked', userId, 'Attempted training without remaining attempts');
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
        const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        
        // Record the training with enhanced data
        db.run(`INSERT INTO training_records 
                (user_id, actual_count, user_answer, is_correct, level, date, timestamp, 
                 difficulty_range, bpm) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
               [userId, actualCount, userAnswer, isCorrect, req.session.level, today, 
                kstTimestamp, difficultyRange.range, 100], 
               function(err) {
            if (err) {
                console.error('훈련 기록 저장 실패:', err);
                logSystemEvent('error', userId, `Training record save failed: ${err.message}`);
                res.json({ success: false, message: '기록 저장에 실패했습니다.' });
                return;
            }
            
            // Update daily attempts
            if (attempts) {
                db.run(`UPDATE daily_attempts SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP 
                        WHERE user_id = ? AND date = ?`, [userId, today]);
            } else {
                db.run(`INSERT INTO daily_attempts (user_id, date, attempts) VALUES (?, ?, 1)`,
                       [userId, today]);
            }
            
            // 훈련 완료 로그
            logSystemEvent('training_completed', userId, 
                          `Training completed - Actual: ${actualCount}, Answer: ${userAnswer}, Correct: ${isCorrect}`);
            
            // 사용자 업데이트 시간 갱신
            updateUserTimestamp(userId);
            
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

// 관리자 관련 라우트들은 동일하지만 로깅 추가...
app.get('/admin', requireAdmin, (req, res) => {
    // Get all participants
    db.all("SELECT id, username, level, created_at, last_login, status FROM users WHERE is_admin = 0 ORDER BY username COLLATE NOCASE",
           (err, users) => {
        db.all("SELECT key, value, description FROM settings ORDER BY key", (err, settings) => {
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
    
    db.all(`SELECT id, username, level, created_at, last_login, status 
            FROM users WHERE is_admin = 0 AND username LIKE ? 
            ORDER BY username COLLATE NOCASE`,
           [`%${searchTerm}%`], (err, users) => {
        res.json({ users });
    });
});

app.post('/admin/update-level', requireAdmin, (req, res) => {
    const { userId, level } = req.body;
    
    db.run("UPDATE users SET level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", 
           [level, userId], (err) => {
        if (err) {
            logSystemEvent('error', req.session.userId, `Level update failed for user ${userId}: ${err.message}`);
            res.json({ success: false, message: '레벨 업데이트에 실패했습니다.' });
        } else {
            logSystemEvent('admin_action', req.session.userId, `Updated user ${userId} level to ${level}`);
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
            db.run(`UPDATE daily_attempts SET bonus_attempts = bonus_attempts + 1, 
                    updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND date = ?`,
                   [userId, today]);
        } else {
            db.run("INSERT INTO daily_attempts (user_id, date, bonus_attempts) VALUES (?, ?, 1)",
                   [userId, today]);
        }
        
        logSystemEvent('admin_action', req.session.userId, `Granted bonus attempt to user ${userId}`);
        res.json({ success: true });
    });
});

app.post('/admin/toggle-setting', requireAdmin, (req, res) => {
    const { key } = req.body;
    
    db.get("SELECT value FROM settings WHERE key = ?", [key], (err, row) => {
        const newValue = row.value === '1' ? '0' : '1';
        db.run(`UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? 
                WHERE key = ?`, [newValue, req.session.username, key], (err) => {
            if (err) {
                logSystemEvent('error', req.session.userId, `Setting toggle failed for ${key}: ${err.message}`);
                res.json({ success: false });
            } else {
                logSystemEvent('admin_action', req.session.userId, `Toggled setting ${key} to ${newValue}`);
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
        if (err) {
            logSystemEvent('error', req.session.userId, `Records query failed for date ${date}: ${err.message}`);
        }
        res.json({ records: records || [] });
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
                    db.run("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", 
                           [hash, req.session.userId], (err) => {
                        if (err) {
                            logSystemEvent('error', req.session.userId, `Password change failed: ${err.message}`);
                            res.render('change-password', { 
                                username: req.session.username, 
                                isAdmin: req.session.isAdmin,
                                error: '비밀번호 변경에 실패했습니다.' 
                            });
                        } else {
                            // 비밀번호 변경 이력 기록
                            db.run("INSERT INTO password_history (user_id, change_type) VALUES (?, 'self')",
                                   [req.session.userId]);
                            
                            logSystemEvent('password_changed', req.session.userId, 'User changed own password');
                            res.redirect(req.session.isAdmin ? '/admin' : '/dashboard');
                        }
                    });
                });
            } else {
                logSystemEvent('password_change_failed', req.session.userId, 'Incorrect current password');
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
    
    // 사용자 정보 조회 후 삭제
    db.get("SELECT username FROM users WHERE id = ? AND is_admin = 0", [userId], (err, user) => {
        if (!user) {
            res.json({ success: false, message: '사용자를 찾을 수 없습니다.' });
            return;
        }
        
        // 관련 데이터 삭제 (Foreign Key Cascade로 자동 처리되지만 명시적으로)
        db.serialize(() => {
            db.run("DELETE FROM training_records WHERE user_id = ?", [userId]);
            db.run("DELETE FROM daily_attempts WHERE user_id = ?", [userId]);
            db.run("DELETE FROM password_history WHERE user_id = ?", [userId]);
            db.run("DELETE FROM users WHERE id = ? AND is_admin = 0", [userId], (err) => {
                if (err) {
                    logSystemEvent('error', req.session.userId, 
                                  `User deletion failed for ${user.username}: ${err.message}`);
                    res.json({ success: false, message: '사용자 삭제에 실패했습니다.' });
                } else {
                    logSystemEvent('admin_action', req.session.userId, 
                                  `Deleted user: ${user.username} (ID: ${userId})`);
                    res.json({ success: true });
                }
            });
        });
    });
});

app.post('/admin/force-change-password', requireAdmin, (req, res) => {
    const { userId, newPassword } = req.body;
    
    bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) {
            logSystemEvent('error', req.session.userId, `Password hash failed: ${err.message}`);
            res.json({ success: false, message: '비밀번호 암호화에 실패했습니다.' });
            return;
        }
        
        db.run("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_admin = 0", 
               [hash, userId], (err) => {
            if (err) {
                logSystemEvent('error', req.session.userId, 
                              `Force password change failed for user ${userId}: ${err.message}`);
                res.json({ success: false, message: '비밀번호 변경에 실패했습니다.' });
            } else {
                // 강제 비밀번호 변경 이력 기록
                db.run("INSERT INTO password_history (user_id, changed_by, change_type) VALUES (?, ?, 'admin_force')",
                       [userId, req.session.userId]);
                
                logSystemEvent('admin_action', req.session.userId, 
                              `Force changed password for user ID: ${userId}`);
                res.json({ success: true });
            }
        });
    });
});

app.get('/logout', (req, res) => {
    const userId = req.session.userId;
    const username = req.session.username;
    
    if (userId) {
        logSystemEvent('logout', userId, `User logged out: ${username}`);
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('세션 삭제 실패:', err);
        }
        res.redirect('/');
    });
});

// 데이터베이스 백업 API (관리자 전용)
app.post('/admin/backup-database', requireAdmin, (req, res) => {
    try {
        backupDatabase();
        logSystemEvent('admin_action', req.session.userId, 'Manual database backup created');
        res.json({ success: true, message: '데이터베이스 백업이 완료되었습니다.' });
    } catch (error) {
        logSystemEvent('error', req.session.userId, `Database backup failed: ${error.message}`);
        res.json({ success: false, message: '백업 생성에 실패했습니다.' });
    }
});

// 시스템 로그 조회 API (관리자 전용)
app.get('/admin/system-logs', requireAdmin, (req, res) => {
    const limit = req.query.limit || 100;
    const logType = req.query.type || '';
    
    let query = `SELECT sl.*, u.username 
                 FROM system_logs sl 
                 LEFT JOIN users u ON sl.user_id = u.id `;
    let params = [];
    
    if (logType) {
        query += ' WHERE sl.log_type = ? ';
        params.push(logType);
    }
    
    query += ' ORDER BY sl.timestamp DESC LIMIT ?';
    params.push(parseInt(limit));
    
    db.all(query, params, (err, logs) => {
        if (err) {
            logSystemEvent('error', req.session.userId, `System logs query failed: ${err.message}`);
            res.json({ success: false, logs: [] });
        } else {
            res.json({ success: true, logs });
        }
    });
});

// 에러 핸들링 미들웨어
app.use((err, req, res, next) => {
    console.error('서버 에러:', err);
    logSystemEvent('error', req.session?.userId, `Server error: ${err.message}`);
    res.status(500).send('서버 내부 오류가 발생했습니다.');
});

// 404 에러 핸들링
app.use((req, res) => {
    logSystemEvent('error', req.session?.userId, `404 Not Found: ${req.url}`);
    res.status(404).send('페이지를 찾을 수 없습니다.');
});

// 정기적인 데이터베이스 백업 (매일 자정)
setInterval(() => {
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    const hour = kstTime.getUTCHours();
    const minute = kstTime.getUTCMinutes();
    
    // 매일 KST 자정 (UTC 15:00)에 백업
    if (hour === 15 && minute === 0) {
        console.log('📅 정기 데이터베이스 백업 실행...');
        backupDatabase();
        logSystemEvent('system', null, 'Scheduled database backup completed');
    }
}, 60000); // 1분마다 체크

// 종료 시 데이터베이스 정리
process.on('SIGINT', () => {
    console.log('\n🛑 서버 종료 중...');
    logSystemEvent('system', null, 'Server shutdown initiated');
    
    // 최종 백업
    backupDatabase();
    
    db.close((err) => {
        if (err) {
            console.error('❌ 데이터베이스 종료 실패:', err.message);
        } else {
            console.log('✅ 데이터베이스 연결 종료됨');
        }
        process.exit(0);
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 === READIN 집중력 훈련 서버 시작 === 🚀`);
    console.log(`📡 서버 포트: ${PORT}`);
    console.log(`🕐 현재 KST 시간: ${getKSTTimestamp()}`);
    console.log(`📅 오늘 날짜 (KST): ${getTodayKST()}`);
    
    const days = getDaysSinceStart();
    const range = getDifficultyRange(3);
    console.log(`📊 8월 30일부터 경과일: ${days}일`);
    console.log(`🎯 현재 기본 레벨 난이도: ${range.range}`);
    console.log(`💾 데이터베이스 파일: ${DB_PATH}`);
    console.log(`📁 백업 폴더: ${BACKUP_DIR}`);
    
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    const kstHour = kstTime.getUTCHours();
    
    if (days === 0) {
        console.log(`✅ 오늘(8월 30일): 30-39 범위`);
    } else if (days === 1) {
        console.log(`✅ 내일: 40-49 범위로 변경됨`);
    }
    
    console.log(`👑 관리자 계정: readin / admin123`);
    console.log(`🎵 소리 재생 속도: 100 BPM`);
    console.log(`🔒 모든 데이터가 영구적으로 저장됩니다`);
    console.log(`===============================================\n`);
    
    // 서버 시작 로그 기록
    logSystemEvent('system', null, `Server started on port ${PORT}`);
});
