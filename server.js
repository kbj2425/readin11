const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// SQLite 데이터베이스 연결
const db = new Database('readin.db');
db.pragma('journal_mode = WAL');

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'readin-concentration-secret-key-v2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// 데이터베이스 초기화
function initializeDatabase() {
    try {
        console.log('🔧 SQLite 테이블 초기화 시작...');

        // Users table
        db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                level INTEGER DEFAULT 3,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                status TEXT DEFAULT 'active'
            )
        `);

        // Training records table
        db.exec(`
            CREATE TABLE IF NOT EXISTS training_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                actual_count INTEGER NOT NULL,
                user_answer INTEGER NOT NULL,
                is_correct INTEGER NOT NULL,
                level INTEGER NOT NULL,
                date TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                difficulty_range TEXT,
                bpm INTEGER DEFAULT 100,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Settings table
        db.exec(`
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT
            )
        `);

        // Daily attempts table
        db.exec(`
            CREATE TABLE IF NOT EXISTS daily_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                date TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                bonus_attempts INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, date),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // 관리자 계정 생성
        const adminCheck = db.prepare("SELECT * FROM users WHERE username = ?").get('readin');
        if (!adminCheck) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.prepare(`
                INSERT INTO users (username, password, is_admin, level, status) 
                VALUES (?, ?, 1, 3, 'active')
            `).run('readin', hash);
            console.log('👑 관리자 계정 생성 완료: readin / admin123');
        }

        // 기본 설정 초기화
        const defaultSettings = [
            ['auto_signup', '0', '자동 회원가입 허용 여부'],
            ['allow_password_change', '1', '참가자 비밀번호 변경 허용 여부'],
            ['show_visual_feedback', '1', '훈련 중 시각적 피드백 표시 여부']
        ];

        const insertSetting = db.prepare(`
            INSERT OR IGNORE INTO settings (key, value, description, updated_by) 
            VALUES (?, ?, ?, 'system')
        `);

        for (const [key, value, description] of defaultSettings) {
            insertSetting.run(key, value, description);
        }

        console.log('🎉 SQLite 데이터베이스 초기화 완료!');
    } catch (error) {
        console.error('❌ 데이터베이스 초기화 실패:', error);
        process.exit(1);
    }
}

// Helper functions
function getTodayKST() {
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    return kstTime.toISOString().split('T')[0];
}

function getKSTTimestamp() {
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    return kstTime.toISOString().replace('T', ' ').substring(0, 19);
}

function getDaysSinceStart() {
    const startDate = new Date('2025-08-30T00:00:00Z');
    const now = new Date();
    const kstTime = new Date(now.getTime() + (9 * 60 * 60 * 1000));
    
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
        case 1:
            const cycle1 = days % 3;
            const base1 = 10 + (cycle1 * 10);
            return { min: base1, max: base1 + 9, range: `${base1}-${base1 + 9}` };
        
        case 2:
            const cycle2 = days % 6;
            const base2 = 10 + (cycle2 * 10);
            return { min: base2, max: base2 + 9, range: `${base2}-${base2 + 9}` };
        
        case 3:
        default:
            const cycle3 = days % 16;
            const base3 = 30 + (cycle3 * 10);
            return { min: base3, max: base3 + 9, range: `${base3}-${base3 + 9}` };
    }
}

function isCorrectAnswer(actual, answer) {
    return Math.abs(actual - answer) <= 1;
}

// Middleware
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

// Health check route
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: getKSTTimestamp(),
        uptime: process.uptime()
    });
});

// Routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        if (req.session.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        try {
            const result = db.prepare("SELECT value FROM settings WHERE key = ?").get('auto_signup');
            const autoSignup = result ? result.value === '1' : false;
            res.render('login', { error: null, autoSignup });
        } catch (error) {
            console.error('설정 조회 오류:', error);
            res.render('login', { error: null, autoSignup: false });
        }
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = db.prepare("SELECT * FROM users WHERE username = ? AND status = 'active'").get(username);
        
        if (user) {
            const isValid = bcrypt.compareSync(password, user.password);
            if (isValid) {
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.isAdmin = user.is_admin === 1;
                req.session.level = user.level;
                
                db.prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?").run(user.id);
                
                if (user.is_admin === 1) {
                    res.redirect('/admin');
                } else {
                    res.redirect('/dashboard');
                }
            } else {
                const settingsResult = db.prepare("SELECT value FROM settings WHERE key = ?").get('auto_signup');
                const autoSignup = settingsResult ? settingsResult.value === '1' : false;
                res.render('login', { error: '비밀번호가 올바르지 않습니다.', autoSignup });
            }
        } else {
            const settingsResult = db.prepare("SELECT value FROM settings WHERE key = ?").get('auto_signup');
            const autoSignup = settingsResult ? settingsResult.value === '1' : false;
            
            if (autoSignup && password === '123456') {
                const hash = bcrypt.hashSync(password, 10);
                const info = db.prepare(`
                    INSERT INTO users (username, password, level, status) 
                    VALUES (?, ?, 3, 'active')
                `).run(username, hash);
                
                req.session.userId = info.lastInsertRowid;
                req.session.username = username;
                req.session.isAdmin = false;
                req.session.level = 3;
                
                res.redirect('/dashboard');
            } else {
                res.render('login', { error: '사용자를 찾을 수 없습니다.', autoSignup });
            }
        }
    } catch (error) {
        console.error('로그인 오류:', error);
        res.render('login', { error: '서버 오류가 발생했습니다.', autoSignup: false });
    }
});

app.get('/dashboard', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    try {
        const attempts = db.prepare("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?").get(userId, today);
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        const records = db.prepare("SELECT * FROM training_records WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50").all(userId);
        const difficultyRange = getDifficultyRange(req.session.level);
        
        res.render('dashboard', {
            username: req.session.username,
            remainingAttempts,
            records,
            difficultyRange
        });
    } catch (error) {
        console.error('대시보드 로딩 오류:', error);
        res.status(500).send('서버 오류가 발생했습니다.');
    }
});

app.get('/training', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    try {
        const attempts = db.prepare("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?").get(userId, today);
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.redirect('/dashboard');
            return;
        }
        
        const difficultyRange = getDifficultyRange(req.session.level);
        const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
        
        const visualFeedbackResult = db.prepare("SELECT value FROM settings WHERE key = ?").get('show_visual_feedback');
        const showVisualFeedback = visualFeedbackResult ? visualFeedbackResult.value === '1' : true;
        
        res.render('training', {
            username: req.session.username,
            actualCount,
            level: req.session.level,
            showVisualFeedback
        });
    } catch (error) {
        console.error('훈련 페이지 로딩 오류:', error);
        res.status(500).send('서버 오류가 발생했습니다.');
    }
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
    
    try {
        const attempts = db.prepare("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?").get(userId, today);
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
        const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        
        db.prepare(`
            INSERT INTO training_records (user_id, actual_count, user_answer, is_correct, level, date, timestamp, difficulty_range, bpm) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 100)
        `).run(userId, actualCount, userAnswer, isCorrect ? 1 : 0, req.session.level, today, kstTimestamp, difficultyRange.range);
        
        if (attempts) {
            db.prepare("UPDATE daily_attempts SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND date = ?").run(userId, today);
        } else {
            db.prepare("INSERT INTO daily_attempts (user_id, date, attempts) VALUES (?, ?, 1)").run(userId, today);
        }
        
        res.json({
            success: true,
            isCorrect,
            actualCount,
            userAnswer,
            remainingAttempts: remainingAttempts - 1
        });
    } catch (error) {
        console.error('훈련 답변 제출 오류:', error);
        res.json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

app.get('/admin', requireAdmin, (req, res) => {
    try {
        const users = db.prepare("SELECT id, username, level, created_at, last_login, status FROM users WHERE is_admin = 0 ORDER BY username").all();
        const settings = db.prepare("SELECT key, value, description FROM settings ORDER BY key").all();
        
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.key] = setting.value;
        });
        
        res.render('admin', {
            username: req.session.username,
            users,
            settings: settingsObj
        });
    } catch (error) {
        console.error('관리자 페이지 로딩 오류:', error);
        res.status(500).send('서버 오류가 발생했습니다.');
    }
});

app.post('/admin/search', requireAdmin, (req, res) => {
    const { searchTerm } = req.body;
    try {
        const users = db.prepare("SELECT id, username, level, created_at, last_login, status FROM users WHERE is_admin = 0 AND username LIKE ? ORDER BY username").all(`%${searchTerm}%`);
        res.json({ users });
    } catch (error) {
        console.error('사용자 검색 오류:', error);
        res.json({ users: [] });
    }
});

app.post('/admin/update-level', requireAdmin, (req, res) => {
    const { userId, level } = req.body;
    try {
        db.prepare("UPDATE users SET level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(level, userId);
        res.json({ success: true });
    } catch (error) {
        console.error('레벨 업데이트 오류:', error);
        res.json({ success: false, message: '레벨 업데이트에 실패했습니다.' });
    }
});

app.post('/admin/bonus-attempt', requireAdmin, (req, res) => {
    const { userId } = req.body;
    const today = getTodayKST();
    
    try {
        const attempts = db.prepare("SELECT * FROM daily_attempts WHERE user_id = ? AND date = ?").get(userId, today);
        
        if (attempts) {
            db.prepare("UPDATE daily_attempts SET bonus_attempts = bonus_attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND date = ?").run(userId, today);
        } else {
            db.prepare("INSERT INTO daily_attempts (user_id, date, bonus_attempts) VALUES (?, ?, 1)").run(userId, today);
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('보너스 기회 부여 오류:', error);
        res.json({ success: false, message: '보너스 기회 부여에 실패했습니다.' });
    }
});

app.post('/admin/toggle-setting', requireAdmin, (req, res) => {
    const { key } = req.body;
    try {
        const result = db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
        const currentValue = result ? result.value : '0';
        const newValue = currentValue === '1' ? '0' : '1';
        
        db.prepare("UPDATE settings SET value = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE key = ?").run(newValue, req.session.username, key);
        res.json({ success: true, newValue });
    } catch (error) {
        console.error('설정 토글 오류:', error);
        res.json({ success: false });
    }
});

app.get('/admin/records/:date', requireAdmin, (req, res) => {
    const date = req.params.date;
    const searchUser = req.query.user || '';
    
    try {
        let query = `
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.date = ?
        `;
        let params = [date];
        
        if (searchUser) {
            query += ' AND u.username LIKE ? ';
            params.push(`%${searchUser}%`);
        }
        
        query += ' ORDER BY u.username, tr.timestamp';
        
        const records = db.prepare(query).all(...params);
        res.json({ records });
    } catch (error) {
        console.error('기록 조회 오류:', error);
        res.json({ records: [] });
    }
});

app.get('/admin/user-records/:userId', requireAdmin, (req, res) => {
    const userId = req.params.userId;
    
    try {
        const records = db.prepare(`
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.user_id = ?
            ORDER BY tr.timestamp DESC
        `).all(userId);
        
        res.json({ 
            success: true, 
            records,
            totalRecords: records.length
        });
    } catch (error) {
        console.error('학생별 기록 조회 오류:', error);
        res.json({ success: false, records: [], totalRecords: 0 });
    }
});

app.get('/admin/user-stats/:userId', requireAdmin, (req, res) => {
    const userId = req.params.userId;
    
    try {
        const totalResult = db.prepare("SELECT COUNT(*) as total FROM training_records WHERE user_id = ?").get(userId);
        const correctResult = db.prepare("SELECT COUNT(*) as correct FROM training_records WHERE user_id = ? AND is_correct = 1").get(userId);
        const recentResult = db.prepare(`
            SELECT COUNT(*) as recent 
            FROM training_records 
            WHERE user_id = ? AND date >= ?
        `).get(userId, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]);
        
        const total = totalResult.total;
        const correct = correctResult.correct;
        const recent = recentResult.recent;
        
        res.json({
            success: true,
            stats: {
                totalAttempts: total,
                correctAnswers: correct,
                accuracy: total > 0 ? Math.round((correct / total) * 100) : 0,
                recentWeek: recent
            }
        });
    } catch (error) {
        console.error('학생 통계 조회 오류:', error);
        res.json({ success: false, stats: null });
    }
});

app.get('/admin/user-all-records/:userId', requireAdmin, (req, res) => {
    const userId = req.params.userId;
    
    try {
        const records = db.prepare(`
            SELECT 
                date,
                level,
                difficulty_range,
                COUNT(*) as daily_attempts,
                SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
                ROUND(AVG(actual_count)) as avg_actual_count
            FROM training_records 
            WHERE user_id = ?
            GROUP BY date, level, difficulty_range
            ORDER BY date DESC
        `).all(userId);
        
        const dailyRecords = records.map(record => {
            const details = db.prepare(`
                SELECT id, actual_count, user_answer, is_correct, timestamp
                FROM training_records
                WHERE user_id = ? AND date = ?
                ORDER BY timestamp
            `).all(userId, record.date);
            
            return {
                ...record,
                records: details
            };
        });
        
        res.json({ 
            success: true, 
            dailyRecords
        });
    } catch (error) {
        console.error('전체 기록 조회 오류:', error);
        res.json({ success: false, dailyRecords: [] });
    }
});

app.get('/change-password', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.render('change-password', { 
            username: req.session.username, 
            isAdmin: true,
            error: null 
        });
    } else {
        try {
            const result = db.prepare("SELECT value FROM settings WHERE key = ?").get('allow_password_change');
            const allowed = result ? result.value === '1' : true;
            if (allowed) {
                res.render('change-password', { 
                    username: req.session.username, 
                    isAdmin: false,
                    error: null 
                });
            } else {
                res.redirect('/dashboard');
            }
        } catch (error) {
            console.error('비밀번호 변경 페이지 로딩 오류:', error);
            res.redirect('/dashboard');
        }
    }
});

app.post('/change-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    try {
        const user = db.prepare("SELECT password FROM users WHERE id = ?").get(req.session.userId);
        
        const isValid = bcrypt.compareSync(currentPassword, user.password);
        if (isValid) {
            const hash = bcrypt.hashSync(newPassword, 10);
            db.prepare("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(hash, req.session.userId);
            res.redirect(req.session.isAdmin ? '/admin' : '/dashboard');
        } else {
            res.render('change-password', { 
                username: req.session.username, 
                isAdmin: req.session.isAdmin,
                error: '현재 비밀번호가 올바르지 않습니다.' 
            });
        }
    } catch (error) {
        console.error('비밀번호 변경 오류:', error);
        res.render('change-password', { 
            username: req.session.username, 
            isAdmin: req.session.isAdmin,
            error: '비밀번호 변경에 실패했습니다.' 
        });
    }
});

app.post('/admin/delete-user', requireAdmin, (req, res) => {
    const { userId } = req.body;
    
    try {
        const user = db.prepare("SELECT username FROM users WHERE id = ? AND is_admin = 0").get(userId);
        if (!user) {
            res.json({ success: false, message: '사용자를 찾을 수 없습니다.' });
            return;
        }
        
        db.prepare("DELETE FROM training_records WHERE user_id = ?").run(userId);
        db.prepare("DELETE FROM daily_attempts WHERE user_id = ?").run(userId);
        db.prepare("DELETE FROM users WHERE id = ? AND is_admin = 0").run(userId);
        
        res.json({ success: true });
    } catch (error) {
        console.error('사용자 삭제 오류:', error);
        res.json({ success: false, message: '사용자 삭제에 실패했습니다.' });
    }
});

app.post('/admin/force-change-password', requireAdmin, (req, res) => {
    const { userId, newPassword } = req.body;
    
    try {
        const hash = bcrypt.hashSync(newPassword, 10);
        db.prepare("UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND is_admin = 0").run(hash, userId);
        res.json({ success: true });
    } catch (error) {
        console.error('강제 비밀번호 변경 오류:', error);
        res.json({ success: false, message: '비밀번호 변경에 실패했습니다.' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('세션 삭제 실패:', err);
        }
        res.redirect('/');
    });
});

// 데이터베이스 초기화 및 서버 시작
initializeDatabase();

app.listen(PORT, () => {
    console.log(`\n🚀 === READIN 집중력 훈련 서버 시작 === 🚀`);
    console.log(`📡 서버 포트: ${PORT}`);
    console.log(`🕐 현재 KST 시간: ${getKSTTimestamp()}`);
    console.log(`📅 오늘 날짜 (KST): ${getTodayKST()}`);
    
    const days = getDaysSinceStart();
    const range = getDifficultyRange(3);
    console.log(`📊 8월 30일부터 경과일: ${days}일`);
    console.log(`🎯 현재 기본 레벨 난이도: ${range.range}`);
    console.log(`💾 SQLite 데이터베이스 사용 (readin.db)`);
    console.log(`👑 관리자 계정: readin / admin123`);
    console.log(`🎵 소리 재생 속도: 100 BPM`);
    console.log(`===============================================\n`);
    
    // Keep-Alive 시스템 (외부 서비스 추천)
    console.log('⚠️ Render 무료 플랜: 15분 비활성시 Sleep 상태');
    console.log('💡 권장: UptimeRobot 등 외부 모니터링 서비스 사용');
    console.log('   - https://uptimerobot.com');
    console.log('   - 5분마다 /health 경로 ping\n');
});
