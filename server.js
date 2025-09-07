const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL 연결 설정
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 헬퍼 함수: 쿼리 실행
async function query(text, params = []) {
    const client = await pool.connect();
    try {
        const hash = await bcrypt.hash(newPassword, 10);
        await query("UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND is_admin = false", 
                   [hash, userId]);
        
        // 강제 비밀번호 변경 이력 기록
        await query("INSERT INTO password_history (user_id, changed_by, change_type) VALUES ($1, $2, 'admin_force')",
                   [userId, req.session.userId]);
        
        await logSystemEvent('admin_action', req.session.userId, 
                           `Force changed password for user ID: ${userId}`);
        res.json({ success: true });
    } catch (error) {
        console.error('강제 비밀번호 변경 오류:', error);
        await logSystemEvent('error', req.session.userId, 
                           `Force password change failed for user ${userId}: ${error.message}`);
        res.json({ success: false, message: '비밀번호 변경에 실패했습니다.' });
    }
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.get('/logout', async (req, res) => {
    const userId = req.session.userId;
    const username = req.session.username;
    
    if (userId) {
        await logSystemEvent('logout', userId, `User logged out: ${username}`);
    }
    
    req.session.destroy((err) => {
        if (err) {
            console.error('세션 삭제 실패:', err);
        }
        res.redirect('/');
    });
});

// 시스템 로그 조회 API (관리자 전용)
app.get('/admin/system-logs', requireAdmin, async (req, res) => {
    const limit = req.query.limit || 100;
    const logType = req.query.type || '';
    
    try {
        let queryText = `SELECT sl.*, u.username 
                        FROM system_logs sl 
                        LEFT JOIN users u ON sl.user_id = u.id `;
        let params = [];
        
        if (logType) {
            queryText += ' WHERE sl.log_type = $1 ';
            params.push(logType);
            queryText += ' ORDER BY sl.timestamp DESC LIMIT $2';
            params.push(parseInt(limit));
        } else {
            queryText += ' ORDER BY sl.timestamp DESC LIMIT $1';
            params.push(parseInt(limit));
        }
        
        const result = await query(queryText, params);
        res.json({ success: true, logs: result.rows });
    } catch (error) {
        console.error('시스템 로그 조회 오류:', error);
        await logSystemEvent('error', req.session.userId, `System logs query failed: ${error.message}`);
        res.json({ success: false, logs: [] });
    }
});

// 에러 핸들링 미들웨어
app.use((err, req, res, next) => {
    console.error('서버 에러:', err);
    logSystemEvent('error', req.session?.userId, `Server error: ${err.message}`);
    res.status(500).send('서버 내부 오류가 발생했습니다.');
});

// 404 에러 핸들링
app.use(async (req, res) => {
    await logSystemEvent('error', req.session?.userId, `404 Not Found: ${req.url}`);
    res.status(404).send('페이지를 찾을 수 없습니다.');
});

// 종료 시 데이터베이스 정리
process.on('SIGINT', async () => {
    console.log('\n🛑 서버 종료 중...');
    await logSystemEvent('system', null, 'Server shutdown initiated');
    
    await pool.end();
    console.log('✅ 데이터베이스 연결 종료됨');
    process.exit(0);
});

// 데이터베이스 초기화 실행
initializeDatabase();

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
    console.log(`🐘 PostgreSQL 데이터베이스 사용`);
    
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
    console.log(`🔒 모든 데이터가 PostgreSQL에 영구 저장됩니다`);
    console.log(`===============================================\n`);
    
    // 서버 시작 로그 기록
    logSystemEvent('system', null, `Server started on port ${PORT} with PostgreSQL`);
});
        const result = await client.query(text, params);
        return result;
    } finally {
        client.release();
    }
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

// PostgreSQL 테이블 초기화
async function initializeDatabase() {
    try {
        console.log('🔧 PostgreSQL 테이블 초기화 시작...');

        // Users table
        await query(`CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            is_admin BOOLEAN DEFAULT false,
            level INTEGER DEFAULT 3,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            status VARCHAR(50) DEFAULT 'active'
        )`);

        // Training records table
        await query(`CREATE TABLE IF NOT EXISTS training_records (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            actual_count INTEGER NOT NULL,
            user_answer INTEGER NOT NULL,
            is_correct BOOLEAN NOT NULL,
            level INTEGER NOT NULL,
            date VARCHAR(20) NOT NULL,
            timestamp VARCHAR(30) NOT NULL,
            session_duration INTEGER,
            difficulty_range VARCHAR(20),
            bpm INTEGER DEFAULT 100
        )`);

        // Settings table
        await query(`CREATE TABLE IF NOT EXISTS settings (
            key VARCHAR(255) PRIMARY KEY,
            value VARCHAR(255) NOT NULL,
            description TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by VARCHAR(255)
        )`);

        // Daily attempts table
        await query(`CREATE TABLE IF NOT EXISTS daily_attempts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            date VARCHAR(20) NOT NULL,
            attempts INTEGER DEFAULT 0,
            bonus_attempts INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, date)
        )`);

        // System logs table
        await query(`CREATE TABLE IF NOT EXISTS system_logs (
            id SERIAL PRIMARY KEY,
            log_type VARCHAR(50) NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            message TEXT NOT NULL,
            ip_address VARCHAR(50),
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        // Password history table
        await query(`CREATE TABLE IF NOT EXISTS password_history (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            changed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            change_type VARCHAR(20) DEFAULT 'self',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        // 관리자 계정 생성
        const adminCheck = await query("SELECT * FROM users WHERE username = 'readin'");
        if (adminCheck.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await query(`INSERT INTO users (username, password, is_admin, level, status) 
                        VALUES ($1, $2, true, 3, 'active')`, ['readin', hash]);
            console.log('👑 관리자 계정 생성 완료: readin / admin123');
        }

        // 기본 설정 초기화
        const defaultSettings = [
            ['auto_signup', '0', '자동 회원가입 허용 여부'],
            ['allow_password_change', '1', '참가자 비밀번호 변경 허용 여부'],
            ['max_daily_attempts', '2', '일일 기본 도전 횟수'],
            ['training_bpm', '100', '훈련 재생 속도 (BPM)'],
            ['difficulty_start_date', '2025-08-30', '난이도 시작 기준일'],
            ['system_maintenance', '0', '시스템 점검 모드']
        ];

        for (const [key, value, description] of defaultSettings) {
            await query(`INSERT INTO settings (key, value, description, updated_by) 
                        VALUES ($1, $2, $3, 'system') ON CONFLICT (key) DO NOTHING`, 
                       [key, value, description]);
        }

        console.log('🎉 PostgreSQL 데이터베이스 초기화 완료!');
    } catch (error) {
        console.error('❌ 데이터베이스 초기화 실패:', error);
        process.exit(1);
    }
}

// 시스템 로그 기록 함수
async function logSystemEvent(logType, userId, message, req = null) {
    const ipAddress = req ? (req.ip || req.connection.remoteAddress) : null;
    const userAgent = req ? req.get('User-Agent') : null;
    
    try {
        await query(`INSERT INTO system_logs (log_type, user_id, message, ip_address, user_agent) 
                    VALUES ($1, $2, $3, $4, $5)`, 
                   [logType, userId, message, ipAddress, userAgent]);
    } catch (error) {
        console.error('❌ 시스템 로그 기록 실패:', error);
    }
}

// 사용자 업데이트 트리거 함수
async function updateUserTimestamp(userId) {
    try {
        await query("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = $1", [userId]);
    } catch (error) {
        console.error('사용자 타임스탬프 업데이트 실패:', error);
    }
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
app.get('/', async (req, res) => {
    if (req.session.userId) {
        if (req.session.isAdmin) {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        try {
            const result = await query("SELECT value FROM settings WHERE key = 'auto_signup'");
            const autoSignup = result.rows.length > 0 ? result.rows[0].value === '1' : false;
            res.render('login', { error: null, autoSignup });
        } catch (error) {
            console.error('설정 조회 오류:', error);
            res.render('login', { error: null, autoSignup: false });
        }
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await query("SELECT * FROM users WHERE username = $1 AND status = 'active'", [username]);
        const user = result.rows[0];
        
        if (user) {
            const isValid = await bcrypt.compare(password, user.password);
            if (isValid) {
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.isAdmin = user.is_admin;
                req.session.level = user.level;
                
                // 마지막 로그인 시간 업데이트
                await query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [user.id]);
                
                // 로그인 로그 기록
                await logSystemEvent('login', user.id, `User logged in: ${username}`, req);
                
                if (user.is_admin) {
                    res.redirect('/admin');
                } else {
                    res.redirect('/dashboard');
                }
            } else {
                await logSystemEvent('login_failed', null, `Failed login attempt: ${username}`, req);
                const settingsResult = await query("SELECT value FROM settings WHERE key = 'auto_signup'");
                const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
                res.render('login', { error: '비밀번호가 올바르지 않습니다.', autoSignup });
            }
        } else {
            // Check auto signup
            const settingsResult = await query("SELECT value FROM settings WHERE key = 'auto_signup'");
            const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
            
            if (autoSignup && password === '123456') {
                // Create new account
                const hash = await bcrypt.hash(password, 10);
                const insertResult = await query(`INSERT INTO users (username, password, level, status) 
                                                 VALUES ($1, $2, 3, 'active') RETURNING id`, [username, hash]);
                
                req.session.userId = insertResult.rows[0].id;
                req.session.username = username;
                req.session.isAdmin = false;
                req.session.level = 3;
                
                // 계정 생성 로그 기록
                await logSystemEvent('account_created', insertResult.rows[0].id, 
                                   `Auto-signup account created: ${username}`, req);
                
                res.redirect('/dashboard');
            } else {
                await logSystemEvent('login_failed', null, `User not found: ${username}`, req);
                res.render('login', { error: '사용자를 찾을 수 없습니다.', autoSignup });
            }
        }
    } catch (error) {
        console.error('로그인 오류:', error);
        res.render('login', { error: '서버 오류가 발생했습니다.', autoSignup: false });
    }
});

app.get('/dashboard', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    try {
        // Get today's attempts
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", 
                                          [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        // Get user's training records
        const recordsResult = await query("SELECT * FROM training_records WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 50", 
                                         [userId]);
        const records = recordsResult.rows;
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

app.get('/training', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    try {
        // Check remaining attempts
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", 
                                          [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            await logSystemEvent('training_blocked', userId, 'No remaining attempts for today');
            res.redirect('/dashboard');
            return;
        }
        
        const difficultyRange = getDifficultyRange(req.session.level);
        const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
        
        // 훈련 시작 로그
        await logSystemEvent('training_started', userId, 
                           `Training started - Level: ${req.session.level}, Range: ${difficultyRange.range}, Count: ${actualCount}`);
        
        res.render('training', {
            username: req.session.username,
            actualCount,
            level: req.session.level
        });
    } catch (error) {
        console.error('훈련 페이지 로딩 오류:', error);
        res.status(500).send('서버 오류가 발생했습니다.');
    }
});

app.post('/submit-answer', requireAuth, async (req, res) => {
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
        // Check remaining attempts
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", 
                                          [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            await logSystemEvent('training_blocked', userId, 'Attempted training without remaining attempts');
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
        const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        
        // Record the training with enhanced data
        await query(`INSERT INTO training_records 
                    (user_id, actual_count, user_answer, is_correct, level, date, timestamp, 
                     difficulty_range, bpm) 
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                   [userId, actualCount, userAnswer, isCorrect, req.session.level, today, 
                    kstTimestamp, difficultyRange.range, 100]);
        
        // Update daily attempts
        if (attempts) {
            await query(`UPDATE daily_attempts SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP 
                        WHERE user_id = $1 AND date = $2`, [userId, today]);
        } else {
            await query(`INSERT INTO daily_attempts (user_id, date, attempts) VALUES ($1, $2, 1)`,
                       [userId, today]);
        }
        
        // 훈련 완료 로그
        await logSystemEvent('training_completed', userId, 
                           `Training completed - Actual: ${actualCount}, Answer: ${userAnswer}, Correct: ${isCorrect}`);
        
        // 사용자 업데이트 시간 갱신
        await updateUserTimestamp(userId);
        
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

app.get('/admin', requireAdmin, async (req, res) => {
    try {
        // Get all participants
        const usersResult = await query("SELECT id, username, level, created_at, last_login, status FROM users WHERE is_admin = false ORDER BY username");
        const users = usersResult.rows;
        
        const settingsResult = await query("SELECT key, value, description FROM settings ORDER BY key");
        const settingsObj = {};
        settingsResult.rows.forEach(setting => {
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

app.post('/admin/search', requireAdmin, async (req, res) => {
    const { searchTerm } = req.body;
    
    try {
        const result = await query(`SELECT id, username, level, created_at, last_login, status 
                                   FROM users WHERE is_admin = false AND username ILIKE $1 
                                   ORDER BY username`, [`%${searchTerm}%`]);
        res.json({ users: result.rows });
    } catch (error) {
        console.error('사용자 검색 오류:', error);
        res.json({ users: [] });
    }
});

app.post('/admin/update-level', requireAdmin, async (req, res) => {
    const { userId, level } = req.body;
    
    try {
        await query("UPDATE users SET level = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", 
                   [level, userId]);
        await logSystemEvent('admin_action', req.session.userId, `Updated user ${userId} level to ${level}`);
        res.json({ success: true });
    } catch (error) {
        console.error('레벨 업데이트 오류:', error);
        await logSystemEvent('error', req.session.userId, `Level update failed for user ${userId}: ${error.message}`);
        res.json({ success: false, message: '레벨 업데이트에 실패했습니다.' });
    }
});

app.post('/admin/bonus-attempt', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    const today = getTodayKST();
    
    try {
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", 
                                          [userId, today]);
        
        if (attemptsResult.rows.length > 0) {
            await query(`UPDATE daily_attempts SET bonus_attempts = bonus_attempts + 1, 
                        updated_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND date = $2`,
                       [userId, today]);
        } else {
            await query("INSERT INTO daily_attempts (user_id, date, bonus_attempts) VALUES ($1, $2, 1)",
                       [userId, today]);
        }
        
        await logSystemEvent('admin_action', req.session.userId, `Granted bonus attempt to user ${userId}`);
        res.json({ success: true });
    } catch (error) {
        console.error('보너스 기회 부여 오류:', error);
        res.json({ success: false, message: '보너스 기회 부여에 실패했습니다.' });
    }
});

app.post('/admin/toggle-setting', requireAdmin, async (req, res) => {
    const { key } = req.body;
    
    try {
        const result = await query("SELECT value FROM settings WHERE key = $1", [key]);
        const currentValue = result.rows[0]?.value || '0';
        const newValue = currentValue === '1' ? '0' : '1';
        
        await query(`UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP, updated_by = $2 
                    WHERE key = $3`, [newValue, req.session.username, key]);
        
        await logSystemEvent('admin_action', req.session.userId, `Toggled setting ${key} to ${newValue}`);
        res.json({ success: true, newValue });
    } catch (error) {
        console.error('설정 토글 오류:', error);
        await logSystemEvent('error', req.session.userId, `Setting toggle failed for ${key}: ${error.message}`);
        res.json({ success: false });
    }
});

app.get('/admin/records/:date', requireAdmin, async (req, res) => {
    const date = req.params.date;
    
    try {
        const result = await query(`SELECT tr.*, u.username 
                                   FROM training_records tr 
                                   JOIN users u ON tr.user_id = u.id 
                                   WHERE tr.date = $1 
                                   ORDER BY u.username, tr.timestamp`, [date]);
        res.json({ records: result.rows });
    } catch (error) {
        console.error('기록 조회 오류:', error);
        await logSystemEvent('error', req.session.userId, `Records query failed for date ${date}: ${error.message}`);
        res.json({ records: [] });
    }
});

app.get('/change-password', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.render('change-password', { 
            username: req.session.username, 
            isAdmin: true,
            error: null 
        });
    } else {
        try {
            const result = await query("SELECT value FROM settings WHERE key = 'allow_password_change'");
            const allowed = result.rows.length > 0 ? result.rows[0].value === '1' : true;
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

app.post('/change-password', requireAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    
    try {
        const result = await query("SELECT password FROM users WHERE id = $1", [req.session.userId]);
        const user = result.rows[0];
        
        const isValid = await bcrypt.compare(currentPassword, user.password);
        if (isValid) {
            const hash = await bcrypt.hash(newPassword, 10);
            await query("UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", 
                       [hash, req.session.userId]);
            
            // 비밀번호 변경 이력 기록
            await query("INSERT INTO password_history (user_id, change_type) VALUES ($1, 'self')",
                       [req.session.userId]);
            
            await logSystemEvent('password_changed', req.session.userId, 'User changed own password');
            res.redirect(req.session.isAdmin ? '/admin' : '/dashboard');
        } else {
            await logSystemEvent('password_change_failed', req.session.userId, 'Incorrect current password');
            res.render('change-password', { 
                username: req.session.username, 
                isAdmin: req.session.isAdmin,
                error: '현재 비밀번호가 올바르지 않습니다.' 
            });
        }
    } catch (error) {
        console.error('비밀번호 변경 오류:', error);
        await logSystemEvent('error', req.session.userId, `Password change failed: ${error.message}`);
        res.render('change-password', { 
            username: req.session.username, 
            isAdmin: req.session.isAdmin,
            error: '비밀번호 변경에 실패했습니다.' 
        });
    }
});

app.post('/admin/delete-user', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    
    try {
        // 사용자 정보 조회 후 삭제
        const userResult = await query("SELECT username FROM users WHERE id = $1 AND is_admin = false", [userId]);
        if (userResult.rows.length === 0) {
            res.json({ success: false, message: '사용자를 찾을 수 없습니다.' });
            return;
        }
        
        const username = userResult.rows[0].username;
        
        // 관련 데이터 삭제 (Foreign Key Cascade로 자동 처리되지만 명시적으로)
        await query("DELETE FROM training_records WHERE user_id = $1", [userId]);
        await query("DELETE FROM daily_attempts WHERE user_id = $1", [userId]);
        await query("DELETE FROM password_history WHERE user_id = $1", [userId]);
        await query("DELETE FROM users WHERE id = $1 AND is_admin = false", [userId]);
        
        await logSystemEvent('admin_action', req.session.userId, 
                           `Deleted user: ${username} (ID: ${userId})`);
        res.json({ success: true });
    } catch (error) {
        console.error('사용자 삭제 오류:', error);
        await logSystemEvent('error', req.session.userId, 
                           `User deletion failed for user ${userId}: ${error.message}`);
        res.json({ success: false, message: '사용자 삭제에 실패했습니다.' });
    }
});

app.post('/admin/force-change-password', requireAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    
    try {
