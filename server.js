const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL 연결
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 쿼리 헬퍼 함수
async function query(text, params = []) {
    const client = await pool.connect();
    try {
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
    secret: process.env.SESSION_SECRET || 'readin-concentration-secret-key-v2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// 데이터베이스 초기화
async function initializeDatabase() {
    try {
        console.log('🔧 PostgreSQL 테이블 초기화 시작...');

        // Users table
        await query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT false,
                level INTEGER DEFAULT 3,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                status VARCHAR(50) DEFAULT 'active'
            )
        `);

        // Training records table
        await query(`
            CREATE TABLE IF NOT EXISTS training_records (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                actual_count INTEGER NOT NULL,
                user_answer INTEGER NOT NULL,
                is_correct BOOLEAN NOT NULL,
                level INTEGER NOT NULL,
                date VARCHAR(20) NOT NULL,
                timestamp VARCHAR(30) NOT NULL,
                difficulty_range VARCHAR(20),
                bpm INTEGER DEFAULT 100
            )
        `);

        // Settings table
        await query(`
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(255) PRIMARY KEY,
                value VARCHAR(255) NOT NULL,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by VARCHAR(255)
            )
        `);

        // Daily attempts table
        await query(`
            CREATE TABLE IF NOT EXISTS daily_attempts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                date VARCHAR(20) NOT NULL,
                attempts INTEGER DEFAULT 0,
                bonus_attempts INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, date)
            )
        `);

        // 관리자 계정 생성
        const adminCheck = await query("SELECT * FROM users WHERE username = 'readin'");
        if (adminCheck.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await query(`
                INSERT INTO users (username, password, is_admin, level, status) 
                VALUES ($1, $2, true, 3, 'active')
            `, ['readin', hash]);
            console.log('👑 관리자 계정 생성 완료: readin / admin123');
        }

        // 기본 설정 초기화
       const defaultSettings = [
    ['auto_signup', '0', '자동 회원가입 허용 여부'],
    ['allow_password_change', '1', '참가자 비밀번호 변경 허용 여부'],
    ['show_visual_feedback', '1', '훈련 중 시각적 피드백 표시 여부']
];

        for (const [key, value, description] of defaultSettings) {
            await query(`
                INSERT INTO settings (key, value, description, updated_by) 
                VALUES ($1, $2, $3, 'system') 
                ON CONFLICT (key) DO NOTHING
            `, [key, value, description]);
        }

        console.log('🎉 PostgreSQL 데이터베이스 초기화 완료!');
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
        case 1: // 초급
            const cycle1 = days % 3;
            const base1 = 10 + (cycle1 * 10);
            return { min: base1, max: base1 + 9, range: `${base1}-${base1 + 9}` };
        
        case 2: // 중급
            const cycle2 = days % 6;
            const base2 = 10 + (cycle2 * 10);
            return { min: base2, max: base2 + 9, range: `${base2}-${base2 + 9}` };
        
        case 3: // 기본 - 16일 주기로 반복
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
                
                await query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1", [user.id]);
                
                if (user.is_admin) {
                    res.redirect('/admin');
                } else {
                    res.redirect('/dashboard');
                }
            } else {
                const settingsResult = await query("SELECT value FROM settings WHERE key = 'auto_signup'");
                const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
                res.render('login', { error: '비밀번호가 올바르지 않습니다.', autoSignup });
            }
        } else {
            const settingsResult = await query("SELECT value FROM settings WHERE key = 'auto_signup'");
            const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
            
            if (autoSignup && password === '123456') {
                const hash = await bcrypt.hash(password, 10);
                const insertResult = await query(`
                    INSERT INTO users (username, password, level, status) 
                    VALUES ($1, $2, 3, 'active') RETURNING id
                `, [username, hash]);
                
                req.session.userId = insertResult.rows[0].id;
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

app.get('/dashboard', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    const today = getTodayKST();
    const userId = req.session.userId;
    
    try {
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        const recordsResult = await query("SELECT * FROM training_records WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 50", [userId]);
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
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.redirect('/dashboard');
            return;
        }
        
      const difficultyRange = getDifficultyRange(req.session.level);
    const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
    
    // 시각적 피드백 설정 조회
    const visualFeedbackResult = await query("SELECT value FROM settings WHERE key = 'show_visual_feedback'");
    const showVisualFeedback = visualFeedbackResult.rows.length > 0 ? visualFeedbackResult.rows[0].value === '1' : true;
    
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
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", [userId, today]);
        const attempts = attemptsResult.rows[0];
        const totalAttempts = attempts ? attempts.attempts : 0;
        const bonusAttempts = attempts ? attempts.bonus_attempts : 0;
        const remainingAttempts = Math.max(0, 2 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
        const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        
        await query(`
            INSERT INTO training_records (user_id, actual_count, user_answer, is_correct, level, date, timestamp, difficulty_range, bpm) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `, [userId, actualCount, userAnswer, isCorrect, req.session.level, today, kstTimestamp, difficultyRange.range, 100]);
        
        if (attempts) {
            await query("UPDATE daily_attempts SET attempts = attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND date = $2", [userId, today]);
        } else {
            await query("INSERT INTO daily_attempts (user_id, date, attempts) VALUES ($1, $2, 1)", [userId, today]);
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

app.get('/admin', requireAdmin, async (req, res) => {
    try {
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
        const result = await query("SELECT id, username, level, created_at, last_login, status FROM users WHERE is_admin = false AND username ILIKE $1 ORDER BY username", [`%${searchTerm}%`]);
        res.json({ users: result.rows });
    } catch (error) {
        console.error('사용자 검색 오류:', error);
        res.json({ users: [] });
    }
});

app.post('/admin/update-level', requireAdmin, async (req, res) => {
    const { userId, level } = req.body;
    try {
        await query("UPDATE users SET level = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", [level, userId]);
        res.json({ success: true });
    } catch (error) {
        console.error('레벨 업데이트 오류:', error);
        res.json({ success: false, message: '레벨 업데이트에 실패했습니다.' });
    }
});

app.post('/admin/bonus-attempt', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    const today = getTodayKST();
    
    try {
        const attemptsResult = await query("SELECT * FROM daily_attempts WHERE user_id = $1 AND date = $2", [userId, today]);
        
        if (attemptsResult.rows.length > 0) {
            await query("UPDATE daily_attempts SET bonus_attempts = bonus_attempts + 1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $1 AND date = $2", [userId, today]);
        } else {
            await query("INSERT INTO daily_attempts (user_id, date, bonus_attempts) VALUES ($1, $2, 1)", [userId, today]);
        }
        
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
        
        await query("UPDATE settings SET value = $1, updated_at = CURRENT_TIMESTAMP, updated_by = $2 WHERE key = $3", [newValue, req.session.username, key]);
        res.json({ success: true, newValue });
    } catch (error) {
        console.error('설정 토글 오류:', error);
        res.json({ success: false });
    }
});

app.get('/admin/records/:date', requireAdmin, async (req, res) => {
    const date = req.params.date;
    const searchUser = req.query.user || '';
    
    try {
        let queryText = `
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.date = $1
        `;
        let params = [date];
        
        if (searchUser) {
            queryText += ' AND u.username ILIKE $2 ';
            params.push(`%${searchUser}%`);
        }
        
        queryText += ' ORDER BY u.username, tr.timestamp';
        
        const result = await query(queryText, params);
        res.json({ records: result.rows });
    } catch (error) {
        console.error('기록 조회 오류:', error);
        res.json({ records: [] });
    }
});

// 새로운 API들 추가 (위 코드 바로 아래에 추가)
app.get('/admin/user-records/:userId', requireAdmin, async (req, res) => {
    const userId = req.params.userId;
    
    try {
        console.log('=== 사용자 기록 조회 시작 ===');
        console.log('사용자 ID:', userId);
        
        // 모든 기록 조회 (간단하게)
        const result = await query(`
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.user_id = $1
            ORDER BY tr.timestamp DESC
        `, [userId]);
        
        console.log('조회된 기록 수:', result.rows.length);
        console.log('첫 번째 기록:', result.rows[0]);
        
        res.json({ 
            success: true, 
            records: result.rows,
            totalRecords: result.rows.length
        });
    } catch (error) {
        console.error('학생별 기록 조회 오류:', error);
        res.json({ success: false, records: [], totalRecords: 0 });
    }
});

app.get('/admin/user-stats/:userId', requireAdmin, async (req, res) => {
    const userId = req.params.userId;
    
    try {
        const totalResult = await query("SELECT COUNT(*) as total FROM training_records WHERE user_id = $1", [userId]);
        const correctResult = await query("SELECT COUNT(*) as correct FROM training_records WHERE user_id = $1 AND is_correct = true", [userId]);
        const recentResult = await query(`
            SELECT COUNT(*) as recent 
            FROM training_records 
            WHERE user_id = $1 AND date >= $2
        `, [userId, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]]);
        
        const total = parseInt(totalResult.rows[0].total);
        const correct = parseInt(correctResult.rows[0].correct);
        const recent = parseInt(recentResult.rows[0].recent);
        
        res.json({
            success: true,
            stats: {
                totalAttempts: total,
                correctAnswers: correct,
                accuracy: total > 0 ? Math.round((correct / total) * 100) : 0,
                recentWeek: recent
            }
        });
        // 참가자별 전체 기록 조회 (날짜별 그룹화)
app.get('/admin/user-all-records/:userId', requireAdmin, async (req, res) => {
    const userId = req.params.userId;
    
    try {
        console.log('전체 기록 조회 시작 - 사용자 ID:', userId);
        
        // 날짜별로 그룹화된 기록 조회
        const result = await query(`
            SELECT 
                tr.date,
                COUNT(*) as daily_attempts,
                SUM(CASE WHEN tr.is_correct THEN 1 ELSE 0 END) as correct_count,
                ROUND(AVG(tr.actual_count)) as avg_actual_count,
                tr.level,
                tr.difficulty_range,
                array_agg(
                    json_build_object(
                        'id', tr.id,
                        'actual_count', tr.actual_count,
                        'user_answer', tr.user_answer,
                        'is_correct', tr.is_correct,
                        'timestamp', tr.timestamp
                    ) ORDER BY tr.timestamp
                ) as records
            FROM training_records tr 
            WHERE tr.user_id = $1
            GROUP BY tr.date, tr.level, tr.difficulty_range
            ORDER BY tr.date DESC
        `, [userId]);
        
        console.log('조회된 날짜별 기록 수:', result.rows.length);
        
        res.json({ 
            success: true, 
            dailyRecords: result.rows
        });
    } catch (error) {
        console.error('전체 기록 조회 오류:', error);
        res.json({ success: false, dailyRecords: [] });
    }
});
    } catch (error) {
        console.error('학생 통계 조회 오류:', error);
        res.json({ success: false, stats: null });
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
            await query("UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2", [hash, req.session.userId]);
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

app.post('/admin/delete-user', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    
    try {
        const userResult = await query("SELECT username FROM users WHERE id = $1 AND is_admin = false", [userId]);
        if (userResult.rows.length === 0) {
            res.json({ success: false, message: '사용자를 찾을 수 없습니다.' });
            return;
        }
        
        await query("DELETE FROM training_records WHERE user_id = $1", [userId]);
        await query("DELETE FROM daily_attempts WHERE user_id = $1", [userId]);
        await query("DELETE FROM users WHERE id = $1 AND is_admin = false", [userId]);
        
        res.json({ success: true });
    } catch (error) {
        console.error('사용자 삭제 오류:', error);
        res.json({ success: false, message: '사용자 삭제에 실패했습니다.' });
    }
});

app.post('/admin/force-change-password', requireAdmin, async (req, res) => {
    const { userId, newPassword } = req.body;
    
    try {
        const hash = await bcrypt.hash(newPassword, 10);
        await query("UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND is_admin = false", [hash, userId]);
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

// 종료 시 정리
process.on('SIGINT', async () => {
    console.log('\n🛑 서버 종료 중...');
    await pool.end();
    console.log('✅ 데이터베이스 연결 종료됨');
    process.exit(0);
});

// 데이터베이스 초기화 및 서버 시작
initializeDatabase().then(() => {
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
        console.log(`👑 관리자 계정: readin / admin123`);
        console.log(`🎵 소리 재생 속도: 100 BPM`);
        console.log(`🔒 모든 데이터가 PostgreSQL에 영구 저장됩니다`);
        console.log(`===============================================\n`);
    });
}).catch(error => {
    console.error('서버 시작 실패:', error);
    process.exit(1);
});
