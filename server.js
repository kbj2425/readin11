const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// 메모리 기반 데이터 저장소 (서버 재시작시 초기화됨)
const memoryDB = {
    users: [],
    trainingRecords: [],
    dailyAttempts: [],
    settings: [],
    stepCompletions: [],
    monthlyRankings: [],
    badges: [],
    titles: [],
    personalGoals: []
};

let userIdCounter = 1;
let recordIdCounter = 1;
let attemptIdCounter = 1;
let stepCompletionIdCounter = 1;
let rankingIdCounter = 1;
let badgeIdCounter = 1;
let titleIdCounter = 1;
let goalIdCounter = 1;

// 쿼리 헬퍼 함수 (메모리 DB용)
async function query(text, params = []) {
    // SELECT 쿼리 시뮬레이션
    if (text.includes('SELECT') && text.includes('FROM users')) {
        if (text.includes("username = $1") || text.includes("username = ?")) {
            const user = memoryDB.users.find(u => u.username === params[0]);
            return { rows: user ? [user] : [] };
        }
        if (text.includes('is_admin = false') || text.includes('is_admin = 0')) {
            return { rows: memoryDB.users.filter(u => !u.is_admin) };
        }
        if (text.includes('WHERE id = $1') || text.includes('WHERE id = ?')) {
            const user = memoryDB.users.find(u => u.id === params[0]);
            return { rows: user ? [user] : [] };
        }
        if (text.includes('username ILIKE') || text.includes('username LIKE')) {
            const searchTerm = params[0].replace(/%/g, '');
            return { rows: memoryDB.users.filter(u => !u.is_admin && u.username.toLowerCase().includes(searchTerm.toLowerCase())) };
        }
    }
    
    if (text.includes('SELECT') && text.includes('FROM settings')) {
        if (text.includes('WHERE key')) {
            const key = params[0];
            const setting = memoryDB.settings.find(s => s.key === key);
            return { rows: setting ? [setting] : [] };
        }
        return { rows: memoryDB.settings };
    }
    
    if (text.includes('SELECT') && text.includes('FROM daily_attempts')) {
        const attempt = memoryDB.dailyAttempts.find(a => a.user_id === params[0] && a.date === params[1]);
        return { rows: attempt ? [attempt] : [] };
    }
    
    if (text.includes('SELECT') && text.includes('FROM training_records')) {
        if (text.includes('JOIN users')) {
            // 날짜별 조회
            if (text.includes('WHERE tr.date')) {
                const date = params[0];
                const searchUser = params[1] || '';
                let records = memoryDB.trainingRecords.filter(r => r.date === date);
                
                if (searchUser) {
                    records = records.filter(r => {
                        const user = memoryDB.users.find(u => u.id === r.user_id);
                        return user && user.username.toLowerCase().includes(searchUser.toLowerCase());
                    });
                }
                
                return { rows: records.map(r => {
                    const user = memoryDB.users.find(u => u.id === r.user_id);
                    return { ...r, username: user ? user.username : 'Unknown' };
                }) };
            }
            // 사용자별 조회
            if (text.includes('WHERE tr.user_id')) {
                const records = memoryDB.trainingRecords.filter(r => r.user_id === params[0]);
                return { rows: records.map(r => {
                    const user = memoryDB.users.find(u => u.id === r.user_id);
                    return { ...r, username: user ? user.username : 'Unknown' };
                }) };
            }
        }
        
        // 기본 조회
        if (text.includes('WHERE user_id')) {
            let records = memoryDB.trainingRecords.filter(r => r.user_id === params[0]);
            if (text.includes('LIMIT')) {
                records = records.slice(0, 50);
            }
            return { rows: records };
        }
        
        // COUNT 쿼리
        if (text.includes('COUNT(*)')) {
            if (text.includes('is_correct')) {
                const count = memoryDB.trainingRecords.filter(r => r.user_id === params[0] && r.is_correct).length;
                return { rows: [{ correct: count }] };
            }
            if (text.includes('date >=')) {
                const count = memoryDB.trainingRecords.filter(r => r.user_id === params[0] && r.date >= params[1]).length;
                return { rows: [{ recent: count }] };
            }
            const count = memoryDB.trainingRecords.filter(r => r.user_id === params[0]).length;
            return { rows: [{ total: count }] };
        }
    }
    
    // INSERT 쿼리 시뮬레이션
    if (text.includes('INSERT INTO users')) {
        const newUser = {
            id: userIdCounter++,
            username: params[0],
            password: params[1],
            is_admin: params.length > 2 && (params[2] === true || params[2] === 1),
            level: 3,
            status: 'active',
            created_at: new Date().toISOString(),
            last_login: null
        };
        memoryDB.users.push(newUser);
        return { rows: [{ id: newUser.id }] };
    }
    
 if (text.includes('INSERT INTO training_records')) {
        const newRecord = {
            id: recordIdCounter++,
            user_id: params[0],
            actual_count: params[1],
            user_answer: params[2],
            is_correct: params[3],
            level: params[4],
            date: params[5],
            timestamp: params[6],
            difficulty_range: params[7],
            bpm: params[8] || 100,
            score: params[9] || 0,
            answer_type: params[10] || 'wrong'
        };
        memoryDB.trainingRecords.push(newRecord);
        return { rows: [] };
    }
    
    if (text.includes('INSERT INTO daily_attempts')) {
        const newAttempt = {
            id: attemptIdCounter++,
            user_id: params[0],
            date: params[1],
            attempts: params[2] === undefined ? 1 : params[2],
            bonus_attempts: params.length > 2 ? params[2] : 0
        };
        memoryDB.dailyAttempts.push(newAttempt);
        return { rows: [] };
    }
    
   if (text.includes('INSERT') && text.includes('settings')) {
        const existing = memoryDB.settings.find(s => s.key === params[0]);
        if (!existing) {
            const newSetting = {
                key: params[0],
                value: params[1],
                description: params[2],
                updated_by: params[3] || 'system'
            };
            memoryDB.settings.push(newSetting);
        }
        return { rows: [] };
    }
    
    if (text.includes('INSERT INTO step_completions')) {
        const newCompletion = {
            id: stepCompletionIdCounter++,
            user_id: params[0],
            date: params[1],
            step1: params[2] || false,
            step2: params[3] || false,
            step3: params[4] || false,
            step4: params[5] || false,
            step5: params[6] || false,
            completed_at: new Date().toISOString()
        };
        memoryDB.stepCompletions.push(newCompletion);
        return { rows: [] };
    }
    
    // UPDATE 쿼리 시뮬레이션
    if (text.includes('UPDATE users')) {
        if (text.includes('last_login')) {
            const user = memoryDB.users.find(u => u.id === params[0]);
            if (user) user.last_login = new Date().toISOString();
        }
        if (text.includes('SET level')) {
            const user = memoryDB.users.find(u => u.id === params[1]);
            if (user) user.level = params[0];
        }
        if (text.includes('SET password')) {
            const user = memoryDB.users.find(u => u.id === params[1]);
            if (user) user.password = params[0];
        }
        return { rows: [] };
    }
    
    if (text.includes('UPDATE daily_attempts')) {
        if (text.includes('SET attempts')) {
            const attempt = memoryDB.dailyAttempts.find(a => a.user_id === params[0] && a.date === params[1]);
            if (attempt) attempt.attempts++;
        }
        if (text.includes('bonus_attempts')) {
            const attempt = memoryDB.dailyAttempts.find(a => a.user_id === params[0] && a.date === params[1]);
            if (attempt) attempt.bonus_attempts++;
        }
        return { rows: [] };
    }
    
    if (text.includes('UPDATE settings')) {
        const setting = memoryDB.settings.find(s => s.key === params[2]);
        if (setting) {
            setting.value = params[0];
            setting.updated_by = params[1];
        }
        return { rows: [] };
    }
    
    // 단계 완료 조회 추가
    if (text.includes('SELECT') && text.includes('FROM step_completions')) {
        if (text.includes('WHERE user_id') && text.includes('AND date')) {
            const completions = memoryDB.stepCompletions.filter(sc => 
                sc.user_id === params[0] && sc.date === params[1]
            );
            return { rows: completions };
        }
        
        if (text.includes('WHERE date')) {
            const completions = memoryDB.stepCompletions.filter(sc => sc.date === params[0]);
            return { rows: completions };
        }
    }
    
    // DELETE 쿼리 시뮬레이션
    if (text.includes('DELETE FROM training_records')) {
        memoryDB.trainingRecords = memoryDB.trainingRecords.filter(r => r.user_id !== params[0]);
        return { rows: [] };
    }
    
    if (text.includes('DELETE FROM daily_attempts')) {
        memoryDB.dailyAttempts = memoryDB.dailyAttempts.filter(a => a.user_id !== params[0]);
        return { rows: [] };
    }
    
    if (text.includes('DELETE FROM users')) {
        memoryDB.users = memoryDB.users.filter(u => u.id !== params[0]);
        return { rows: [] };
    }
    
    return { rows: [] };
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
        console.log('🔧 메모리 데이터베이스 초기화 시작...');
        console.log('⚠️ 경고: 서버 재시작시 모든 데이터가 삭제됩니다!');

        // 관리자 계정 생성
        const hash = await bcrypt.hash('admin123', 10);
        memoryDB.users.push({
            id: userIdCounter++,
            username: 'readin',
            password: hash,
            is_admin: true,
            level: 3,
            status: 'active',
            created_at: new Date().toISOString(),
            last_login: null
        });
        console.log('👑 관리자 계정 생성 완료: readin / admin123');

        // 기본 설정 초기화
        const defaultSettings = [
            { key: 'auto_signup', value: '1', description: '자동 회원가입 허용 여부', updated_by: 'system' },
            { key: 'allow_password_change', value: '0', description: '참가자 비밀번호 변경 허용 여부', updated_by: 'system' },
            { key: 'show_visual_feedback', value: '1', description: '훈련 중 시각적 피드백 표시 여부', updated_by: 'system' }
        ];

        memoryDB.settings = defaultSettings;

        console.log('🎉 메모리 데이터베이스 초기화 완료!');
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

function isPerfectAnswer(actual, answer) {
    return actual === answer;
}

function getAnswerScore(actual, answer) {
    if (isPerfectAnswer(actual, answer)) {
        return { score: 15, type: 'perfect' };
    } else if (isCorrectAnswer(actual, answer)) {
        return { score: 10, type: 'close' };
    } else {
        return { score: 0, type: 'wrong' };
    }
}

// 월간 랭킹 계산
function calculateMonthlyRanking(year, month) {
    const targetMonth = `${year}-${String(month).padStart(2, '0')}`;
    const users = memoryDB.users.filter(u => !u.is_admin);
    
    const rankings = users.map(user => {
        const userRecords = memoryDB.trainingRecords.filter(r => 
            r.user_id === user.id && r.date.startsWith(targetMonth)
        );
        
        if (userRecords.length === 0) {
            return {
                user_id: user.id,
                username: user.username,
                total_score: 0,
                perfect_count: 0,
                close_count: 0,
                wrong_count: 0,
                total_attempts: 0,
                accuracy: 0,
                month: targetMonth
            };
        }
        
        const perfectCount = userRecords.filter(r => r.answer_type === 'perfect').length;
        const closeCount = userRecords.filter(r => r.answer_type === 'close').length;
        const wrongCount = userRecords.filter(r => r.answer_type === 'wrong').length;
        const totalAttempts = userRecords.length;
        
        const accumulatedScore = (perfectCount * 15) + (closeCount * 10);
        const accuracy = ((perfectCount + closeCount) / totalAttempts) * 100;
        const totalScore = Math.round(accumulatedScore + accuracy);
        
        return {
            user_id: user.id,
            username: user.username,
            total_score: totalScore,
            perfect_count: perfectCount,
            close_count: closeCount,
            wrong_count: wrongCount,
            total_attempts: totalAttempts,
            accuracy: Math.round(accuracy * 10) / 10,
            month: targetMonth
        };
    });
    
    return rankings.sort((a, b) => b.total_score - a.total_score);
}

// 칭호 확인
function checkTitles(userId) {
    const titles = [];
    const user = memoryDB.users.find(u => u.id === userId);
    if (!user) return titles;
    
    // 집중의 달인: 3개월 연속 1위
    const recentMonths = getRecentMonths(3);
    const consecutiveFirst = recentMonths.every(month => {
        const ranking = calculateMonthlyRanking(parseInt(month.split('-')[0]), parseInt(month.split('-')[1]));
        return ranking[0]?.user_id === userId;
    });
    if (consecutiveFirst) {
        titles.push({ title: '집중의 달인', icon: '🏆', description: '3개월 연속 1위' });
    }
    
    // 꾸준이: 한 달 동안 매일 완료 (30일)
    const currentMonth = getTodayKST().substring(0, 7);
    const monthRecords = memoryDB.trainingRecords.filter(r => 
        r.user_id === userId && r.date.startsWith(currentMonth)
    );
    const uniqueDays = new Set(monthRecords.map(r => r.date)).size;
    if (uniqueDays >= 30) {
        titles.push({ title: '꾸준이', icon: '⭐', description: '한 달 매일 완료' });
    }
    
    // 정확왕: 월 정답률 95% 이상
    const ranking = calculateMonthlyRanking(parseInt(currentMonth.split('-')[0]), parseInt(currentMonth.split('-')[1]));
    const userRank = ranking.find(r => r.user_id === userId);
    if (userRank && userRank.accuracy >= 95) {
        titles.push({ title: '정확왕', icon: '🎯', description: '정답률 95% 이상' });
    }
    
    return titles;
}

function getRecentMonths(count) {
    const months = [];
    const now = new Date();
    for (let i = 0; i < count; i++) {
        const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
        months.push(`${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`);
    }
    return months;
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
        uptime: Math.floor(process.uptime()),
        users: memoryDB.users.length,
        records: memoryDB.trainingRecords.length
    });
});

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
            const result = await query("SELECT value FROM settings WHERE key = $1", ['auto_signup']);
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
        // 자동 회원가입시 유효성 검사 (readin 제외)
        if (username !== 'readin') {
            const koreanOnly = /^[가-힣]{2,3}$/;
            if (!koreanOnly.test(username)) {
                const settingsResult = await query("SELECT value FROM settings WHERE key = $1", ['auto_signup']);
                const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
                res.render('login', { 
                    error: '이름은 2-3글자 한글만 가능합니다. (숫자, 영어, 특수문자 불가)', 
                    autoSignup 
                });
                return;
            }
        }
        
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
                const settingsResult = await query("SELECT value FROM settings WHERE key = $1", ['auto_signup']);
                const autoSignup = settingsResult.rows.length > 0 ? settingsResult.rows[0].value === '1' : false;
                res.render('login', { error: '비밀번호가 올바르지 않습니다.', autoSignup });
            }
        } else {
            const settingsResult = await query("SELECT value FROM settings WHERE key = $1", ['auto_signup']);
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
        const remainingAttempts = Math.max(0, 1 + bonusAttempts - totalAttempts);
        
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

// 심호흡 훈련 페이지
app.get('/breathing', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }

    res.render('breathing', {
        username: req.session.username
    });
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
        const remainingAttempts = Math.max(0, 1 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.redirect('/dashboard');
            return;
        }
        
        const difficultyRange = getDifficultyRange(req.session.level);
        const actualCount = Math.floor(Math.random() * (difficultyRange.max - difficultyRange.min + 1)) + difficultyRange.min;
        
        const visualFeedbackResult = await query("SELECT value FROM settings WHERE key = $1", ['show_visual_feedback']);
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

// 1단계: 안구 회전 훈련
app.get('/step1-eye', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    res.render('step1-eye', {
        username: req.session.username
    });
});

// 2단계: 선생님 한마디
app.get('/step2-teacher', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    res.render('step2-teacher', {
        username: req.session.username
    });
});

// 3단계: 독서 노트
app.get('/step3-notebook', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    res.render('step3-notebook', {
        username: req.session.username
    });
});

// 4단계: 읽기듣기 트레이닝
app.get('/step4-listening', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    res.render('step4-listening', {
        username: req.session.username
    });
});

// 5단계: 책읽기 시작
app.get('/step5-reading', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    res.render('step5-reading', {
        username: req.session.username
    });
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
        const remainingAttempts = Math.max(0, 1 + bonusAttempts - totalAttempts);
        
        if (remainingAttempts <= 0) {
            res.json({ success: false, message: '오늘의 도전 기회를 모두 사용했습니다.' });
            return;
        }
        
      const isCorrect = isCorrectAnswer(parseInt(actualCount), parseInt(userAnswer));
        const answerResult = getAnswerScore(parseInt(actualCount), parseInt(userAnswer));
        
        await query(`
            INSERT INTO training_records (user_id, actual_count, user_answer, is_correct, level, date, timestamp, difficulty_range, bpm, score, answer_type) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [userId, actualCount, userAnswer, isCorrect, req.session.level, today, kstTimestamp, difficultyRange.range, 100, answerResult.score, answerResult.type]);
        
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
        const result = await query(`
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.date = $1
        `, [date, searchUser]);
        
        res.json({ records: result.rows });
    } catch (error) {
        console.error('기록 조회 오류:', error);
        res.json({ records: [] });
    }
});

app.get('/admin/user-records/:userId', requireAdmin, async (req, res) => {
    const userId = req.params.userId;
    
    try {
        const result = await query(`
            SELECT tr.*, u.username 
            FROM training_records tr 
            JOIN users u ON tr.user_id = u.id 
            WHERE tr.user_id = $1
            ORDER BY tr.timestamp DESC
        `, [userId]);
        
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
    const userId = parseInt(req.params.userId);
    
    try {
        console.log('=== 통계 조회 시작 ===');
        console.log('사용자 ID:', userId);
        
        // 해당 사용자의 모든 기록
        const userRecords = memoryDB.trainingRecords.filter(r => r.user_id === userId);
        
        console.log('사용자 기록 수:', userRecords.length);
        
        // 총 시도 횟수
        const total = userRecords.length;
        
        // 정답 횟수
        const correct = userRecords.filter(r => r.is_correct).length;
        
        // 최근 7일 기록
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const sevenDaysAgoStr = sevenDaysAgo.toISOString().split('T')[0];
        const recent = userRecords.filter(r => r.date >= sevenDaysAgoStr).length;
        
        const stats = {
            totalAttempts: total,
            correctAnswers: correct,
            accuracy: total > 0 ? Math.round((correct / total) * 100) : 0,
            recentWeek: recent
        };
        
        console.log('통계 결과:', stats);
        
        res.json({
            success: true,
            stats: stats
        });
    } catch (error) {
        console.error('학생 통계 조회 오류:', error);
        console.error('에러 상세:', error.stack);
        res.json({ 
            success: false, 
            stats: null,
            error: error.message 
        });
    }
});

app.get('/admin/user-all-records/:userId', requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.userId);
    
    try {
        console.log('=== 전체 기록 조회 시작 ===');
        console.log('사용자 ID:', userId);
        console.log('전체 기록 수:', memoryDB.trainingRecords.length);
        
        // 해당 사용자의 모든 기록 가져오기
        const allRecords = memoryDB.trainingRecords.filter(r => r.user_id === userId);
        
        console.log('사용자 기록 수:', allRecords.length);
        
        if (allRecords.length === 0) {
            return res.json({ 
                success: true, 
                dailyRecords: [] 
            });
        }
        
        // 날짜별로 그룹화
        const dateGroups = {};
        
        allRecords.forEach(record => {
            const date = record.date;
            
            if (!dateGroups[date]) {
                dateGroups[date] = {
                    date: date,
                    level: record.level,
                    difficulty_range: record.difficulty_range || '-',
                    daily_attempts: 0,
                    correct_count: 0,
                    total_actual_count: 0,
                    records: []
                };
            }
            
            dateGroups[date].daily_attempts++;
            if (record.is_correct) {
                dateGroups[date].correct_count++;
            }
            dateGroups[date].total_actual_count += parseInt(record.actual_count);
            dateGroups[date].records.push({
                id: record.id,
                actual_count: record.actual_count,
                user_answer: record.user_answer,
                is_correct: record.is_correct,
                timestamp: record.timestamp
            });
        });
        
        // 배열로 변환하고 정렬
        const dailyRecords = Object.values(dateGroups).map(group => ({
            date: group.date,
            level: group.level,
            difficulty_range: group.difficulty_range,
            daily_attempts: group.daily_attempts,
            correct_count: group.correct_count,
            avg_actual_count: Math.round(group.total_actual_count / group.daily_attempts),
            records: group.records.sort((a, b) => a.timestamp.localeCompare(b.timestamp))
        })).sort((a, b) => b.date.localeCompare(a.date));
        
        console.log('날짜별 그룹 수:', dailyRecords.length);
        console.log('첫 번째 날짜:', dailyRecords[0]);
        
        res.json({ 
            success: true, 
            dailyRecords: dailyRecords
        });
    } catch (error) {
        console.error('전체 기록 조회 오류:', error);
        console.error('에러 상세:', error.stack);
        res.json({ 
            success: false, 
            dailyRecords: [],
            error: error.message 
        });
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
            const result = await query("SELECT value FROM settings WHERE key = $1", ['allow_password_change']);
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

// 단계 완료 처리
app.post('/complete-step', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.json({ success: false, message: '관리자는 단계를 완료할 수 없습니다.' });
        return;
    }

    const { step } = req.body;
    const userId = req.session.userId;
    const today = getTodayKST();
    
    console.log('=== 단계 완료 요청 ===');
    console.log('userId:', userId, 'step:', step, 'today:', today);
    
    try {
        // 오늘 날짜의 완료 기록 찾기
        let completion = memoryDB.stepCompletions.find(sc => 
            sc.user_id === userId && sc.date === today
        );
        
        if (!completion) {
            // 새로운 기록 생성
            completion = {
                id: stepCompletionIdCounter++,
                user_id: userId,
                date: today,
                step1: step === 1,
                step2: step === 2,
                step3: step === 3,
                step4: step === 4,
                step5: step === 5,
                completed_at: new Date().toISOString()
            };
            memoryDB.stepCompletions.push(completion);
            console.log('✅ 새로운 완료 기록 생성:', completion);
        } else {
            // 기존 기록 업데이트
            completion[`step${step}`] = true;
            completion.completed_at = new Date().toISOString();
            console.log('✅ 기존 기록 업데이트:', completion);
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ 단계 완료 처리 오류:', error);
        res.json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
});

// 오늘의 단계 완료 현황 조회 (관리자용)
app.get('/admin/today-steps', requireAdmin, async (req, res) => {
    const today = getTodayKST();
    
    try {
        const completions = memoryDB.stepCompletions.filter(sc => sc.date === today);
        const users = memoryDB.users.filter(u => !u.is_admin);
        
        const results = users.map(user => {
            const completion = completions.find(c => c.user_id === user.id);
            return {
                id: user.id,
                username: user.username,
                step1: completion?.step1 || false,
                step2: completion?.step2 || false,
                step3: completion?.step3 || false,
                step4: completion?.step4 || false,
                step5: completion?.step5 || false,
                completed_count: [
                    completion?.step1,
                    completion?.step2,
                    completion?.step3,
                    completion?.step4,
                    completion?.step5
                ].filter(Boolean).length
            };
        });
        
        res.json({ success: true, data: results });
    } catch (error) {
        console.error('단계 현황 조회 오류:', error);
        res.json({ success: false, data: [] });
    }
});

// 이번 달 랭킹 조회 (학생용)
app.get('/ranking', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1;
    
    // 2026년 1월 1일 이전이면 접근 불가
    if (currentYear < 2026 || (currentYear === 2026 && currentMonth < 1)) {
        return res.render('ranking', {
            username: req.session.username,
            rankings: [],
            myRank: null,
            currentMonth: `${currentYear}년 ${currentMonth}월`,
            isActive: false,
            activationDate: '2026년 1월 1일'
        });
    }
    
    const rankings = calculateMonthlyRanking(currentYear, currentMonth);
    const myRank = rankings.findIndex(r => r.user_id === req.session.userId) + 1;
    const myData = rankings.find(r => r.user_id === req.session.userId);
    
    // 개인 목표 조회
    const goal = memoryDB.personalGoals.find(g => 
        g.user_id === req.session.userId && g.month === `${currentYear}-${String(currentMonth).padStart(2, '0')}`
    );
    
    const titles = checkTitles(req.session.userId);
    
    res.render('ranking', {
        username: req.session.username,
        rankings: rankings.slice(0, 5),
        myRank,
        myData,
        totalUsers: rankings.length,
        currentMonth: `${currentYear}년 ${currentMonth}월`,
        goal,
        titles,
        isActive: true
    });
});

// 개인 목표 설정
app.post('/set-goal', requireAuth, async (req, res) => {
    if (req.session.isAdmin) {
        res.json({ success: false, message: '관리자는 목표를 설정할 수 없습니다.' });
        return;
    }
    
    const { targetRank } = req.body;
    const userId = req.session.userId;
    const now = new Date();
    const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    
    try {
        const existingGoal = memoryDB.personalGoals.find(g => 
            g.user_id === userId && g.month === currentMonth
        );
        
        if (existingGoal) {
            existingGoal.target_rank = parseInt(targetRank);
            existingGoal.updated_at = new Date().toISOString();
        } else {
            memoryDB.personalGoals.push({
                id: goalIdCounter++,
                user_id: userId,
                month: currentMonth,
                target_rank: parseInt(targetRank),
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('목표 설정 오류:', error);
        res.json({ success: false, message: '목표 설정에 실패했습니다.' });
    }
});

// 전체 랭킹 조회 (관리자용)
app.get('/admin/full-ranking', requireAdmin, (req, res) => {
    const now = new Date();
    const year = parseInt(req.query.year) || now.getFullYear();
    const month = parseInt(req.query.month) || (now.getMonth() + 1);
    
    const rankings = calculateMonthlyRanking(year, month);
    
    res.json({
        success: true,
        rankings,
        year,
        month
    });
});

// 배지 수여 (관리자용)
app.post('/admin/award-badges', requireAdmin, async (req, res) => {
    const { year, month } = req.body;
    const targetMonth = `${year}-${String(month).padStart(2, '0')}`;
    
    try {
        const rankings = calculateMonthlyRanking(year, month);
        
        memoryDB.badges = memoryDB.badges.filter(b => b.month !== targetMonth);
        
        const badgeTypes = [
            { rank: 1, type: 'gold', name: '골드 배지', reward: '5,000원' },
            { rank: 2, type: 'silver', name: '실버 배지', reward: '4,000원' },
            { rank: 3, type: 'bronze', name: '브론즈 배지', reward: '3,000원' },
            { rank: 4, type: 'excellence', name: '우수 배지', reward: '2,000원' },
            { rank: 5, type: 'excellence', name: '우수 배지', reward: '1,000원' }
        ];
        
        badgeTypes.forEach((badge, index) => {
            if (rankings[index]) {
                memoryDB.badges.push({
                    id: badgeIdCounter++,
                    user_id: rankings[index].user_id,
                    username: rankings[index].username,
                    rank: badge.rank,
                    badge_type: badge.type,
                    badge_name: badge.name,
                    reward: badge.reward,
                    month: targetMonth,
                    awarded_at: new Date().toISOString()
                });
            }
        });
        
        res.json({ success: true, message: '배지가 수여되었습니다.' });
    } catch (error) {
        console.error('배지 수여 오류:', error);
        res.json({ success: false, message: '배지 수여에 실패했습니다.' });
    }
});

// 내 배지 조회
app.get('/my-badges', requireAuth, (req, res) => {
    if (req.session.isAdmin) {
        res.redirect('/admin');
        return;
    }
    
    const myBadges = memoryDB.badges.filter(b => b.user_id === req.session.userId);
    
    res.render('my-badges', {
        username: req.session.username,
        badges: myBadges.sort((a, b) => b.awarded_at.localeCompare(a.awarded_at))
    });
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
process.on('SIGINT', () => {
    console.log('\n🛑 서버 종료 중...');
    console.log('✅ 메모리 데이터 정리됨');
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
        console.log(`💾 메모리 데이터베이스 사용 (서버 재시작시 데이터 삭제)`);
        console.log(`👑 관리자 계정: readin / admin123`);
        console.log(`🎵 소리 재생 속도: 100 BPM`);
        console.log(`===============================================\n`);
        
        // Keep-Alive 시스템 (10분마다 자체 ping)
        setInterval(() => {
            const url = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
            
            fetch(`${url}/health`)
                .then(res => res.json())
                .then(data => {
                    console.log(`✅ Keep-Alive: ${data.timestamp} (Uptime: ${data.uptime}초, Users: ${data.users}, Records: ${data.records})`);
                })
                .catch(err => {
                    console.log(`⚠️ Keep-Alive 실패: ${err.message}`);
                });
        }, 10 * 60 * 1000); // 10분마다
        
        console.log('⏰ Keep-Alive 시스템 활성화 (10분 간격)');
        console.log('🔄 서버가 자동으로 깨어있는 상태를 유지합니다');
        console.log('💡 권장: UptimeRobot(https://uptimerobot.com)으로 외부 모니터링 추가\n');
    });
}).catch(error => {
    console.error('서버 시작 실패:', error);
    process.exit(1);
});
