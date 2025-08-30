# READIN 집중력 훈련 애플리케이션

리드인 독서논술코칭 방이센터의 집중력 훈련을 위한 웹 애플리케이션입니다.

## 🎯 주요 기능

### 👑 관리자 기능 (readin)
- **참가자 관리**: 검색, 레벨 설정, 계정 생성/삭제
- **시스템 설정**: 자동 회원가입 및 비밀번호 변경 허용 제어
- **훈련 기록 조회**: 날짜별 모든 참가자의 훈련 결과 확인
- **추가 기회 부여**: 특정 참가자에게 보너스 도전 기회 제공
- **강제 비밀번호 변경**: 참가자의 비밀번호 직접 변경

### 👨‍🎓 참가자 기능
- **집중력 훈련**: 소리 반복 횟수 맞추기 게임
- **일일 도전**: 하루 2회 기본 도전 기회 + 관리자 부여 보너스
- **개인 기록 조회**: 모든 과거 훈련 결과 확인
- **자동 회원가입**: 관리자 허용시 초기 비밀번호로 계정 생성

## 📊 동적 난이도 시스템

매일 한국 표준시(KST) 자정을 기준으로 난이도가 자동 상승합니다:

- **레벨 1 (초급)**: 10-19 → 30-39 (3일 주기)
- **레벨 2 (중급)**: 10-19 → 60-69 (6일 주기)  
- **레벨 3 (기본)**: 30-39 → 180-189 (16일 주기)

## 🎮 게임 규칙

1. 소리가 반복되는 횟수를 정확히 세기
2. 실제 횟수 ±1 범위 내 답변은 정답 처리
3. 하루 2회 기본 도전 기회 (관리자가 추가 기회 부여 가능)

## 🚀 배포 방법

### Render 배포

1. **GitHub 저장소 생성**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin [YOUR_GITHUB_REPO_URL]
   git push -u origin main
   ```

2. **Render 설정**
   - [Render.com](https://render.com)에서 새 Web Service 생성
   - GitHub 저장소 연결
   - 다음 설정 사용:
     - **Build Command**: `npm install`
     - **Start Command**: `npm start`
     - **Node Version**: 18 이상

3. **환경 변수 설정** (필요시)
   - `NODE_ENV`: `production`

### 로컬 실행

1. **의존성 설치**
   ```bash
   npm install
   ```

2. **개발 서버 실행**
   ```bash
   npm run dev
   ```

3. **프로덕션 서버 실행**
   ```bash
   npm start
   ```

## 🔧 기술 스택

- **Backend**: Node.js, Express.js
- **Database**: SQLite3
- **Frontend**: EJS 템플릿, Vanilla JavaScript
- **Session**: express-session
- **Authentication**: bcrypt
- **Date/Time**: moment-timezone (KST 지원)

## 📝 데이터베이스 구조

### users 테이블
- `id`: 사용자 고유 ID
- `username`: 사용자 이름
- `password`: 암호화된 비밀번호
- `is_admin`: 관리자 여부
- `level`: 훈련 레벨 (1-3)

### training_records 테이블
- `id`: 기록 고유 ID
- `user_id`: 사용자 ID (외래키)
- `actual_count`: 실제 소리 반복 횟수
- `user_answer`: 사용자 답변
- `is_correct`: 정답 여부
- `level`: 훈련 시 레벨
- `date`: 훈련 날짜
- `timestamp`: 훈련 시각

### daily_attempts 테이블
- `id`: 기록 고유 ID
- `user_id`: 사용자 ID (외래키)
- `date`: 날짜
- `attempts`: 일반 시도 횟수
- `bonus_attempts`: 보너스 시도 횟수

### settings 테이블
- `key`: 설정 키
- `value`: 설정 값

## 🎨 디자인 특징

- **컬러 테마**: 분홍색 계열 (`#FFC0CB`, `#FF69B4`)
- **반응형 디자인**: 모바일 및 데스크톱 지원
- **사용자 친화적**: 드롭다운 메뉴, 모달, 애니메이션
- **접근성**: 키보드 탐색, 시각적 피드백

## 🔐 보안 기능

- **비밀번호 암호화**: bcrypt 해싱
- **세션 관리**: express-session
- **권한 제어**: 관리자/참가자 구분
- **입력 검증**: 프론트엔드/백엔드 이중 검증

## 📱 주요 페이지

1. **로그인 페이지** (`/`)
   - 기본 로그인
   - 자동 회원가입 (관리자 설정시)

2. **대시보드** (`/dashboard`)
   - 남은 도전 기회 표시
   - 개인 훈련 기록 조회
   - 현재 난이도 정보

3. **훈련 페이지** (`/training`)
   - 소리 재생 및 시각적 피드백
   - 답변 입력 및 결과 표시

4. **관리자 패널** (`/admin`)
   - 참가자 관리
   - 시스템 설정
   - 훈련 기록 조회

5. **비밀번호 변경** (`/change-password`)
   - 현재/새 비밀번호 입력
   - 유효성 검증

## 🚀 API 엔드포인트

### 인증
- `POST /login`: 로그인 및 자동 회원가입
- `GET /logout`: 로그아웃

### 사용자
- `GET /dashboard`: 참가자 대시보드
- `GET /training`: 훈련 페이지
- `POST /submit-answer`: 훈련 답변 제출
- `POST /change-password`: 비밀번호 변경

### 관리자
- `GET /admin`: 관리자 패널
- `POST /admin/search`: 참가자 검색
- `POST /admin/update-level`: 레벨 변경
- `POST /admin/bonus-attempt`: 추가 기회 부여
- `POST /admin/toggle-setting`: 시스템 설정 토글
- `GET /admin/records/:date`: 날짜별 기록 조회
- `POST /admin/delete-user`: 사용자 삭제
- `POST /admin/force-change-password`: 강제 비밀번호 변경

## 🔧 환경 설정

기본적으로 별도 환경 변수 없이 실행 가능하며, 필요시 다음 설정 가능:

```bash
PORT=3000                    # 서버 포트 (기본: 3000)
NODE_ENV=production          # 환경 모드
```

## 📦 배포 체크리스트

1. ✅ package.json 의존성 확인
2. ✅ Node.js 14+ 환경
3. ✅ SQLite 데이터베이스 자동 생성
4. ✅ 관리자 계정 자동 생성
5. ✅ 정적 파일 서빙 설정
6. ✅ 세션 보안 설정

## 🐛 문제 해결

### 일반적인 문제
- **소리가 안 들림**: 브라우저 자동재생 정책으로 인한 문제, 사용자 상호작용 후 재시도
- **데이터베이스 오류**: SQLite 파일 권한 확인
- **세션 문제**: 브라우저 쿠키 설정 확인

### Render 배포 관련
- **빌드 실패**: Node.js 버전 확인 (18+ 권장)
- **데이터베이스**: Render의 임시 파일 시스템 한계 고려
- **포트**: PORT 환경 변수 자동 설정

## 📞 지원

문제 발생시 다음을 확인해주세요:
1. 브라우저 개발자 도구 콘솔 오류
2. 서버 로그 확인
3. 데이터베이스 연결 상태
4. 네트워크 연결 상태

## 📄 라이선스

MIT License - 교육 목적으로 자유롭게 사용 가능합니다.
