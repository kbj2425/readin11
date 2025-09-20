# READIN 집중력 훈련 애플리케이션

리드인 독서논술코칭 방이센터의 집중력 향상을 위한 웹 기반 훈련 시스템입니다.

## 🎯 시스템 개요

### 훈련 방식
100 BPM 속도로 재생되는 비프음의 반복 횟수를 정확히 세어 답변하는 집중력 훈련입니다. 실제 횟수의 ±1 범위 내 답변은 정답으로 인정됩니다.

### 게임 규칙
- 하루 2회 기본 훈련 기회 제공
- 관리자가 추가 기회 부여 가능
- 매일 난이도가 자동으로 조정됩니다

## 👥 사용자 기능

### 참가자
- 일일 집중력 훈련 참여
- 개인 훈련 기록 및 통계 조회
- 비밀번호 변경
- 자동 회원가입 (관리자 허용 시)

### 관리자
- 참가자 계정 관리
- 훈련 기록 조회 및 분석
- 시스템 설정 관리
- 통계 및 성과 분석

## 🔧 기술 스택

- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL
- **Frontend**: EJS 템플릿, Vanilla JavaScript
- **Audio**: Web Audio API (실시간 비프음 생성)
- **Session**: express-session
- **Security**: bcrypt 비밀번호 암호화

## 🚀 배포 방법

### Render.com 배포

1. **GitHub 저장소 준비**
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
   - Build Command: `npm install`
   - Start Command: `npm start`
   - Node Version: 18+

3. **PostgreSQL 데이터베이스 생성**
   - Render에서 PostgreSQL 서비스 생성
   - Internal Database URL 복사

4. **환경 변수 설정**
   - `DATABASE_URL`: PostgreSQL 연결 URL
   - `NODE_ENV`: `production`

### 로컬 개발 환경

```bash
# 의존성 설치
npm install

# 개발 서버 실행
npm run dev

# 프로덕션 서버 실행
npm start
```

## 📱 주요 기능

### 훈련 시스템
- 실시간 비프음 생성 및 재생
- 정확한 타이밍 기반 난이도 조정
- 시각적 피드백 제공

### 데이터 관리
- 모든 훈련 기록 영구 저장
- 개인별 성과 통계
- 날짜별 기록 조회

### 보안 기능
- 비밀번호 암호화 저장
- 세션 기반 인증
- 권한별 접근 제어

## 🔍 문제 해결

### 일반적인 문제
- **소리가 안 들림**: 브라우저 자동재생 정책으로 인한 문제, 사용자 상호작용 후 재시도
- **데이터 오류**: PostgreSQL 연결 상태 확인
- **세션 문제**: 브라우저 쿠키 설정 확인

### 배포 관련
- **빌드 실패**: Node.js 버전 확인 (18+ 권장)
- **데이터베이스 연결**: DATABASE_URL 환경변수 확인
- **포트 설정**: PORT 환경변수 자동 설정 확인

## 📞 지원

문제 발생 시 확인사항:
1. 브라우저 개발자 도구 콘솔 오류 확인
2. 네트워크 연결 상태 확인
3. 환경변수 설정 확인

## 📄 라이선스

MIT License - 교육 목적으로 자유롭게 사용 가능합니다.

---

**개발**: 리드인 독서논술코칭 방이센터  
**목적**: 학습자 집중력 향상 및 인지능력 개발
