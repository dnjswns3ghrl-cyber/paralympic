# 패럴림픽 — 개인 커뮤니티 사이트

Node.js + SQL.js(SQLite) 기반 커뮤니티 사이트입니다.

## 로컬 실행

```bash
npm install
npm start
# → http://localhost:3000
```

## 무료 인터넷 배포 방법

### 방법 1: Railway (가장 간단, 추천 ⭐)

1. https://railway.app 에서 GitHub로 회원가입
2. 이 폴더를 GitHub 저장소에 올리기
   ```bash
   git init
   git add .
   git commit -m "init"
   # GitHub에서 새 repo 만든 후:
   git remote add origin https://github.com/YOUR_NAME/paralympic.git
   git push -u origin main
   ```
3. Railway → "New Project" → "Deploy from GitHub Repo" 선택
4. 저장소 선택하면 자동 배포! 도메인 자동 발급

### 방법 2: Render (무료, 슬립 있음)

1. https://render.com 에서 GitHub로 회원가입
2. "New Web Service" → GitHub 저장소 선택
3. 설정:
   - Build Command: `npm install`
   - Start Command: `npm start`
4. "Create Web Service" 클릭 → 배포 완료

### 방법 3: Fly.io (무료 티어)

```bash
npm install -g flyctl
fly auth login
fly launch
fly deploy
```

## 데이터 영구 저장 (중요)

Railway/Render는 파일 시스템이 재시작 시 초기화됩니다.
데이터를 영구 보존하려면:

### Railway Volume 사용
Railway 프로젝트 → Volumes → "Add Volume" → 마운트 경로: `/app/data`

### 환경변수 설정
```
PORT=3000
```

## 파일 구조
```
paralympic/
├── server.js        # 백엔드 서버
├── package.json     
├── public/
│   └── index.html   # 프론트엔드
└── data/            # SQLite DB (자동 생성)
    └── community.db
```

## 기능
- ✅ 게시글 작성/조회/목록
- ✅ 댓글
- ✅ 추천/비추천 (HOT 자동 선정)
- ✅ 갤러리 탭
- ✅ 실시간 검색
- ✅ 다크모드 (localStorage 저장)
- ✅ 조회수 카운트
- ✅ 페이지네이션
- ✅ 사이드바 인기글/통계
