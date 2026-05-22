const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data', 'community.db');
const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key'; 

app.use(cors());
app.use(express.json());

// 정적 자원 폴더 서빙 (이미지 등 자원용)
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
  }

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // 1. 유저 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT NOT NULL UNIQUE,
      password   TEXT NOT NULL,
      nickname   TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'USER',
      created_at TEXT DEFAULT (datetime('now','localtime'))
    )
  `);

  // 2. 게시글 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER,
      title      TEXT NOT NULL,
      body       TEXT NOT NULL,
      tag        TEXT NOT NULL DEFAULT '잡담',
      nick       TEXT NOT NULL DEFAULT '익명',
      up         INTEGER DEFAULT 0,
      down       INTEGER DEFAULT 0,
      views      INTEGER DEFAULT 0,
      hot        INTEGER DEFAULT 0,
      has_img    INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    )
  `);

  // 3. 댓글 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id    INTEGER NOT NULL,
      user_id    INTEGER,
      nick       TEXT NOT NULL DEFAULT '익명',
      body       TEXT NOT NULL,
      up         INTEGER DEFAULT 0,
      down       INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
    )
  `);

  // 4. 게시글 중복 추천 방지 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS votes (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id   INTEGER NOT NULL,
      uuid      TEXT NOT NULL,
      type      TEXT NOT NULL,
      UNIQUE(post_id, uuid)
    )
  `);

  // 5. 댓글 중복 추천 방지 테이블
  db.run(`
    CREATE TABLE IF NOT EXISTS comment_votes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      comment_id  INTEGER NOT NULL,
      uuid        TEXT NOT NULL,
      type        TEXT NOT NULL,
      UNIQUE(comment_id, uuid)
    )
  `);

  // 하위 호환용 컬럼 예외 처리
  try { db.exec("SELECT tag FROM posts LIMIT 1"); } catch (e) {
    try { db.run("ALTER TABLE posts ADD COLUMN tag TEXT NOT NULL DEFAULT '잡담'"); } catch(err){}
  }
  try { db.exec("SELECT up FROM comments LIMIT 1"); } catch (e) {
    try { db.run("ALTER TABLE comments ADD COLUMN up INTEGER DEFAULT 0"); } catch(err){}
    try { db.run("ALTER TABLE comments ADD COLUMN down INTEGER DEFAULT 0"); } catch(err){}
  }

  // 최고 관리자 자동 생성
  const adminCheck = db.exec("SELECT COUNT(*) as cnt FROM users WHERE role='ADMIN'")[0].values[0][0];
  if (adminCheck === 0) {
    const hashedAdminPw = bcrypt.hashSync('admin1234', 10);
    db.run("INSERT INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)", ['admin', hashedAdminPw, '최고관리자', 'ADMIN']);
    saveDB();
  }

  console.log('✅ 데이터베이스 초기화 완료');
}

function saveDB() {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === 'production') return;
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err) {
    console.error("⚠️ DB 파일 저장 실패:", err);
  }
}

function query(sql, params = []) {
  const res = db.exec(sql, params);
  if (!res.length) return [];
  const { columns, values } = res[0];
  return values.map(row => Object.fromEntries(columns.map((col, i) => [col, row[i]])));
}

function run(sql, params = []) {
  db.run(sql, params);
  saveDB();
  const res = db.exec('SELECT last_insert_rowid() as id');
  return res[0]?.values[0][0] || null;
}

// ── 🛡️ 미들웨어 ───────────────────────────────────────────────────────────────

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '인증 토큰이 유효하지 않습니다.' });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  next();
}

// ── 🔑 API 라우트 영역 ─────────────────────────────────────────────────────────

app.post('/api/auth/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username?.trim() || !password?.trim() || !nickname?.trim()) return res.status(400).json({ error: '모든 칸을 입력해 주세요.' });
  if (query('SELECT * FROM users WHERE username = ?', [username.trim()]).length > 0) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });

  run('INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)', [username.trim(), bcrypt.hashSync(password, 10), nickname.trim()]);
  res.status(201).json({ success: true });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = query('SELECT * FROM users WHERE username = ?', [username]);
  if (users.length === 0 || !bcrypt.compareSync(password, users[0].password)) {
    return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  }
  const user = users[0];
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, nickname: user.nickname }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token, user: { username: user.username, nickname: user.nickname, role: user.role } });
});

app.get('/api/posts', (req, res) => {
  const { tab = 'all', page = 1, q = '', tag = '' } = req.query;
  const perPage = 10;
  const offset = (parseInt(page) - 1) * perPage;
  let where = '1=1';
  const params = [];

  if (tab === 'hot') where += ' AND hot=1';
  if (tag && tag !== '전체') { where += ' AND tag = ?'; params.push(tag); }
  if (q) { where += ' AND (title LIKE ? OR body LIKE ?)'; params.push(`%${q}%`, `%${q}%`); }

  const total = query(`SELECT COUNT(*) as cnt FROM posts WHERE ${where}`, params)[0]?.cnt || 0;
  const posts = query(
    `SELECT p.*, (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count 
     FROM posts p WHERE ${where} ORDER BY p.id DESC LIMIT ? OFFSET ?`, [...params, perPage, offset]
  );
  res.json({ posts, total, page: parseInt(page), perPage });
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  run('UPDATE posts SET views = views + 1 WHERE id = ?', [id]);
  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  if (!posts.length) return res.status(404).json({ error: '게시글이 존재하지 않습니다.' });
  const comments = query('SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC', [id]);
  res.json({ post: posts[0], comments });
});

app.post('/api/posts', authenticateToken, (req, res) => {
  const { title, body, tag = '잡담' } = req.body;
  if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: '제목과 내용을 적어주세요.' });
  if (tag === '공지' && req.user.role !== 'ADMIN') return res.status(403).json({ error: '공지 권한 없음' });

  const id = run('INSERT INTO posts (user_id, title, body, tag, nick) VALUES (?,?,?,?,?)', [req.user.id, title.trim(), body.trim(), tag, req.user.nickname]);
  res.status(201).json({ id });
});

app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const postId = parseInt(req.params.id);
  const { body } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: '댓글 내용을 적어주세요.' });

  run('INSERT INTO comments (post_id, user_id, nick, body) VALUES (?,?,?,?)', [postId, req.user.id, req.user.nickname, body.trim()]);
  res.status(201).json({ success: true });
});

app.post('/api/posts/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type, uuid } = req.body; 
  if (!['up', 'down'].includes(type) || !uuid) return res.status(400).json({ error: '올바르지 않은 요청입니다.' });

  const exist = query('SELECT type FROM votes WHERE post_id = ? AND uuid = ?', [id, uuid]);
  if (exist.length > 0) {
    return res.status(400).json({ error: `이미 이 게시글에 ${exist[0].type === 'up' ? '개추' : '비추'}를 누르셨습니다.` });
  }

  try {
    run('INSERT INTO votes (post_id, uuid, type) VALUES (?, ?, ?)', [id, uuid, type]);
    run(`UPDATE posts SET ${type} = ${type} + 1 WHERE id = ?`, [id]);
    run('UPDATE posts SET hot = 1 WHERE id = ? AND up >= 5', [id]);
    const updated = query('SELECT up, down FROM posts WHERE id = ?', [id])[0];
    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: '투표 처리 중 오류가 발생했습니다.' });
  }
});

app.post('/api/comments/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type, uuid } = req.body;
  if (!['up', 'down'].includes(type) || !uuid) return res.status(400).json({ error: '올바르지 않은 요청입니다.' });

  const exist = query('SELECT type FROM comment_votes WHERE comment_id = ? AND uuid = ?', [id, uuid]);
  if (exist.length > 0) {
    return res.status(400).json({ error: `이미 이 댓글에 ${exist[0].type === 'up' ? '추천' : '비추천'}을 누르셨습니다.` });
  }

  try {
    run('INSERT INTO comment_votes (comment_id, uuid, type) VALUES (?, ?, ?)', [id, uuid, type]);
    run(`UPDATE comments SET ${type} = ${type} + 1 WHERE id = ?`, [id]);
    const updated = query('SELECT up, down FROM comments WHERE id = ?', [id])[0];
    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: '댓글 투표 처리 실패' });
  }
});

// ── 👑 관리자 라우트 영역 ──────────────────────────────────────────────────────

app.delete('/api/admin/posts/:id', authenticateToken, isAdmin, (req, res) => {
  run('DELETE FROM posts WHERE id = ?', [parseInt(req.params.id)]);
  res.json({ success: true, message: '게시글이 성공적으로 삭제되었습니다.' });
});

app.delete('/api/admin/comments/:id', authenticateToken, isAdmin, (req, res) => {
  run('DELETE FROM comments WHERE id = ?', [parseInt(req.params.id)]);
  res.json({ success: true, message: '댓글이 성공적으로 삭제되었습니다.' });
});

app.get('/api/stats', (req, res) => {
  const total = query('SELECT COUNT(*) as cnt FROM posts')[0]?.cnt || 0;
  const today = query("SELECT COUNT(*) as cnt FROM posts WHERE date(created_at) = date('now','localtime')")[0]?.cnt || 0;
  const comments = query('SELECT COUNT(*) as cnt FROM comments')[0]?.cnt || 0;
  res.json({ total, today, comments });
});

// ── ⚙️ 라우팅 예외 처리 및 폴백 안전 서빙 ──────────────────────────────────────

// 1. 정의되지 않은 비정상 /api 요청 차단
app.use('/api', (req, res) => {
  res.status(404).json({ error: '존재하지 않는 API 엔드포인트입니다.' });
});

// 2. [완전 박멸 치트키] 외부 HTML 파일 시스템 조회를 전면 차단하고, 
// 보내주신 정상 UI 소스코드(임시.txt의 실체)를 서버메모리에서 즉시 렌더링하여 강제 다운로드시킵니다.
app.use((req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>패럴림픽 커뮤니티</title>
    <script src="https://cdn.jsdelivr.net/npm/lucide@0.344.0/dist/umd/lucide.min.js"></script>
    <style>
        :root {
            --bg-main: #0b0f19; --bg-card: #151d30; --bg-input: #1e2942;
            --text-main: #f1f5f9; --text-muted: #94a3b8; --accent: #3b82f6;
            --accent-hover: #2563eb; --border: #273554; --danger: #ef4444;
        }
        body.light-mode {
            --bg-main: #f8fafc; --bg-card: #ffffff; --bg-input: #f1f5f9;
            --text-main: #0f172a; --text-muted: #64748b; --accent: #3b82f6;
            --accent-hover: #2563eb; --border: #e2e8f0; --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: var(--bg-main); color: var(--text-main); transition: background-color 0.3s, color 0.3s; padding-bottom: 60px; }
        header { background-color: var(--bg-card); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
        .logo-area { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; color: var(--accent); font-weight: bold; font-size: 1.25rem; }
        .nav-actions { display: flex; align-items: center; gap: 1rem; }
        .icon-btn { background: none; border: none; color: var(--text-main); cursor: pointer; padding: 0.5rem; border-radius: 0.375rem; display: flex; align-items: center; justify-content: center; }
        .icon-btn:hover { background-color: var(--bg-input); }
        main { max-width: 1000px; margin: 2rem auto; padding: 0 1rem; }
        .hidden { display: none !important; }
        .card { background-color: var(--bg-card); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.5rem; margin-bottom: 1.5rem; }
        .form-group { margin-bottom: 1.25rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-size: 0.875rem; color: var(--text-muted); }
        .form-control { width: 100%; padding: 0.75rem 1rem; background-color: var(--bg-input); border: 1px solid var(--border); color: var(--text-main); border-radius: 0.5rem; font-size: 1rem; }
        .form-control:focus { outline: 2px solid var(--accent); }
        textarea.form-control { min-height: 150px; resize: vertical; }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 0.5rem; font-size: 1rem; font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 0.5rem; justify-content: center; }
        .btn-primary { background-color: var(--accent); color: white; }
        .btn-primary:hover { background-color: var(--accent-hover); }
        .btn-secondary { background-color: var(--bg-input); color: var(--text-main); border: 1px solid var(--border); }
        .btn-secondary:hover { background-color: var(--border); }
        .btn-danger { background-color: var(--danger); color: white; }
        .btn-block { width: 100%; }
        .post-item { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid var(--border); cursor: pointer; }
        .post-item:last-child { border-bottom: none; }
        .post-meta { display: flex; gap: 1rem; font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: bold; background-color: var(--bg-input); color: var(--text-muted); }
        .badge-notice { background-color: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .comment-item { padding: 1rem 0; border-bottom: 1px solid var(--border); position: relative; }
        .comment-meta { display: flex; justify-content: space-between; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.25rem; }
        .vote-box { display: flex; gap: 0.5rem; align-items: center; margin-top: 0.5rem; }
        .vote-btn { background-color: var(--bg-input); border: 1px solid var(--border); color: var(--text-muted); padding: 0.25rem 0.5rem; border-radius: 0.375rem; cursor: pointer; display: flex; align-items: center; gap: 0.25rem; font-size: 0.85rem; }
        .vote-btn:hover { color: var(--text-main); background-color: var(--border); }
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
        .tab-btn { background: none; border: none; color: var(--text-muted); padding: 0.5rem 1rem; cursor: pointer; font-size: 1rem; position: relative; }
        .tab-btn.active { color: var(--accent); font-weight: bold; }
        .tab-btn.active::after { content: ''; position: absolute; bottom: -0.5rem; left: 0; right: 0; height: 2px; background-color: var(--accent); }
    </style>
</head>
<body>
    <header>
        <div class="logo-area" onclick="goHome()">
            <i data-lucide="messages-square"></i>
            <span>패럴림픽</span>
        </div>
        <div class="nav-actions">
            <button class="icon-btn" onclick="toggleDarkMode()"><i id="theme-icon" data-lucide="moon"></i></button>
            <button class="icon-btn" id="user-menu-btn" onclick="toggleUserMenu()"><i data-lucide="user"></i></button>
        </div>
    </header>

    <main>
        <div id="view-home" class="view">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                <h2>게시판 목록</h2>
                <button class="btn btn-primary" onclick="navigate('write')"><i data-lucide="pen-tool"></i>새 글 쓰기</button>
            </div>
            <div class="tabs">
                <button class="tab-btn active" onclick="changeTab('all', this)">전체글</button>
                <button class="tab-btn" onclick="changeTab('hot', this)">개추글</button>
            </div>
            <div class="card" style="padding: 0 1.5rem;">
                <div id="post-list">
                    <p style="padding: 2rem; text-align: center; color: var(--text-muted);">글을 불러오는 중입니다...</p>
                </div>
            </div>
        </div>

        <div id="view-detail" class="view hidden">
            <button class="btn btn-secondary" onclick="goHome()" style="margin-bottom: 1rem;"><i data-lucide="arrow-left"></i>목록으로</button>
            <div class="card">
                <div style="display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.5rem;">
                    <span class="badge" id="detail-tag">잡담</span>
                    <h2 id="detail-title">제목</h2>
                </div>
                <div class="post-meta" style="margin-bottom: 1.5rem;">
                    <span id="detail-author">작성자</span>
                    <span id="detail-date">날짜</span>
                    <span>조회수 <span id="detail-views">0</span></span>
                </div>
                <hr style="border: none; border-top: 1px solid var(--border); margin-bottom: 1.5rem;">
                <div id="detail-body" style="line-height: 1.6; white-space: pre-wrap; min-height: 100px;">내용</div>
                <div class="vote-box" style="margin-top: 2rem;">
                    <button class="vote-btn" onclick="votePost('up')"><i data-lucide="thumbs-up"></i>개추 <span id="detail-up">0</span></button>
                    <button class="vote-btn" onclick="votePost('down')"><i data-lucide="thumbs-down"></i>비추 <span id="detail-down">0</span></button>
                </div>
            </div>
            <h3>댓글</h3>
            <div class="card" style="margin-top: 0.5rem;">
                <div id="comment-list" style="margin-bottom: 1.5rem;"></div>
                <div style="display: flex; gap: 0.5rem;">
                    <input type="text" id="comment-input" class="form-control" placeholder="댓글을 입력하세요.">
                    <button class="btn btn-primary" onclick="submitComment()">등록</button>
                </div>
            </div>
        </div>

        <div id="view-write" class="view hidden">
            <h2>새 글 쓰기</h2>
            <div class="card" style="margin-top: 1rem;">
                <div class="form-group">
                    <label for="write-tag">말머리</label>
                    <select id="write-tag" class="form-control">
                        <option value="잡담">💬 잡담</option>
                        <option value="질문">❓ 질문</option>
                        <option value="정보">💡 정보</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="write-title">제목</label>
                    <input type="text" id="write-title" class="form-control" placeholder="제목을 입력하세요.">
                </div>
                <div class="form-group">
                    <label for="write-body">내용</label>
                    <textarea id="write-body" class="form-control" placeholder="내용을 입력하세요."></textarea>
                </div>
                <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
                    <button class="btn btn-secondary" onclick="goHome()">취소</button>
                    <button class="btn btn-primary" onclick="submitPost()">등록하기</button>
                </div>
            </div>
        </div>

        <div id="view-auth" class="view hidden">
            <h2 id="auth-title">로그인</h2>
            <div class="card" style="max-width: 400px; margin: 2rem auto;">
                <div class="form-group">
                    <label for="auth-username">아이디</label>
                    <input type="text" id="auth-username" class="form-control">
                </div>
                <div class="form-group">
                    <label for="auth-password">비밀번호</label>
                    <input type="password" id="auth-password" class="form-control">
                </div>
                <div class="form-group hidden" id="fg-nickname">
                    <label for="auth-nickname">닉네임</label>
                    <input type="text" id="auth-nickname" class="form-control">
                </div>
                <button class="btn btn-primary btn-block" id="btn-auth-submit" onclick="handleAuthSubmit()">로그인</button>
                <p style="text-align: center; margin-top: 1rem; font-size: 0.9rem; color: var(--text-muted);">
                    <span id="auth-switch-text">계정이 없으신가요?</span>
                    <a href="#" id="auth-switch-link" onclick="toggleAuthMode(event)" style="color: var(--accent); text-decoration: none; margin-left: 0.25rem;">회원가입</a>
                </p>
            </div>
        </div>
    </main>

    <script>
        const API_URL = window.location.origin;
        let currentView = 'home'; let currentTab = 'all'; let currentPostId = null;
        let isSignUpMode = false;

        function getUUID() {
            let id = localStorage.getItem('user_uuid');
            if(!id) { id = 'uuid_' + Math.random().toString(36).substr(2, 9); localStorage.setItem('user_uuid', id); }
            return id;
        }

        async function apiFetch(path, options = {}) {
            const token = localStorage.getItem('token');
            options.headers = { 'Content-Type': 'application/json', ...options.headers };
            if (token) options.headers['Authorization'] = 'Bearer ' + token;
            
            const r = await fetch(API_URL + path, options);
            if (!r.ok) {
                const errObj = JSON.parse(await r.text() || '{}');
                throw new Error(errObj.error || '네트워크 에러 발생');
            }
            return r.json();
        }

        function toggleDarkMode() {
            document.body.classList.toggle('light-mode');
            const isLight = document.body.classList.contains('light-mode');
            document.getElementById('theme-icon').setAttribute('data-lucide', isLight ? 'sun' : 'moon');
            lucide.createIcons();
        }

        function toggleUserMenu() {
            if(localStorage.getItem('token')) {
                if(confirm('로그아웃 하시겠습니까?')) {
                    localStorage.removeItem('token'); localStorage.removeItem('user');
                    alert('로그아웃 되었습니다.'); goHome();
                }
            } else { navigate('auth'); }
        }

        function navigate(viewName) {
            document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
            const target = document.getElementById('view-' + viewName);
            if(target) target.classList.remove('hidden');
            currentView = viewName;
            if(viewName === 'home') loadPosts();
        }

        function goHome() { navigate('home'); }
        function changeTab(tab, btn) {
            currentTab = tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            loadPosts();
        }

        function toggleAuthMode(e) {
            e.preventDefault(); isSignUpMode = !isSignUpMode;
            document.getElementById('auth-title').innerText = isSignUpMode ? '회원가입' : '로그인';
            document.getElementById('fg-nickname').classList.toggle('hidden', !isSignUpMode);
            document.getElementById('btn-auth-submit').innerText = isSignUpMode ? '회원가입 완료' : '로그인';
            document.getElementById('auth-switch-text').innerText = isSignUpMode ? '이미 계정이 있으신가요?' : '계정이 없으신가요?';
            document.getElementById('auth-switch-link').innerText = isSignUpMode ? '로그인' : '회원가입';
        }

        async function handleAuthSubmit() {
            const username = document.getElementById('auth-username').value;
            const password = document.getElementById('auth-password').value;
            const nickname = document.getElementById('auth-nickname').value;
            try {
                if(isSignUpMode) {
                    await apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, password, nickname }) });
                    alert('회원가입 성공! 로그인해 주세요.'); isSignUpMode = false; toggleAuthMode({preventDefault:()=>{}});
                } else {
                    const res = await apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
                    localStorage.setItem('token', res.token); localStorage.setItem('user', JSON.stringify(res.user));
                    alert(res.user.nickname + '님 환영합니다!'); goHome();
                }
            } catch(e) { alert(e.message); }
        }

        async function loadPosts() {
            try {
                const res = await apiFetch('/api/posts?tab=' + currentTab);
                const list = document.getElementById('post-list');
                list.innerHTML = res.posts.length === 0 ? '<p style="padding:2rem; text-align:center; color:var(--text-muted);">등록된 글이 없습니다.</p>' : '';
                res.posts.forEach(p => {
                    const item = document.createElement('div'); item.className = 'post-item';
                    item.onclick = () => openPost(p.id);
                    item.innerHTML = '<div><div style="font-weight:600; font-size:1.05rem; margin-bottom:0.25rem;"><span class="badge ' + (p.tag==='공지'?'badge-notice':'') + '">' + p.tag + '</span> ' + p.title + ' <span style="color:var(--accent); font-size:0.9rem;">[' + p.comment_count + ']</span></div><div class="post-meta"><span>' + p.nick + '</span><span>' + p.created_at + '</span></div></div><div style="display:flex; align-items:center; gap:0.5rem; color:var(--text-muted); font-size:0.9rem;"><i data-lucide="thumbs-up" style="width:16px;"></i>' + p.up + ' <span>조회 ' + p.views + '</span></div>';
                    list.appendChild(item);
                });
                lucide.createIcons();
            } catch(e) { alert(e.message); }
        }

        async function openPost(id) {
            currentPostId = id;
            try {
                const res = await apiFetch('/api/posts/' + id);
                document.getElementById('detail-tag').innerText = res.post.tag;
                document.getElementById('detail-tag').className = 'badge ' + (res.post.tag==='공지'?'badge-notice':'');
                document.getElementById('detail-title').innerText = res.post.title;
                document.getElementById('detail-author').innerText = res.post.nick;
                document.getElementById('detail-date').innerText = res.post.created_at;
                document.getElementById('detail-views').innerText = res.post.views;
                document.getElementById('detail-body').innerText = res.post.body;
                document.getElementById('detail-up').innerText = res.post.up;
                document.getElementById('detail-down').innerText = res.post.down;
                
                const clist = document.getElementById('comment-list'); clist.innerHTML = '';
                res.comments.forEach(c => {
                    const citem = document.createElement('div'); citem.className = 'comment-item';
                    citem.innerHTML = '<div class="comment-meta"><strong>' + c.nick + '</strong><span>' + c.created_at + '</span></div><div style="line-height:1.4;">' + c.body + '</div><div class="vote-box"><button class="vote-btn" onclick="voteComment(' + c.id + ', \'up\', this)"><i data-lucide="thumbs-up" style="width:14px;"></i>' + c.up + '</button><button class="vote-btn" onclick="voteComment(' + c.id + ', \'down\', this)"><i data-lucide="thumbs-down" style="width:14px;"></i>' + c.down + '</button></div>';
                    clist.appendChild(citem);
                });
                navigate('detail'); lucide.createIcons();
            } catch(e) { alert(e.message); }
        }

        async function submitPost() {
            const title = document.getElementById('write-title').value;
            const body = document.getElementById('write-body').value;
            const tag = document.getElementById('write-tag').value;
            try {
                await apiFetch('/api/posts', { method: 'POST', body: JSON.stringify({ title, body, tag }) });
                document.getElementById('write-title').value = ''; document.getElementById('write-body').value = '';
                goHome();
            } catch(e) { alert(e.message); }
        }

        async function submitComment() {
            const inp = document.getElementById('comment-input');
            if(!inp.value.trim()) return;
            try {
                await apiFetch('/api/posts/' + currentPostId + '/comments', { method: 'POST', body: JSON.stringify({ body: inp.value }) });
                inp.value = ''; openPost(currentPostId);
            } catch(e) { alert(e.message); }
        }

        async function votePost(type) {
            try {
                const res = await apiFetch('/api/posts/' + currentPostId + '/vote', { method: 'POST', body: JSON.stringify({ type, uuid: getUUID() }) });
                document.getElementById('detail-up').innerText = res.up;
                document.getElementById('detail-down').innerText = res.down;
            } catch(e) { alert(e.message); }
        }

        async function voteComment(cid, type, btn) {
            try {
                const res = await apiFetch('/api/comments/' + cid + '/vote', { method: 'POST', body: JSON.stringify({ type, uuid: getUUID() }) });
                openPost(currentPostId);
            } catch(e) { alert(e.message); }
        }

        window.onload = () => { lucide.createIcons(); loadPosts(); };
    </script>
</body>
</html>
  `);
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 서버 정상 작동 포트: ${PORT}`));
});