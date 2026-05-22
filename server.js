const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs'); // 비밀번호 분쇄기(암호화)
const jwt = require('jsonwebtoken'); // 출입증 발급기

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data', 'community.db');
const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key'; // 출입증 위조 방지용 비밀 열쇠

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

  // 1. 유저 테이블 생성 (아이디, 비밀번호, 닉네임, 역할)
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

  // 2. 게시글 테이블 생성 (누가 썼는지 알기 위해 user_id 추가)
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER,
      title      TEXT NOT NULL,
      body       TEXT NOT NULL,
      nick       TEXT NOT NULL DEFAULT '익명',
      up         INTEGER DEFAULT 0,
      down       INTEGER DEFAULT 0,
      views      INTEGER DEFAULT 0,
      hot        INTEGER DEFAULT 0,
      has_img    INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now','localtime'))
    )
  `);

  // 3. 댓글 테이블 생성 (누가 썼는지 알기 위해 user_id 추가)
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id    INTEGER NOT NULL,
      user_id    INTEGER,
      nick       TEXT NOT NULL DEFAULT '익명',
      body       TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
    )
  `);

  // [중요] 최고 관리자 계정이 없으면 자동으로 1개 생성 (ID: admin / PW: admin1234)
  const adminCheck = db.exec("SELECT COUNT(*) as cnt FROM users WHERE role='ADMIN'")[0].values[0][0];
  if (adminCheck === 0) {
    const hashedAdminPw = bcrypt.hashSync('admin1234', 10); // 비밀번호 암호화
    db.run(
      "INSERT INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)",
      ['admin', hashedAdminPw, '최고관리자', 'ADMIN']
    );
    console.log('👑 관리자 계정 생성 완료 (ID: admin / PW: admin1234)');
    saveDB();
  }

  // 샘플 데이터 생성
  const count = db.exec('SELECT COUNT(*) as cnt FROM posts')[0].values[0][0];
  if (count === 0) {
    const samples = [
      ['안녕하세요, 처음 가입했어요!', '이 커뮤니티 처음 가입했는데 잘 부탁드립니다.\n앞으로 많은 이야기 나눠요 :)', '익명고양이', 12, 1, 128, 1],
      ['오늘 점심 뭐 먹었나요? 저는 마라탕 먹었어요', '마라탕 정말 맛있었는데 너무 매워서 혼났습니다...\n여러분은 점심 뭐 드셨어요?', '도넛러버', 8, 0, 64, 1]
    ];
    for (const [title, body, nick, up, down, views, hot] of samples) {
      db.run(
        'INSERT INTO posts (title, body, nick, up, down, views, hot) VALUES (?,?,?,?,?,?,?)',
        [title, body, nick, up, down, views, hot]
      );
    }
    saveDB();
  }

  console.log('✅ 데이터베이스 초기화 완료');
}

function saveDB() {
  if (process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === 'production') {
    return;
  }
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
  return values.map(row =>
    Object.fromEntries(columns.map((col, i) => [col, row[i]]))
  );
}

function run(sql, params = []) {
  db.run(sql, params);
  saveDB();
  const res = db.exec('SELECT last_insert_rowid() as id');
  return res[0]?.values[0][0] || null;
}

// ── 🛡️ 미들웨어 (출입증 검사기들) ───────────────────────────────────────────────

// 1. 로그인한 사람인지 확인하는 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // 헤더에서 토큰 글자만 쏙 빼오기

  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '출입증이 올바르지 않습니다.' });
    req.user = user; // 유저 정보 저장 (id, username, role, nickname)
    next(); // 통과! 다음 일 하러 가세요.
  });
}

// 2. 관리자(ADMIN)가 맞는지 확인하는 미들웨어
function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  }
  next(); // 통과! 관리자가 맞군요.
}


// ── 🔑 API 라우트: 회원가입 & 로그인 ──────────────────────────────────────────────

// 회원가입
app.post('/api/auth/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username?.trim() || !password?.trim() || !nickname?.trim()) {
    return res.status(400).json({ error: '모든 칸을 입력해 주세요.' });
  }

  // 아이디 중복 확인
  const exist = query('SELECT * FROM users WHERE username = ?', [username.trim()]);
  if (exist.length > 0) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });

  // 비밀번호 안전하게 분쇄하기(암호화)
  const hashedPassword = bcrypt.hashSync(password, 10);

  run('INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)', [
    username.trim(),
    hashedPassword,
    nickname.trim()
  ]);

  res.status(201).json({ success: true, message: '회원가입이 완료되었습니다!' });
});

// 로그인 (출입증 발급)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = query('SELECT * FROM users WHERE username = ?', [username]);
  
  if (users.length === 0) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  
  const user = users[0];
  
  // 비밀번호 맞는지 확인
  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

  // 하루짜리 출입증(JWT 토큰) 만들기
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, nickname: user.nickname },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    success: true,
    token: token,
    user: { username: user.username, nickname: user.nickname, role: user.role }
  });
});


// ── 📝 API 라우트: 커뮤니티 기능 ─────────────────────────────────────────────────

// 게시글 목록 보기
app.get('/api/posts', (req, res) => {
  const { tab = 'all', page = 1, q = '' } = req.query;
  const perPage = 10;
  const offset = (parseInt(page) - 1) * perPage;

  let where = '1=1';
  const params = [];

  if (tab === 'hot') { where += ' AND hot=1'; }
  if (q) {
    where += ' AND (title LIKE ? OR body LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }

  const total = query(`SELECT COUNT(*) as cnt FROM posts WHERE ${where}`, params)[0]?.cnt || 0;
  const posts = query(
    `SELECT p.id, p.title, p.nick, p.up, p.down, p.views, p.hot, p.has_img, p.created_at,
            (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
     FROM posts p WHERE ${where} ORDER BY p.id DESC LIMIT ? OFFSET ?`,
    [...params, perPage, offset]
  );

  res.json({ posts, total, page: parseInt(page), perPage });
});

// 게시글 상세 보기
app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  run('UPDATE posts SET views = views + 1 WHERE id = ?', [id]);
  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  if (!posts.length) return res.status(404).json({ error: '게시글 없음' });
  const comments = query('SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC', [id]);
  res.json({ post: posts[0], comments });
});

// 게시글 작성 (로그인한 회원만 가능하게 authenticateToken 미들웨어 추가)
app.post('/api/posts', authenticateToken, (req, res) => {
  const { title, body } = req.body;
  if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: '제목과 내용을 적어주세요.' });
  
  // 로그인한 사람의 정보(req.user)를 사용해 저장
  const id = run('INSERT INTO posts (user_id, title, body, nick) VALUES (?,?,?,?)', [
    req.user.id,
    title.trim(),
    body.trim(),
    req.user.nickname // 자동으로 유저의 닉네임이 들어감
  ]);
  
  if (!id) return res.status(500).json({ error: '데이터 저장 실패' });

  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  res.status(201).json(posts[0]);
});

// 댓글 작성 (로그인한 회원만 가능하게 authenticateToken 미들웨어 추가)
app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const postId = parseInt(req.params.id);
  const { body } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: '댓글 내용을 적어주세요.' });
  
  const id = run('INSERT INTO comments (post_id, user_id, nick, body) VALUES (?,?,?,?)', [
    postId,
    req.user.id,
    req.user.nickname, // 자동으로 유저의 닉네임이 들어감
    body.trim()
  ]);
  
  if (!id) return res.status(500).json({ error: '댓글 저장 실패' });

  const comments = query('SELECT * FROM comments WHERE id = ?', [id]);
  res.status(201).json(comments[0]);
});

// 추천/비추천
app.post('/api/posts/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type } = req.body;
  if (!['up', 'down'].includes(type)) return res.status(400).json({ error: '잘못된 요청' });
  run(`UPDATE posts SET ${type} = ${type} + 1 WHERE id = ?`, [id]);
  run('UPDATE posts SET hot = 1 WHERE id = ? AND up >= 5', [id]);
  const posts = query('SELECT up, down, hot FROM posts WHERE id = ?', [id]);
  res.json(posts[0] || {});
});


// ── 👑 API 라우트: 관리자 전용 기능 ───────────────────────────────────────────────

// 게시글 강제 삭제 (로그인도 해야하고, 관리자여야 통과됨)
app.delete('/api/admin/posts/:id', authenticateToken, isAdmin, (req, res) => {
  const postId = parseInt(req.params.id);
  run('DELETE FROM posts WHERE id = ?', [postId]);
  res.json({ success: true, message: '관리자 권한으로 게시글을 삭제했습니다.' });
});

// 댓글 강제 삭제
app.delete('/api/admin/comments/:id', authenticateToken, isAdmin, (req, res) => {
  const commentId = parseInt(req.params.id);
  run('DELETE FROM comments WHERE id = ?', [commentId]);
  res.json({ success: true, message: '관리자 권한으로 댓글을 삭제했습니다.' });
});


// 통계 데이터 보기
app.get('/api/stats', (req, res) => {
  const total = query('SELECT COUNT(*) as cnt FROM posts')[0]?.cnt || 0;
  const today = query("SELECT COUNT(*) as cnt FROM posts WHERE date(created_at) = date('now','localtime')")[0]?.cnt || 0;
  const comments = query('SELECT COUNT(*) as cnt FROM comments')[0]?.cnt || 0;
  res.json({ total, today, comments });
});

// ── SPA 폴백 라우트 ──────────────────────────────────────────────────────────
// app.get 대신 app.use를 사용하여 최신 Express v5+의 PathError를 원천 차단합니다.
app.use((req, res, next) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 서버 실행 중, 포트: ${PORT}`);
  });
});