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

  // 1. 유저 테이블 생성
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

  // 2. 게시글 테이블 생성
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

  // 기존 DB 하위 호환 tag 컬럼 예외 처리
  try {
    db.exec("SELECT tag FROM posts LIMIT 1");
  } catch (e) {
    try {
      db.run("ALTER TABLE posts ADD COLUMN tag TEXT NOT NULL DEFAULT '잡담'");
      console.log('📝 기존 posts 테이블에 tag(말머리) 컬럼 추가 완료');
    } catch (err) {
      console.error("⚠️ 컬럼 추가 실패:", err);
    }
  }

  // 3. 댓글 테이블 생성
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

  // 최고 관리자 계정 자동 생성
  const adminCheck = db.exec("SELECT COUNT(*) as cnt FROM users WHERE role='ADMIN'")[0].values[0][0];
  if (adminCheck === 0) {
    const hashedAdminPw = bcrypt.hashSync('admin1234', 10);
    db.run(
      "INSERT INTO users (username, password, nickname, role) VALUES (?, ?, ?, ?)",
      ['admin', hashedAdminPw, '최고관리자', 'ADMIN']
    );
    console.log('👑 관리자 계정 생성 완료 (ID: admin / PW: admin1234)');
    saveDB();
  }

  // 샘플 데이터
  const count = db.exec('SELECT COUNT(*) as cnt FROM posts')[0].values[0][0];
  if (count === 0) {
    const samples = [
      ['안녕하세요, 처음 가입했어요!', '이 커뮤니티 처음 가입했는데 잘 부탁드립니다.\n앞으로 많은 이야기 나눠요 :)', '잡담', '익명고양이', 12, 1, 128, 1],
      ['공지사항 필독 바랍니다.', '깨끗한 커뮤니티 환경 조성을 위해 규칙을 준수해 주세요.', '공지', '최고관리자', 30, 0, 512, 1]
    ];
    for (const [title, body, tag, nick, up, down, views, hot] of samples) {
      db.run(
        'INSERT INTO posts (title, body, tag, nick, up, down, views, hot) VALUES (?,?,?,?,?,?,?,?)',
        [title, body, tag, nick, up, down, views, hot]
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

// ── 🛡️ 미들웨어 ───────────────────────────────────────────────────────────────

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: '출입증이 올바르지 않습니다.' });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  }
  next();
}

// ── 🔑 API 라우트: 회원가입 & 로그인 ──────────────────────────────────────────────

app.post('/api/auth/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username?.trim() || !password?.trim() || !nickname?.trim()) {
    return res.status(400).json({ error: '모든 칸을 입력해 주세요.' });
  }

  const exist = query('SELECT * FROM users WHERE username = ?', [username.trim()]);
  if (exist.length > 0) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });

  const hashedPassword = bcrypt.hashSync(password, 10);

  run('INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)', [
    username.trim(),
    hashedPassword,
    nickname.trim()
  ]);

  res.status(201).json({ success: true, message: '회원가입이 완료되었습니다!' });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = query('SELECT * FROM users WHERE username = ?', [username]);
  
  if (users.length === 0) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  
  const user = users[0];
  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

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

// ── 📝 API 라우트: 커뮤니티 기능 (말머리 필터 조건 추가) ─────────────────────────

app.get('/api/posts', (req, res) => {
  const { tab = 'all', page = 1, q = '', tag = '' } = req.query;
  const perPage = 10;
  const offset = (parseInt(page) - 1) * perPage;

  let where = '1=1';
  const params = [];

  if (tab === 'hot') { where += ' AND hot=1'; }
  
  // ★ 프론트엔드에서 말머리 필터를 선택했을 경우 SQL에 바인딩
  if (tag && tag !== '전체') {
    where += ' AND tag = ?';
    params.push(tag);
  }

  if (q) {
    where += ' AND (title LIKE ? OR body LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }

  const total = query(`SELECT COUNT(*) as cnt FROM posts WHERE ${where}`, params)[0]?.cnt || 0;
  const posts = query(
    `SELECT p.id, p.title, p.tag, p.nick, p.up, p.down, p.views, p.hot, p.has_img, p.created_at,
            (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
     FROM posts p WHERE ${where} ORDER BY p.id DESC LIMIT ? OFFSET ?`,
    [...params, perPage, offset]
  );

  res.json({ posts, total, page: parseInt(page), perPage });
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  run('UPDATE posts SET views = views + 1 WHERE id = ?', [id]);
  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  if (!posts.length) return res.status(404).json({ error: '게시글 없음' });
  const comments = query('SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC', [id]);
  res.json({ post: posts[0], comments });
});

app.post('/api/posts', authenticateToken, (req, res) => {
  const { title, body, tag = '잡담' } = req.body;
  if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: '제목과 내용을 적어주세요.' });
  
  const allowedTags = ['잡담', '사진', '질문', '공지'];
  const finalTag = allowedTags.includes(tag) ? tag : '잡담';

  if (finalTag === '공지' && req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: '공지사항은 최고 관리자 권한이 필요합니다.' });
  }

  const id = run('INSERT INTO posts (user_id, title, body, tag, nick) VALUES (?,?,?,?,?)', [
    req.user.id,
    title.trim(),
    body.trim(),
    finalTag,
    req.user.nickname
  ]);
  
  if (!id) return res.status(500).json({ error: '데이터 저장 실패' });

  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  res.status(201).json(posts[0]);
});

app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const postId = parseInt(req.params.id);
  const { body } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: '댓글 내용을 적어주세요.' });
  
  const id = run('INSERT INTO comments (post_id, user_id, nick, body) VALUES (?,?,?,?)', [
    postId,
    req.user.id,
    req.user.nickname,
    body.trim()
  ]);
  
  if (!id) return res.status(500).json({ error: '댓글 저장 실패' });

  const comments = query('SELECT * FROM comments WHERE id = ?', [id]);
  res.status(201).json(comments[0]);
});

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

app.delete('/api/admin/posts/:id', authenticateToken, isAdmin, (req, res) => {
  const postId = parseInt(req.params.id);
  run('DELETE FROM posts WHERE id = ?', [postId]);
  res.json({ success: true, message: '관리자 권한으로 게시글을 삭제했습니다.' });
});

app.delete('/api/admin/comments/:id', authenticateToken, isAdmin, (req, res) => {
  const commentId = parseInt(req.params.id);
  run('DELETE FROM comments WHERE id = ?', [commentId]);
  res.json({ success: true, message: '관리자 권한으로 댓글을 삭제했습니다.' });
});

app.get('/api/stats', (req, res) => {
  const total = query('SELECT COUNT(*) as cnt FROM posts')[0]?.cnt || 0;
  const today = query("SELECT COUNT(*) as cnt FROM posts WHERE date(created_at) = date('now','localtime')")[0]?.cnt || 0;
  const comments = query('SELECT COUNT(*) as cnt FROM comments')[0]?.cnt || 0;
  res.json({ total, today, comments });
});

// ── SPA 폴백 및 라우터 매칭 차단 예외처리 ────────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) {
    return res.status(404).json({ error: '존재하지 않는 API 엔드포인트입니다.' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 서버 실행 중, 포트: ${PORT}`);
  });
});