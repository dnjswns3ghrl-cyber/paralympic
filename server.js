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

// [정상화] public 폴더 자체를 정적 라우터 표준으로 지정하되, API 요청과 절대 겹치지 않게 순서를 정렬합니다.
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

  // 하위 호환용 컬럼 예외 처리 (기존 코드 유지)
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

// ── 🛡️ 미들웨어 (기존 코드 유지) ─────────────────────────────────────────────────

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

// [교정] 매개변수 오타 react -> req 수정 완료
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

// ── ⚙️ 라우팅 예외 처리 영역 ──────────────────────────────────────────────────

// [교정] 명시되지 않은 비정상 /api/* 요청만 404 차단하도록 명확히 분리
app.use('/api', (req, res) => {
  res.status(404).json({ error: '존재하지 않는 API 엔드포인트입니다.' });
});

// 모든 일반 페이지 주소 진입 시 public/index.html로 정상 포워딩 (SPA 라우팅 규칙)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 서버 정상 작동 포트: ${PORT}`));
});