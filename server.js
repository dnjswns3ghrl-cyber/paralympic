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
const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key_change_in_production';

app.use(cors());

// 대용량 Base64 이미지 전송을 위한 파서 제한 확장
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 정적 파일 제공 등록
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function initDB() {
  const SQL = await initSqlJs();
  const dataDir = path.join(__dirname, 'data');

  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT '잡담',
    nick TEXT NOT NULL DEFAULT '익명',
    up INTEGER DEFAULT 0,
    down INTEGER DEFAULT 0,
    views INTEGER DEFAULT 0,
    hot INTEGER DEFAULT 0,
    has_img INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS post_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    img_data TEXT NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER,
    nick TEXT NOT NULL DEFAULT '익명',
    body TEXT NOT NULL,
    up INTEGER DEFAULT 0,
    down INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    type TEXT NOT NULL,
    UNIQUE(post_id, uuid)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS comment_votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER NOT NULL,
    uuid TEXT NOT NULL,
    type TEXT NOT NULL,
    UNIQUE(comment_id, uuid)
  )`);

  // 마이그레이션 안전 점검
  const migrations = [
    ["SELECT tag     FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN tag     TEXT    NOT NULL DEFAULT '잡담'"],
    ["SELECT user_id FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN user_id INTEGER"],
    ["SELECT has_img FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN has_img INTEGER DEFAULT 0"],
    ["SELECT hot     FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN hot     INTEGER DEFAULT 0"],
    ["SELECT up      FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN up      INTEGER DEFAULT 0"],
    ["SELECT down    FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN down    INTEGER DEFAULT 0"],
    ["SELECT views   FROM posts    LIMIT 1", "ALTER TABLE posts    ADD COLUMN views   INTEGER DEFAULT 0"],
    ["SELECT user_id FROM comments LIMIT 1", "ALTER TABLE comments ADD COLUMN user_id INTEGER"],
    ["SELECT up      FROM comments LIMIT 1", "ALTER TABLE comments ADD COLUMN up      INTEGER DEFAULT 0"],
    ["SELECT down    FROM comments LIMIT 1", "ALTER TABLE comments ADD COLUMN down    INTEGER DEFAULT 0"],
  ];
  for (const [check, alter] of migrations) {
    try { db.exec(check); } catch(e) {
      try { db.run(alter); console.log('🔧 마이그레이션:', alter); } catch(err) {}
    }
  }

  const adminCount = db.exec("SELECT COUNT(*) as cnt FROM users WHERE role='ADMIN'")[0].values[0][0];
  if (adminCount === 0) {
    db.run("INSERT INTO users (username, password, nickname, role) VALUES (?,?,?,?)",
      ['admin', bcrypt.hashSync('admin1234', 10), '최고관리자', 'ADMIN']);
    console.log('👑 관리자 계정 생성: admin / admin1234');
  }

  saveDB();
  console.log('✅ DB 초기화 완료');
}

// ── [교정] 데이터 내보내기 시 파일 잠금 유동성 확보를 위해 안전 버퍼 변환 적용 ──
function saveDB() {
  try {
    const dataDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    
    // sql.js 인메모리 데이터를 바이너리 버퍼로 변환 후 동기적 저장 안정화
    const binaryArray = db.export();
    const buffer = Buffer.from(binaryArray);
    fs.writeFileSync(DB_PATH, buffer);
  } catch(err) {
    console.error('⚠️ DB 저장 실패:', err.message);
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
  return db.exec('SELECT last_insert_rowid() as id')[0]?.values[0][0] || null;
}

// 미들웨어
function authenticateToken(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: '토큰이 만료되었거나 유효하지 않습니다. 다시 로그인해 주세요.' });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN')
    return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  next();
}

// ── API 라우트 ───────────────────────────────────────────────────────────────

app.post('/api/auth/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username?.trim() || !password?.trim() || !nickname?.trim())
    return res.status(400).json({ error: '모든 칸을 입력해 주세요.' });
  if (query('SELECT id FROM users WHERE username=?', [username.trim()]).length)
    return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  run('INSERT INTO users (username,password,nickname) VALUES (?,?,?)',
    [username.trim(), bcrypt.hashSync(password, 10), nickname.trim()]);
  res.status(201).json({ success: true });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const users = query('SELECT * FROM users WHERE username=?', [username]);
  if (!users.length || !bcrypt.compareSync(password, users[0].password))
    return res.status(400).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });
  const user = users[0];
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, nickname: user.nickname },
    JWT_SECRET, { expiresIn: '24h' }
  );
  res.json({ success: true, token, user: { username: user.username, nickname: user.nickname, role: user.role } });
});

app.get('/api/posts', (req, res) => {
  const { tab='all', page=1, q='', tag='' } = req.query;
  const perPage = 10, offset = (parseInt(page)-1) * perPage;
  let where = '1=1'; const params = [];
  if (tab === 'hot') where += ' AND hot=1';
  if (tag && tag !== '전체') { where += ' AND tag=?'; params.push(tag); }
  if (q) { where += ' AND (title LIKE ? OR body LIKE ?)'; params.push(`%${q}%`, `%${q}%`); }
  const total = query(`SELECT COUNT(*) as cnt FROM posts WHERE ${where}`, params)[0]?.cnt || 0;
  const posts = query(
    `SELECT p.*, (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count
     FROM posts p WHERE ${where} ORDER BY p.id DESC LIMIT ? OFFSET ?`,
    [...params, perPage, offset]
  );
  res.json({ posts, total, page: parseInt(page), perPage });
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  run('UPDATE posts SET views=views+1 WHERE id=?', [id]);
  const posts = query('SELECT * FROM posts WHERE id=?', [id]);
  if (!posts.length) return res.status(404).json({ error: '게시글이 없습니다.' });
  const comments = query('SELECT * FROM comments WHERE post_id=? ORDER BY id ASC', [id]);
  
  // 연관 이미지 데이터 로드 바인딩
  const images = query('SELECT img_data FROM post_images WHERE post_id=? ORDER BY id ASC', [id]).map(img => img.img_data);
  
  res.json({ post: posts[0], comments, images });
});

app.post('/api/posts', authenticateToken, (req, res) => {
  const { title, body, tag='잡담', images=[] } = req.body;
  if (!title?.trim() || !body?.trim())
    return res.status(400).json({ error: '제목과 내용을 적어주세요.' });
  if (tag === '공지' && req.user.role !== 'ADMIN')
    return res.status(403).json({ error: '공지 글은 관리자만 쓸 수 있습니다.' });
  
  const hasImgFlag = (images && images.length > 0) ? 1 : 0;

  // 1. 게시글 데이터 삽입
  const id = run('INSERT INTO posts (user_id,title,body,tag,nick,has_img) VALUES (?,?,?,?,?,?)',
    [req.user.id, title.trim(), body.trim(), tag, req.user.nickname, hasImgFlag]);
  
  // 2. 이미지 데이터 삽입 및 트랜잭션 수동 동기화 처리
  if (images && images.length > 0) {
    images.forEach(imgData => {
      db.run('INSERT INTO post_images (post_id, img_data) VALUES (?, ?)', [id, imgData]);
    });
    saveDB(); // 이미지 일괄 삽입 후 디스크 저장소 강제 리프레시
  }

  res.status(201).json({ id });
});

app.post('/api/posts/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type, uuid } = req.body;
  if (!['up','down'].includes(type) || !uuid)
    return res.status(400).json({ error: '올바르지 않은 요청입니다.' });
  const exist = query('SELECT type FROM votes WHERE post_id=? AND uuid=?', [id, uuid]);
  if (exist.length)
    return res.status(400).json({ error: `이미 ${exist[0].type==='up'?'개추':'비추'}를 누르셨습니다.` });
  try {
    run('INSERT INTO votes (post_id,uuid,type) VALUES (?,?,?)', [id, uuid, type]);
    run(`UPDATE posts SET ${type}=${type}+1 WHERE id=?`, [id]);
    run('UPDATE posts SET hot=1 WHERE id=? AND up>=5', [id]);
    res.json(query('SELECT up,down FROM posts WHERE id=?', [id])[0]);
  } catch(e) { res.status(500).json({ error: '투표 처리 중 오류.' }); }
});

app.post('/api/posts/:id/comments', authenticateToken, (req, res) => {
  const postId = parseInt(req.params.id);
  const { body } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: '댓글 내용을 적어주세요.' });
  run('INSERT INTO comments (post_id,user_id,nick,body) VALUES (?,?,?,?)',
    [postId, req.user.id, req.user.nickname, body.trim()]);
  res.status(201).json({ success: true });
});

app.post('/api/comments/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type, uuid } = req.body;
  if (!['up','down'].includes(type) || !uuid)
    return res.status(400).json({ error: '올바르지 않은 요청입니다.' });
  const exist = query('SELECT type FROM comment_votes WHERE comment_id=? AND uuid=?', [id, uuid]);
  if (exist.length)
    return res.status(400).json({ error: `이미 ${exist[0].type==='up'?'추천':'비추천'}을 누르셨습니다.` });
  try {
    run('INSERT INTO comment_votes (comment_id,uuid,type) VALUES (?,?,?)', [id, uuid, type]);
    run(`UPDATE comments SET ${type}=${type}+1 WHERE id=?`, [id]);
    res.json(query('SELECT up,down FROM comments WHERE id=?', [id])[0]);
  } catch(e) { res.status(500).json({ error: '댓글 투표 실패.' }); }
});

app.delete('/api/admin/posts/:id', authenticateToken, isAdmin, (req, res) => {
  run('DELETE FROM posts WHERE id=?', [parseInt(req.params.id)]);
  res.json({ success: true });
});

app.delete('/api/admin/comments/:id', authenticateToken, isAdmin, (req, res) => {
  run('DELETE FROM comments WHERE id=?', [parseInt(req.params.id)]);
  res.json({ success: true });
});

app.get('/api/stats', (req, res) => {
  res.json({
    total:    query("SELECT COUNT(*) as cnt FROM posts")[0]?.cnt || 0,
    today:    query("SELECT COUNT(*) as cnt FROM posts WHERE date(created_at)=date('now','localtime')")[0]?.cnt || 0,
    comments: query("SELECT COUNT(*) as cnt FROM comments")[0]?.cnt || 0,
  });
});

app.use('/api', (req, res) => res.status(404).json({ error: '존재하지 않는 API입니다.' }));

// ── [교정] SPA 폴백 경로 수정 (public 폴더 내의 index.html 지정) ──
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => app.listen(PORT, () => console.log(`🚀 서버 실행 중: http://localhost:${PORT}`)));