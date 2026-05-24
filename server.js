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

// [교정] Base64 이미지 대용량 패킷이 잘리지 않도록 JSON 파서 리밋을 50MB로 확장
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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

  // 테이블 스키마 생성
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

  // 하위 호환성 마이그레이션
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
      try { db.run(alter); console.log('🔧 마이그레이션 적용:', alter); } catch(err) {}
    }
  }

  const adminCount = db.exec("SELECT COUNT(*) as cnt FROM users WHERE role='ADMIN'")[0].values[0][0];
  if (adminCount === 0) {
    db.run("INSERT INTO users (username, password, nickname, role) VALUES (?,?,?,?)",
      ['admin', bcrypt.hashSync('admin1234', 10), '최고관리자', 'ADMIN']);
  }

  saveDB();
  console.log('✅ SQLite 데이터베이스 준비 완료');
}

function saveDB() {
  try {
    const dataDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    const binaryArray = db.export();
    const buffer = Buffer.from(binaryArray);
    fs.writeFileSync(DB_PATH, buffer);
  } catch(err) {
    console.error('⚠️ DB 디스크 저장 실패:', err.message);
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
  try {
    const res = db.exec('SELECT last_insert_rowid()');
    return res[0].values[0][0];
  } catch (e) {
    return null;
  }
}

function authenticateToken(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: '인증이 만료되었습니다.' });
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') return res.status(403).json({ error: '권한이 없습니다.' });
  next();
}

// ── API 라우터 영역 ──────────────────────────────────────────────────────────

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
    return res.status(400).json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' });
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
    ...[params, perPage, offset].flat()
  );
  res.json({ posts, total, page: parseInt(page), perPage });
});

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  db.run('UPDATE posts SET views=views+1 WHERE id=?', [id]);
  saveDB();

  const posts = query('SELECT * FROM posts WHERE id=?', [id]);
  if (!posts.length) return res.status(404).json({ error: '존재하지 않는 게시글입니다.' });
  
  const comments = query('SELECT * FROM comments WHERE post_id=? ORDER BY id ASC', [id]);
  
  // [교정] post_images에서 바이너리 데이터를 명확하게 뽑아 배열로 바인딩
  const imageRows = query('SELECT img_data FROM post_images WHERE post_id=? ORDER BY id ASC', [id]);
  const images = imageRows.map(row => row.img_data);

  res.json({ post: posts[0], comments, images });
});

// [교정] 게시글 등록 시 이미지 트랜잭션 및 ID 바인딩 무결성 확보
app.post('/api/posts', authenticateToken, (req, res) => {
  const { title, body, tag='잡담', images=[] } = req.body;
  if (!title?.trim() || !body?.trim())
    return res.status(400).json({ error: '제목과 내용을 모두 적어주세요.' });
  
  const hasImgFlag = (images && images.length > 0) ? 1 : 0;

  try {
    // 1. 메인 포스트 삽입 및 보장된 고유 ID 검출
    const id = run('INSERT INTO posts (user_id,title,body,tag,nick,has_img) VALUES (?,?,?,?,?,?)',
      [req.user.id, title.trim(), body.trim(), tag, req.user.nickname, hasImgFlag]);
    
    // 2. 고유 ID가 유효하고 이미지가 존재할 때 배열 루프 처리
    if (id && hasImgFlag === 1) {
      for (const imgData of images) {
        db.run('INSERT INTO post_images (post_id, img_data) VALUES (?, ?)', [id, imgData]);
      }
      // 대용량 쓰기가 끝난 후 단 한 번 디스크 파일 동기화로 락 방지 및 데이터 보호
      saveDB();
    }

    res.status(201).json({ id });
  } catch (err) {
    console.error("🚨 게시글 등록 중 내부 예외 발생:", err);
    res.status(500).json({ error: '데이터베이스 처리 중 오류가 발생했습니다.' });
  }
});

app.post('/api/posts/:id/vote', (req, res) => {
  const id = parseInt(req.params.id);
  const { type, uuid } = req.body;
  if (!['up','down'].includes(type) || !uuid) return res.status(400).json({ error: '잘못된 요청입니다.' });
  const exist = query('SELECT type FROM votes WHERE post_id=? AND uuid=?', [id, uuid]);
  if (exist.length) return res.status(400).json({ error: `이미 투표하셨습니다.` });
  
  try {
    run('INSERT INTO votes (post_id,uuid,type) VALUES (?,?,?)', [id, uuid, type]);
    run(`UPDATE posts SET ${type}=${type}+1 WHERE id=?`, [id]);
    run('UPDATE posts SET hot=1 WHERE id=? AND up>=5', [id]);
    res.json(query('SELECT up,down FROM posts WHERE id=?', [id])[0]);
  } catch(e) { res.status(500).json({ error: '투표 실패' }); }
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
  const exist = query('SELECT type FROM comment_votes WHERE comment_id=? AND uuid=?', [id, uuid]);
  if (exist.length) return res.status(400).json({ error: `이미 투표하셨습니다.` });
  try {
    run('INSERT INTO comment_votes (comment_id,uuid,type) VALUES (?,?,?)', [id, uuid, type]);
    run(`UPDATE comments SET ${type}=${type}+1 WHERE id=?`, [id]);
    res.json(query('SELECT up,down FROM comments WHERE id=?', [id])[0]);
  } catch(e) { res.status(500).json({ error: '댓글 투표 실패' }); }
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

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => app.listen(PORT, () => console.log(`🚀 서버 정상 가동중: 포트 ${PORT}`)));