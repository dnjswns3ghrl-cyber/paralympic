const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'data', 'community.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
  }

  // Railway 환경이고 파일이 없으면 메모리 DB로 안전하게 시작
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
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

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id    INTEGER NOT NULL,
      nick       TEXT NOT NULL DEFAULT '익명',
      body       TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now','localtime')),
      FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
    )
  `);

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
  // Railway 배포 환경에서는 파일 쓰기 에러 방지를 위해 로그만 찍고 스킵 (메모리 유지)
  if (process.env.RAILWAY_ENVIRONMENT || process.env.NODE_ENV === 'production') {
    return;
  }
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (err) {
    console.error("⚠️ DB 파일 저장 실패 (권한 제한 등):", err);
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

// ── API 라우트 ────────────────────────────────────────────────────────────────

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

app.get('/api/posts/:id', (req, res) => {
  const id = parseInt(req.params.id);
  run('UPDATE posts SET views = views + 1 WHERE id = ?', [id]);
  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  if (!posts.length) return res.status(404).json({ error: '게시글 없음' });
  const comments = query('SELECT * FROM comments WHERE post_id = ? ORDER BY id ASC', [id]);
  res.json({ post: posts[0], comments });
});

app.post('/api/posts', (req, res) => {
  const { title, body, nick = '익명' } = req.body;
  if (!title?.trim() || !body?.trim()) return res.status(400).json({ error: '제목/내용 필수' });
  
  const id = run('INSERT INTO posts (title, body, nick) VALUES (?,?,?)', [title.trim(), body.trim(), nick.trim() || '익명']);
  if (!id) return res.status(500).json({ error: '데이터 저장 실패' });

  const posts = query('SELECT * FROM posts WHERE id = ?', [id]);
  res.status(201).json(posts[0] || { success: true, id });
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

app.post('/api/posts/:id/comments', (req, res) => {
  const postId = parseInt(req.params.id);
  const { body, nick = '익명' } = req.body;
  if (!body?.trim()) return res.status(400).json({ error: '내용 필수' });
  
  const id = run('INSERT INTO comments (post_id, nick, body) VALUES (?,?,?)', [postId, nick.trim() || '익명', body.trim()]);
  if (!id) return res.status(500).json({ error: '댓글 저장 실패' });

  const comments = query('SELECT * FROM comments WHERE id = ?', [id]);
  res.status(201).json(comments[0] || { success: true, id });
});

app.get('/api/stats', (req, res) => {
  const total = query('SELECT COUNT(*) as cnt FROM posts')[0]?.cnt || 0;
  const today = query("SELECT COUNT(*) as cnt FROM posts WHERE date(created_at) = date('now','localtime')")[0]?.cnt || 0;
  const comments = query('SELECT COUNT(*) as cnt FROM comments')[0]?.cnt || 0;
  res.json({ total, today, comments });
});

// ── SPA 폴백 라우트 수정 (최신 Express 대응) ──────────────────────────────────────────
app.get('(.*)', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 서버 실행 중, 포트: ${PORT}`);
  });
});