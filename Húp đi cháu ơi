const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');

const app = express();
const db = new Database(process.env.DB_FILE || 'golden-play.sqlite');
const PORT = process.env.PORT || 3000;

db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 balance INTEGER NOT NULL DEFAULT 10000,
 role TEXT NOT NULL DEFAULT 'player',
 disabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS rounds (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 game TEXT NOT NULL,
 choice TEXT NOT NULL,
 outcome TEXT NOT NULL,
 bet INTEGER NOT NULL,
 delta INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(session({
 secret: process.env.SESSION_SECRET || 'change-this-secret-before-deploying',
 resave: false, saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false }));

const getUser = id => db.prepare('SELECT id, username, balance, role, disabled FROM users WHERE id=?').get(id);
function requireAuth(req,res,next){
  const u = req.session.userId && getUser(req.session.userId);
  if (!u || u.disabled) return res.status(401).json({error:'Vui lòng đăng nhập.'});
  req.user = u; next();
}
function requireAdmin(req,res,next){
  if (req.user.role !== 'admin') return res.status(403).json({error:'Bạn không có quyền quản trị.'});
  next();
}
function safeUser(u){ return {id:u.id, username:u.username, balance:u.balance, role:u.role}; }

app.post('/api/auth/register', (req,res)=>{
  const username = String(req.body.username||'').trim();
  const password = String(req.body.password||'');
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username) || password.length < 8)
    return res.status(400).json({error:'Tên tài khoản 3–20 ký tự; mật khẩu tối thiểu 8 ký tự.'});
  try {
    const hash = bcrypt.hashSync(password, 12);
    const info = db.prepare('INSERT INTO users(username,password_hash,balance) VALUES(?,?,10000)').run(username,hash);
    req.session.userId = info.lastInsertRowid;
    res.json({user:safeUser(getUser(info.lastInsertRowid))});
  } catch(e){ res.status(409).json({error:'Tên tài khoản đã được sử dụng.'}); }
});
app.post('/api/auth/login',(req,res)=>{
  const username=String(req.body.username||'').trim(), password=String(req.body.password||'');
  const u=db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!u || u.disabled || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:'Thông tin đăng nhập không chính xác.'});
  req.session.userId=u.id; res.json({user:safeUser(u)});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',requireAuth,(req,res)=>res.json({user:safeUser(req.user)}));

app.get('/api/leaderboard',(req,res)=>{
 const rows=db.prepare(`SELECT username, MAX(balance) AS score FROM users WHERE disabled=0 GROUP BY id ORDER BY score DESC LIMIT 20`).all();
 res.json({items:rows});
});
app.get('/api/history',requireAuth,(req,res)=>{
 const rows=db.prepare('SELECT game,choice,outcome,bet,delta,created_at FROM rounds WHERE user_id=? ORDER BY id DESC LIMIT 15').all(req.user.id);
 res.json({items:rows});
});

app.post('/api/play',requireAuth,(req,res)=>{
 const game=String(req.body.game||''), choice=String(req.body.choice||''), bet=Number(req.body.bet);
 if(!['taixiu','xocdia','slot'].includes(game)) return res.status(400).json({error:'Trò chơi không hợp lệ.'});
 if(!Number.isSafeInteger(bet)||bet<10||bet>100000) return res.status(400).json({error:'Cược từ 10 đến 100.000 xu.'});
 const u=getUser(req.user.id);
 if(bet>u.balance) return res.status(400).json({error:'Bạn không đủ xu.'});
 let outcome='', win=false, multiplier=2, detail={};
 if(game==='taixiu'){
   if(!['Tài','Xỉu'].includes(choice)) return res.status(400).json({error:'Lựa chọn không hợp lệ.'});
   const dice=[1,2,3].map(()=>1+Math.floor(Math.random()*6)), sum=dice.reduce((a,b)=>a+b,0);
   outcome=sum>=11&&sum<=17?'Tài':'Xỉu'; win=choice===outcome && sum!==3 && sum!==18;
   detail={dice,sum}; 
 } else if(game==='xocdia'){
   if(!['Chẵn','Lẻ'].includes(choice)) return res.status(400).json({error:'Lựa chọn không hợp lệ.'});
   const coins=Array.from({length:4},()=>Math.random()<.5?'Đỏ':'Trắng'), red=coins.filter(x=>x==='Đỏ').length;
   outcome=red%2===0?'Chẵn':'Lẻ'; win=choice===outcome; detail={coins,red};
 } else {
   if(choice!=='Quay') return res.status(400).json({error:'Lựa chọn không hợp lệ.'});
   const symbols=['🍒','⭐','💎','🔔','7️⃣'];
   const reels=Array.from({length:3},()=>symbols[Math.floor(Math.random()*symbols.length)]);
   outcome=reels.join(' '); win=reels.every(x=>x===reels[0]); multiplier=5; detail={reels};
 }
 const delta=win?bet*(multiplier-1):-bet;
 const tx=db.transaction(()=>{
   db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(delta,u.id);
   db.prepare('INSERT INTO rounds(user_id,game,choice,outcome,bet,delta) VALUES(?,?,?,?,?,?)').run(u.id,game,choice,outcome,bet,delta);
 });
 tx();
 res.json({win,delta,outcome,detail,user:safeUser(getUser(u.id))});
});

app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>{
 const users=db.prepare('SELECT id,username,balance,role,disabled,created_at FROM users ORDER BY id DESC LIMIT 200').all();
 res.json({users});
});
app.post('/api/admin/users/:id/disable',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id);
 if(id===req.user.id) return res.status(400).json({error:'Không thể tự khóa tài khoản đang dùng.'});
 const target=db.prepare('SELECT id,role FROM users WHERE id=?').get(id);
 if(!target) return res.status(404).json({error:'Không tìm thấy tài khoản.'});
 if(target.role==='admin') return res.status(400).json({error:'Không thể khóa tài khoản quản trị.'});
 db.prepare('UPDATE users SET disabled=1-disabled WHERE id=?').run(id);
 res.json({ok:true});
});

function seedAdmin(){
 const username=process.env.ADMIN_USER, password=process.env.ADMIN_PASS;
 if(!username || !password) return;
 const exists=db.prepare('SELECT id FROM users WHERE username=?').get(username);
 if(!exists) db.prepare('INSERT INTO users(username,password_hash,balance,role) VALUES(?,?,10000,?)')
   .run(username,bcrypt.hashSync(password,12),'admin');
}
seedAdmin();
app.listen(PORT,()=>console.log(`Golden Play dang chay tai http://localhost:${PORT}`));
