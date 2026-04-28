const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
const httpServer = http.createServer(app);
const io = new Server(httpServer, { transports: ['websocket', 'polling'] });

// Persist JWT secret across restarts
const secretFile = path.join(__dirname, '.jwt_secret');
let JWT_SECRET;
if (fs.existsSync(secretFile)) {
  JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
} else {
  JWT_SECRET = require('crypto').randomBytes(32).toString('hex');
  fs.writeFileSync(secretFile, JWT_SECRET);
}

// Simple JSON store - no native modules needed
class Store {
  constructor(file) {
    this.file = file;
    try { this.data = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { this.data = { users: [], messages: [] }; }
  }
  save() { fs.writeFileSync(this.file, JSON.stringify(this.data)); }
  findUserByUsername(username) {
    return this.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  }
  findUserById(id) { return this.data.users.find(u => u.id === id); }
  searchUsers(q, excludeId) {
    return this.data.users
      .filter(u => u.username.toLowerCase().includes(q.toLowerCase()) && u.id !== excludeId)
      .map(u => ({ id: u.id, username: u.username, public_key: u.public_key }))
      .slice(0, 20);
  }
  addUser(user) { this.data.users.push(user); this.save(); }
  addMessage(msg) { this.data.messages.push(msg); this.save(); }
  getMessages(a, b) {
    return this.data.messages
      .filter(m => (m.sender_id===a && m.recipient_id===b) || (m.sender_id===b && m.recipient_id===a))
      .sort((x,y) => x.created_at - y.created_at).slice(-200);
  }
  getConversations(userId) {
    const seen = new Map();
    for (const m of this.data.messages) {
      if (m.sender_id !== userId && m.recipient_id !== userId) continue;
      const other = m.sender_id === userId ? m.recipient_id : m.sender_id;
      if (!seen.has(other) || seen.get(other).created_at < m.created_at) seen.set(other, m);
    }
    const result = [];
    for (const [otherId, lastMsg] of seen.entries()) {
      const u = this.findUserById(otherId);
      if (u) result.push({ other_id: otherId, other_username: u.username, other_public_key: u.public_key, last_time: lastMsg.created_at });
    }
    return result.sort((a,b) => b.last_time - a.last_time);
  }
}

const db = new Store(path.join(__dirname, 'chat.db.json'));

// Uploads stored on your machine
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(403).json({ error: 'Invalid token' }); }
}

app.post('/api/register', async (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password || !publicKey) return res.status(400).json({ error: 'Missing fields' });
  if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Username must be 3-32 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, _ only' });
  if (db.findUserByUsername(username)) return res.status(409).json({ error: 'Username already taken' });
  const hash = await bcrypt.hash(password, 12);
  const id = uuidv4();
  db.addUser({ id, username, password_hash: hash, public_key: publicKey, created_at: Date.now() });
  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, id, username, publicKey });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.findUserByUsername(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, id: user.id, username: user.username, publicKey: user.public_key });
});

app.get('/api/users/search', auth, (req, res) => {
  const q = (req.query.q || '').trim();
  res.json(q ? db.searchUsers(q, req.user.id) : []);
});

app.get('/api/users/:id', auth, (req, res) => {
  const u = db.findUserById(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id: u.id, username: u.username, public_key: u.public_key });
});

app.get('/api/conversations', auth, (req, res) => res.json(db.getConversations(req.user.id)));

app.get('/api/messages/:userId', auth, (req, res) => {
  const msgs = db.getMessages(req.user.id, req.params.userId).map(m => ({
    ...m, sender_username: (db.findUserById(m.sender_id) || {}).username || '?'
  }));
  res.json(msgs);
});

const onlineUsers = new Map();
app.get('/api/online', auth, (req, res) => res.json({ online: [...onlineUsers.keys()] }));

// File upload - stored on your machine
app.post('/api/upload', auth, express.raw({ limit: '200mb', type: () => true }), (req, res) => {
  if (!req.body || !req.body.length) return res.status(400).json({ error: 'No data' });
  const fileId = uuidv4();
  fs.writeFileSync(path.join(uploadsDir, fileId), req.body);
  res.json({ fileId });
});

// Serve encrypted file
app.get('/api/files/:fileId', auth, (req, res) => {
  const fileId = path.basename(req.params.fileId);
  const filePath = path.join(uploadsDir, fileId);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(filePath).pipe(res);
});

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  onlineUsers.set(socket.user.id, socket.id);
  socket.join(socket.user.id);
  io.emit('user_online', socket.user.id);
  socket.on('send_message', (data) => {
    const { recipientId, ciphertext, iv, recipientKey, senderKey } = data;
    if (!recipientId || !ciphertext || !iv || !recipientKey || !senderKey) return;
    const id = uuidv4();
    const created_at = Math.floor(Date.now() / 1000);
    const msg = { id, sender_id: socket.user.id, recipient_id: recipientId, ciphertext, iv, recipient_key: recipientKey, sender_key: senderKey, created_at };
    db.addMessage(msg);
    const full = { ...msg, sender_username: socket.user.username };
    io.to(recipientId).emit('new_message', full);
    socket.emit('message_sent', full);
  });
  socket.on('typing', ({ recipientId, isTyping }) => {
    io.to(recipientId).emit('typing', { userId: socket.user.id, isTyping });
  });
  socket.on('disconnect', () => {
    onlineUsers.delete(socket.user.id);
    io.emit('user_offline', socket.user.id);
  });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log('SecureChat running on http://localhost:' + PORT);
  const nets = require('os').networkInterfaces();
  for (const name of Object.keys(nets))
    for (const net of nets[name])
      if (net.family === 'IPv4' && !net.internal)
        console.log('Network: http://' + net.address + ':' + PORT);
});

// Optional public tunnel: node server.js --public
if (process.argv.includes('--public')) {
  const localtunnel = require('localtunnel');
  httpServer.once('listening', async () => {
    try {
      console.log('Starting public tunnel...');
      const tunnel = await localtunnel({ port: PORT });
      console.log('');
      console.log('PUBLIC URL (share with friend): ' + tunnel.url);
      console.log('');
      tunnel.on('close', () => console.log('Tunnel closed.'));
      tunnel.on('error', e => console.error('Tunnel error:', e.message));
    } catch(e) { console.error('Could not create tunnel:', e.message); }
  });
}
