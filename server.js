import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import crypto from 'crypto';
import net from 'net';
import tls from 'tls';

const app = express();
app.use(express.json());
app.use(cors());
// LAMSL no-store: dynamic API/file listing responses must not be cached by browsers/CDNs.
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/slideshow-images' || req.path === '/ef-images') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || null;
const SESSION_SECRET = process.env.LAMSL_SESSION_SECRET || ADMIN_API_KEY || 'lamsl-dev-session-secret';
console.log('ADMIN_API_KEY loaded:', !!ADMIN_API_KEY);

function getBearerToken(req) {
  const auth = String(req.headers.authorization || '');
  if (auth.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim();
  return '';
}

function createSessionToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifySessionToken(token) {
  try {
    if (!token || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    const sigBuffer = Buffer.from(sig || '');
    const expectedBuffer = Buffer.from(expected);
    if (sigBuffer.length !== expectedBuffer.length) return null;
    if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    if (!['admin', 'umpire', 'team-manager', 'user'].includes(String(payload.role || '').toLowerCase())) return null;
    return payload;
  } catch (error) {
    return null;
  }
}

function getStaticSession(req) {
  const role = String(req.headers['x-lamsl-role'] || '').toLowerCase();
  const sessionActive = req.headers['x-lamsl-session'] === 'active';
  const username = String(req.headers['x-lamsl-username'] || 'admin');
  if (sessionActive && ['admin', 'umpire'].includes(role)) return { username, role };
  return null;
}

function requireAdminKey(req, res, next) {
  const token = req.headers['x-admin-key'] || getBearerToken(req);
  if (ADMIN_API_KEY && token === ADMIN_API_KEY) return next();
  const session = verifySessionToken(token);
  if (session && session.role === 'admin') return next();
  const staticSession = getStaticSession(req);
  if (staticSession && staticSession.role === 'admin') return next();
  return res.status(403).json({ success: false, error: 'Forbidden: admin login/session token or valid API key required' });
}


function requireTeamContentAuth(req, res, next) {
  const token = req.headers['x-admin-key'] || getBearerToken(req);
  if (ADMIN_API_KEY && token === ADMIN_API_KEY) return next();
  if (verifySessionToken(token)) return next();
  const role = String(req.headers['x-lamsl-role'] || '').toLowerCase();
  const sessionActive = req.headers['x-lamsl-session'] === 'active';
  if (sessionActive && ['admin', 'umpire', 'team-manager'].includes(role)) return next();
  return res.status(403).json({ success: false, error: 'Forbidden: team manager/admin login or API key required' });
}

app.post('/api/admin-session', express.json(), (req, res) => {
  const staticSession = getStaticSession(req);
  const key = req.headers['x-admin-key'] || getBearerToken(req);
  const apiKeyValid = !!(ADMIN_API_KEY && key === ADMIN_API_KEY);
  if (!staticSession && !apiKeyValid) {
    return res.status(403).json({ success: false, error: 'Forbidden: sign in as admin/umpire before requesting backend session.' });
  }
  const role = staticSession?.role || 'admin';
  const username = staticSession?.username || 'admin';
  const token = createSessionToken({ username, role, iat: Date.now(), exp: Date.now() + 12 * 60 * 60 * 1000 });
  return res.json({ success: true, token, role, username, expiresInHours: 12 });
});

// Ensure required directories exist
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const persistentRoot = process.env.LAMSL_STORAGE_DIR || process.env.RENDER_DISK_MOUNT || projectRoot;
const uploadDir = path.join(persistentRoot, 'uploads');
const slideshowDir = path.join(persistentRoot, 'SlideshowImages');
const logsDir = path.join(persistentRoot, 'logs');
const efDir = path.join(persistentRoot, 'EFimages');
const dataDir = path.join(persistentRoot, 'data');
const teamProfileDir = path.join(persistentRoot, 'TeamProfileImages');
const legacyTeamProfileDir = path.join(persistentRoot, 'teamProfile images');
const bundledDataDir = path.join(projectRoot, 'data');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
if (!fs.existsSync(slideshowDir)) {
  fs.mkdirSync(slideshowDir, { recursive: true });
}
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(efDir)) {
  fs.mkdirSync(efDir, { recursive: true });
}
if (!fs.existsSync(teamProfileDir)) {
  fs.mkdirSync(teamProfileDir, { recursive: true });
}
if (!fs.existsSync(legacyTeamProfileDir)) {
  fs.mkdirSync(legacyTeamProfileDir, { recursive: true });
}


const usersFile = path.join(dataDir, 'users.json');
function readUsers(){
  try {
    if(!fs.existsSync(usersFile)) {
      const seed=[{username:'admin',password:'admin',role:'admin'}];
      fs.writeFileSync(usersFile, JSON.stringify(seed,null,2));
      return seed;
    }
    return JSON.parse(fs.readFileSync(usersFile,'utf8'));
  } catch(e){ return [{username:'admin',password:'admin',role:'admin'}]; }
}
function writeUsers(users){ fs.writeFileSync(usersFile, JSON.stringify(users,null,2)); return users; }

app.post('/api/login', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ success: false, error: 'username and password required' });
  const users = readUsers();
  const user = users.find(item => String(item.username || '') === username && String(item.password || '') === password);
  if (!user) return res.status(401).json({ success: false, error: 'Invalid username or password.' });
  const role = String(user.role || 'user').toLowerCase();
  const assignedTeam = user.assignedTeam || user.team || '';
  const assignedDivision = user.assignedDivision || user.division || '';
  const token = createSessionToken({ username: user.username, role, assignedTeam, assignedDivision, iat: Date.now(), exp: Date.now() + 12 * 60 * 60 * 1000 });
  res.json({ success: true, username: user.username, role, assignedTeam, assignedDivision, token, expiresInHours: 12 });
});


app.get('/api/users', requireAdminKey, (req,res)=>{
  const users=readUsers().map(u=>({...u,password:'********'}));
  res.json({success:true, users});
});

app.post('/api/users', requireAdminKey, (req,res)=>{
  const users=readUsers();
  const payload=req.body||{};
  if(!payload.username || !payload.password) return res.status(400).json({success:false,error:'username and password required'});
  const existing=users.findIndex(u=>u.username===payload.username);
  const record={username:payload.username,password:payload.password,role:payload.role||'user',assignedTeam:payload.assignedTeam||payload.team||'',assignedDivision:payload.assignedDivision||payload.division||''};
  if(existing>=0) users[existing]=record;
  else users.push(record);
  writeUsers(users);
  res.json({success:true, users:users.map(u=>({...u,password:'********'}))});
});


app.put('/api/users/:username', requireAdminKey, (req,res)=>{
  const users=readUsers();
  const original=req.params.username;
  const payload=req.body||{};
  const existing=users.findIndex(u=>u.username===original);
  if(existing<0) return res.status(404).json({success:false,error:'user not found'});
  const username=payload.username || original;
  if(username !== original && users.some(u=>u.username===username)) return res.status(409).json({success:false,error:'username already exists'});
  users[existing]={
    ...users[existing],
    username,
    role: payload.role || users[existing].role || 'user',
    password: payload.password ? payload.password : users[existing].password,
    assignedTeam: payload.assignedTeam !== undefined ? payload.assignedTeam : (payload.team !== undefined ? payload.team : (users[existing].assignedTeam || users[existing].team || '')),
    assignedDivision: payload.assignedDivision !== undefined ? payload.assignedDivision : (payload.division !== undefined ? payload.division : (users[existing].assignedDivision || users[existing].division || ''))
  };
  writeUsers(users);
  res.json({success:true, users:users.map(u=>({...u,password:'********'}))});
});

app.delete('/api/users/:username', requireAdminKey, (req,res)=>{
  const users=readUsers().filter(u=>u.username!==req.params.username || u.username==='admin');
  writeUsers(users);
  res.json({success:true});
});

// Email signup endpoint
app.post('/api/subscribe', (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email'
    });
  }

  const subscribers = readSubscribers();
  if (!subscribers.some(item => String(item.email || item).toLowerCase() === email.toLowerCase())) {
    subscribers.push({ email, subscribedAt: new Date().toISOString(), source: 'website' });
    writeSubscribers(subscribers);
  }

  res.json({
    success: true,
    message: 'Email subscribed'
  });
});

// Image upload endpoint
function getImageDestination(req) {
  const raw = String((req.body && (req.body.destination || req.body.target || req.body.imageType)) || 'homepage').toLowerCase();
  if (['event', 'events', 'fundraiser', 'fundraisers', 'ef', 'efimages'].includes(raw)) return 'events';
  return 'homepage';
}

const upload = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => {
    const destination = getImageDestination(req);
    cb(null, destination === 'events' ? efDir : slideshowDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '';
    const safeBase = path.basename(file.originalname || 'image', ext).replace(/[^a-z0-9_-]+/gi, '-').slice(0, 40) || 'image';
    cb(null, `${Date.now()}-${safeBase}${ext}`);
  }
})});

app.post('/api/upload-image', requireAdminKey, upload.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });
    const destination = getImageDestination(req);
    const publicFolder = destination === 'events' ? '/EFimages/' : '/SlideshowImages/';
    const url = publicFolder + req.file.filename;
    const content = readContent();
    const imageRecord = {
      url,
      src: url,
      path: url,
      filename: req.file.filename,
      originalName: req.file.originalname || '',
      caption: String(req.body.caption || '').trim(),
      destination,
      uploadedAt: new Date().toISOString()
    };

    if (destination === 'events') {
      content.eventFundraiserImages = Array.isArray(content.eventFundraiserImages) ? content.eventFundraiserImages : [];
      content.eventFundraiserImages.unshift(imageRecord);
      const meta = readEfMeta();
      meta.unshift({ name: req.file.filename, path: url, url, caption: imageRecord.caption, uploadedAt: imageRecord.uploadedAt });
      writeEfMeta(meta);
    } else {
      content.slideshow = Array.isArray(content.slideshow) ? content.slideshow : [];
      content.slideshow.unshift(imageRecord);
    }

    content.updatedAt = new Date().toISOString();
    writeContent(content);
    res.json({ success: true, destination, url, image: imageRecord, content });
  } catch (error) {
    console.error('Image upload failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


function getManagedImageInfo(body = {}) {
  const destination = getImageDestination({ body });
  const raw = String(body.filename || body.name || body.path || body.url || '').trim();
  const filename = path.basename(raw.replace(/\\/g, '/'));
  if (!filename || filename === '.' || filename === '..') return null;
  const folder = destination === 'events' ? efDir : slideshowDir;
  const publicPrefix = destination === 'events' ? '/EFimages/' : '/SlideshowImages/';
  return { destination, filename, folder, publicUrl: publicPrefix + filename };
}

function sameManagedImage(item, info) {
  if (!item || !info) return false;
  const candidates = [item.filename, item.name, item.url, item.src, item.path, item.publicUrl]
    .filter(Boolean)
    .map(value => path.basename(String(value).replace(/\\/g, '/')));
  return candidates.includes(info.filename);
}

function deleteManagedImageHandler(req, res) {
  try {
    const info = getManagedImageInfo(req.body || {});
    if (!info) return res.status(400).json({ success: false, error: 'Missing valid image filename/url.' });

    const fullPath = path.resolve(info.folder, info.filename);
    const allowedRoot = path.resolve(info.folder) + path.sep;
    if (!fullPath.startsWith(allowedRoot)) return res.status(400).json({ success: false, error: 'Invalid image path.' });

    const content = readContent();
    let removedReference = false;
    let removedFile = false;

    if (info.destination === 'events') {
      const before = Array.isArray(content.eventFundraiserImages) ? content.eventFundraiserImages.length : 0;
      content.eventFundraiserImages = (content.eventFundraiserImages || []).filter(item => !sameManagedImage(item, info));
      removedReference = before !== content.eventFundraiserImages.length;
      const metaBefore = readEfMeta();
      const metaAfter = metaBefore.filter(item => !sameManagedImage(item, info));
      if (metaAfter.length !== metaBefore.length) removedReference = true;
      writeEfMeta(metaAfter);
    } else {
      const before = Array.isArray(content.slideshow) ? content.slideshow.length : 0;
      content.slideshow = (content.slideshow || []).filter(item => !sameManagedImage(item, info));
      removedReference = before !== content.slideshow.length;
    }

    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
      removedFile = true;
    }

    content.updatedAt = new Date().toISOString();
    writeContent(content);
    res.json({ success: true, destination: info.destination, filename: info.filename, removedFile, removedReference, content: readContent() });
  } catch (error) {
    console.error('Image delete failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
}

app.post('/api/delete-image', requireAdminKey, express.json(), deleteManagedImageHandler);
app.post('/api/images/delete', requireAdminKey, express.json(), deleteManagedImageHandler);
app.post('/api/uploaded-images/delete', requireAdminKey, express.json(), deleteManagedImageHandler);

// Serve uploaded images
app.use('/uploads', express.static(uploadDir));
app.use('/SlideshowImages', express.static(slideshowDir));
app.get('/slideshow-images', (req, res) => {
  try {
    const content = readContent();
    res.json({ success: true, images: getMergedHomepageSlideshow(content) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
app.use('/TeamProfileImages', express.static(teamProfileDir));
app.use('/teamProfile images', express.static(legacyTeamProfileDir));
app.use('/EFimages', express.static(efDir));
app.use('/EF_Images', express.static(efDir));

// Admin action logging endpoint
app.post('/api/log-admin-action', requireAdminKey, (req, res) => {
  const { username, action, details } = req.body;

  if (!username || !action) {
    return res.status(400).json({
      success: false,
      message: 'Missing username or action'
    });
  }

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    username,
    action,
    details: details || {}
  };

  const logFile = path.join(logsDir, 'admin-actions.log');
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');

  res.json({
    success: true,
    message: 'Action logged'
  });
});

// ===== Content endpoints =====

const DEFAULT_GAME_SCHEDULES = [{"id": "game-1", "date": "2026-04-26", "time": "08:00am", "park": "Carson - Calas Park", "division": "All", "team1": "Titans", "team2": "Primos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-2", "date": "2026-04-26", "time": "09:50am", "park": "Carson - Calas Park", "division": "All", "team1": "Dodgers", "team2": "Nasty Boyz", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-3", "date": "2026-04-26", "time": "11:45am", "park": "Carson - Calas Park", "division": "All", "team1": "Goodfellas", "team2": "Demons", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-4", "date": "2026-04-26", "time": "08:00am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Camaradas", "team2": "Desvelados", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-5", "date": "2026-04-26", "time": "09:50am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Diablos", "team2": "Toxic", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-6", "date": "2026-04-26", "time": "11:45am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Wild Hogz", "team2": "Strokes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-7", "date": "2026-04-26", "time": "08:00am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Legends", "team2": "Charros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-8", "date": "2026-04-26", "time": "09:50am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Salvajes", "team2": "Coyotes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-9", "date": "2026-04-26", "time": "11:45am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Caballeros", "team2": "Orioles", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-10", "date": "2026-04-26", "time": "01:45pm", "park": "Carson - Dolphin Park", "division": "All", "team1": "Doom Squad", "team2": "La Tribu", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-11", "date": "2026-04-26", "time": "08:00am", "park": "Carson - Veterans Park", "division": "All", "team1": "Bandits", "team2": "Naranjeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-12", "date": "2026-04-26", "time": "09:50am", "park": "Carson - Veterans Park", "division": "All", "team1": "White Sox", "team2": "Cubs", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-13", "date": "2026-04-26", "time": "11:45am", "park": "Carson - Veterans Park", "division": "All", "team1": "Dirt Bags", "team2": "Xolos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-14", "date": "2026-05-03", "time": "08:00am", "park": "Carson - Calas Park", "division": "All", "team1": "Demons", "team2": "Caballeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-15", "date": "2026-05-03", "time": "09:50am", "park": "Carson - Calas Park", "division": "All", "team1": "Dodgers", "team2": "Legends", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-16", "date": "2026-05-03", "time": "11:45am", "park": "Carson - Calas Park", "division": "All", "team1": "Nasty Boyz", "team2": "Doom Squad", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-17", "date": "2026-05-03", "time": "08:00am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Coyotes", "team2": "Naranjeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-18", "date": "2026-05-03", "time": "09:50am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Camaradas", "team2": "Xolos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-19", "date": "2026-05-03", "time": "11:45am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Orioles", "team2": "Bandits", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-20", "date": "2026-05-03", "time": "08:00am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Strokes", "team2": "Los Pericos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-21", "date": "2026-05-03", "time": "09:50am", "park": "Carson - Dolphin Park", "division": "All", "team1": "White Sox", "team2": "Primos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-22", "date": "2026-05-03", "time": "11:45am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Cubs", "team2": "Toxic", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-23", "date": "2026-05-03", "time": "08:00am", "park": "Carson - Veterans Park", "division": "All", "team1": "Charros", "team2": "La Tribu", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-24", "date": "2026-05-03", "time": "09:50am", "park": "Carson - Veterans Park", "division": "All", "team1": "Goodfellas", "team2": "Salvajes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-25", "date": "2026-05-03", "time": "11:45am", "park": "Carson - Veterans Park", "division": "All", "team1": "Desvelados", "team2": "Dirt Bags", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-26", "date": "2026-05-17", "time": "08:00am", "park": "Carson - Calas Park", "division": "All", "team1": "Orioles", "team2": "Salvajes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-27", "date": "2026-05-17", "time": "09:50am", "park": "Carson - Calas Park", "division": "All", "team1": "La Tribu", "team2": "Dodgers", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-28", "date": "2026-05-17", "time": "11:45am", "park": "Carson - Calas Park", "division": "All", "team1": "Xolos", "team2": "Wild Hogz", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-29", "date": "2026-05-17", "time": "08:00am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Diablos", "team2": "Legends", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-30", "date": "2026-05-17", "time": "09:50am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Caballeros", "team2": "Bandits", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-31", "date": "2026-05-17", "time": "11:45am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Nasty Boyz", "team2": "Cubs", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-32", "date": "2026-05-17", "time": "08:00am", "park": "Carson - Dolphin Park", "division": "All", "team1": "White Sox", "team2": "Doom Squad", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-33", "date": "2026-05-17", "time": "09:50am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Coyotes", "team2": "Demons", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-34", "date": "2026-05-17", "time": "11:45am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Goodfellas", "team2": "Naranjeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-35", "date": "2026-05-17", "time": "08:00am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Titans", "team2": "Charros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-36", "date": "2026-05-17", "time": "09:50am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Camaradas", "team2": "Strokes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-37", "date": "2026-05-17", "time": "11:45am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Desvelados", "team2": "Los Pericos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-38", "date": "2026-05-31", "time": "08:00am", "park": "Carson - Calas Park", "division": "All", "team1": "Coyotes", "team2": "Caballeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-39", "date": "2026-05-31", "time": "09:50am", "park": "Carson - Calas Park", "division": "All", "team1": "Bandits", "team2": "Salvajes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-40", "date": "2026-05-31", "time": "11:45am", "park": "Carson - Calas Park", "division": "All", "team1": "La Tribu", "team2": "Cubs", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-41", "date": "2026-05-31", "time": "08:00am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Dirt Bags", "team2": "Wild Hogz", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-42", "date": "2026-05-31", "time": "09:50am", "park": "Carson - Stevenson Park", "division": "All", "team1": "White Sox", "team2": "Diablos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-43", "date": "2026-05-31", "time": "11:45am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Orioles", "team2": "Goodfellas", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-44", "date": "2026-05-31", "time": "08:00am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Camaradas", "team2": "Los Pericos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-45", "date": "2026-05-31", "time": "09:50am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Doom Squad", "team2": "Titans", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-46", "date": "2026-05-31", "time": "11:45am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Nasty Boyz", "team2": "Charros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-47", "date": "2026-05-31", "time": "08:00am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Naranjeros", "team2": "Demons", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-48", "date": "2026-05-31", "time": "09:50am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Strokes", "team2": "Desvelados", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-49", "date": "2026-05-31", "time": "11:45am", "park": "Bell Gardens - Ford Park", "division": "All", "team1": "Legends", "team2": "Primos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-50", "date": "2026-06-07", "time": "08:00am", "park": "Carson - Calas Park", "division": "All", "team1": "Demons", "team2": "Salvajes", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-51", "date": "2026-06-07", "time": "09:50am", "park": "Carson - Calas Park", "division": "All", "team1": "Goodfellas", "team2": "Orioles", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-52", "date": "2026-06-07", "time": "11:45am", "park": "Carson - Calas Park", "division": "All", "team1": "Xolos", "team2": "Desvelados", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-53", "date": "2026-06-07", "time": "08:00am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Caballeros", "team2": "Naranjeros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-54", "date": "2026-06-07", "time": "09:50am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Coyotes", "team2": "Bandits", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-55", "date": "2026-06-07", "time": "11:45am", "park": "Carson - Stevenson Park", "division": "All", "team1": "Nasty Boyz", "team2": "Primos", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-56", "date": "2026-06-07", "time": "08:00am", "park": "Carson - Dolphin Park", "division": "All", "team1": "White Sox", "team2": "Charros", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-57", "date": "2026-06-07", "time": "09:50am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Titans", "team2": "Dodgers", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-58", "date": "2026-06-07", "time": "11:45am", "park": "Carson - Dolphin Park", "division": "All", "team1": "Camaradas", "team2": "Wild Hogz", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-59", "date": "2026-06-07", "time": "08:00am", "park": "Carson - Veterans Park", "division": "All", "team1": "Toxic", "team2": "Doom Squad", "score1": "", "score2": "", "status": "scheduled"}, {"id": "game-60", "date": "2026-06-07", "time": "09:50am", "park": "Carson - Veterans Park", "division": "All", "team1": "Dirt Bags", "team2": "Los Pericos", "score1": "", "score2": "", "status": "scheduled"}];
const DEFAULT_TEAMS_BY_DIVISION = {"A": ["Titans", "La Tribu", "Nasty Boyz", "Toxic", "White Sox", "Legends"], "B": ["Cubs", "Primos", "Dodgers", "Diablos", "Charros", "Doom Squad"], "C": ["Demons", "Naranjeros", "Caballeros", "Salvajes", "Coyotes", "Bandits", "Orioles", "Goodfellas"], "D": ["Strokes", "Dirt Bags", "Camaradas", "Wild Hogz", "Los Pericos", "Xolos", "Desvelados"], "E": []};
function buildDefaultStandings() {
  const standings = {};
  Object.entries(DEFAULT_TEAMS_BY_DIVISION).forEach(([division, teams]) => {
    standings[division] = {};
    (teams || []).forEach(team => standings[division][team] = { w: 0, l: 0, t: 0, rf: 0, ra: 0, gp: 0 });
  });
  return standings;
}

function getTeamDivisionBackend(teamName) {
  for (const [division, teams] of Object.entries(DEFAULT_TEAMS_BY_DIVISION)) {
    if ((teams || []).includes(teamName)) return division;
  }
  return 'All';
}
function buildStandingsFromGamesBackend(games) {
  const standings = buildDefaultStandings();
  (games || []).forEach(game => {
    if (game.score1 === '' || game.score2 === '' || game.score1 == null || game.score2 == null) return;
    const s1 = Number(game.score1), s2 = Number(game.score2);
    if (!Number.isFinite(s1) || !Number.isFinite(s2)) return;
    [[game.team1, s1, s2], [game.team2, s2, s1]].forEach(([team, rf, ra]) => {
      const division = getTeamDivisionBackend(team);
      standings[division] = standings[division] || {};
      standings[division][team] = standings[division][team] || { w: 0, l: 0, t: 0, rf: 0, ra: 0, gp: 0 };
      const row = standings[division][team];
      row.gp += 1;
      row.rf += rf;
      row.ra += ra;
      if (rf > ra) row.w += 1;
      else if (rf < ra) row.l += 1;
      else row.t += 1;
    });
  });
  return standings;
}

function normalizeContent(raw) {
  const content = raw && typeof raw === 'object' ? raw : {};
  if (!Array.isArray(content.gameSchedules) || content.gameSchedules.length === 0) content.gameSchedules = DEFAULT_GAME_SCHEDULES;
  if (!Array.isArray(content.gameScores)) content.gameScores = [];
  if (!Array.isArray(content.practiceSchedules)) content.practiceSchedules = [];
  if (!Array.isArray(content.slideshow)) content.slideshow = [];
  if (!Array.isArray(content.eventFundraiserImages)) content.eventFundraiserImages = [];
  if (!content.rosters || typeof content.rosters !== 'object' || Array.isArray(content.rosters)) content.rosters = {};
  if (!content.teamPlayers || typeof content.teamPlayers !== 'object' || Array.isArray(content.teamPlayers)) content.teamPlayers = {};
  if (!content.teamPhotos || typeof content.teamPhotos !== 'object' || Array.isArray(content.teamPhotos)) content.teamPhotos = {};
  content.standings = buildStandingsFromGamesBackend(content.gameSchedules);
  if (!content.zelle || typeof content.zelle !== 'object' || Array.isArray(content.zelle)) content.zelle = {};
  if (typeof content.homepageMessage !== 'string') content.homepageMessage = '';
  return content;
}

const contentFile = path.join(dataDir, 'content.json');
function readContent() {
  try {
    if (!fs.existsSync(contentFile)) {
      const bundledContent = path.join(bundledDataDir, 'content.json');
      if (fs.existsSync(bundledContent)) {
        const seeded = normalizeContent(JSON.parse(fs.readFileSync(bundledContent, 'utf8')));
        fs.writeFileSync(contentFile, JSON.stringify(seeded, null, 2));
        return seeded;
      }
      return normalizeContent({});
    }
    return normalizeContent(JSON.parse(fs.readFileSync(contentFile, 'utf8')));
  } catch (e) {
    return normalizeContent({});
  }
}

function writeContent(content) {
  const normalized = normalizeContent(content || {});
  fs.writeFileSync(contentFile, JSON.stringify(normalized, null, 2));
  return normalized;
}

// Backward-compatible aliases used by older route code.
const loadContent = readContent;
const saveContent = writeContent;


app.get('/api/storage-status', (req, res) => {
  res.json({
    success: true,
    persistentRoot,
    uploadDir,
    dataDir,
    contentFile,
    storageDirConfigured: !!process.env.LAMSL_STORAGE_DIR,
    contentFileExists: fs.existsSync(contentFile),
    uploadDirExists: fs.existsSync(uploadDir),
    slideshowDir,
    slideshowDirExists: fs.existsSync(slideshowDir)
  });
});

function getMergedHomepageSlideshow(content) {
  const contentImages = Array.isArray(content.slideshow) ? content.slideshow : [];
  let diskImages = [];
  try {
    diskImages = fs.readdirSync(slideshowDir)
      .filter(name => /\.(png|jpe?g|gif|webp|svg)$/i.test(name))
      .map(name => ({ name, filename: name, url: '/SlideshowImages/' + name, path: '/SlideshowImages/' + name, caption: '' }));
  } catch (error) {
    diskImages = [];
  }
  const seen = new Set();
  return [...contentImages, ...diskImages].filter(img => {
    const key = img && (img.url || img.path || img.filename || img.name);
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

app.get('/api/content', (req, res) => {
  const content = readContent();
  res.json({
    ...content,
    slideshow: getMergedHomepageSlideshow(content),
    deploymentVersion: '2026.06.05-stability-single-source-v1'
  });
});

app.post('/api/update', requireAdminKey, async (req, res) => {
  try {
    const current = loadContent();
    const previousScheduleSignature = scheduleSignature(current);
    const incoming = req.body && typeof req.body === 'object' ? req.body : {};
    const next = {
      ...current,
      ...incoming,
      gameSchedules: Array.isArray(incoming.gameSchedules) ? incoming.gameSchedules : (current.gameSchedules || []),
      practiceSchedules: Array.isArray(incoming.practiceSchedules) ? incoming.practiceSchedules : (current.practiceSchedules || []),
      slideshow: Array.isArray(incoming.slideshow) ? incoming.slideshow : (current.slideshow || []),
      eventFundraiserImages: Array.isArray(incoming.eventFundraiserImages) ? incoming.eventFundraiserImages : (current.eventFundraiserImages || []),
      rosters: incoming.rosters && typeof incoming.rosters === 'object' ? incoming.rosters : (current.rosters || {}),
      teamPlayers: incoming.teamPlayers && typeof incoming.teamPlayers === 'object' ? incoming.teamPlayers : (current.teamPlayers || {}),
      teamPhotos: incoming.teamPhotos && typeof incoming.teamPhotos === 'object' ? incoming.teamPhotos : (current.teamPhotos || {}),
      announcements: Array.isArray(incoming.announcements) ? incoming.announcements : (current.announcements || []),
      zelle: incoming.zelle && typeof incoming.zelle === 'object' ? incoming.zelle : (current.zelle || {}),
      homepageMessage: Object.prototype.hasOwnProperty.call(incoming, 'homepageMessage') ? incoming.homepageMessage : (current.homepageMessage || '')
    };

    next.gameScores = Array.isArray(next.gameSchedules)
      ? next.gameSchedules.filter(game => game.score1 !== '' && game.score2 !== '' && game.score1 != null && game.score2 != null)
      : [];
    next.standings = buildStandingsFromGamesBackend(next.gameSchedules || []);
    next.updatedAt = new Date().toISOString();

    saveContent(next);
    const nextScheduleSignature = scheduleSignature(next);
    if (previousScheduleSignature !== nextScheduleSignature && process.env.LAMSL_AUTO_NOTIFY_SCHEDULE_UPDATES !== 'false') {
      sendScheduleUpdateNotification(next, { automatic: true, reason: 'backend-schedule-change' })
        .catch(error => logNotification({ type: 'schedule-update', status: 'automatic-send-error', error: error.message }));
    }
    res.json({ success: true, content: next, scheduleNotificationQueued: previousScheduleSignature !== nextScheduleSignature });
  } catch (error) {
    console.error('Content update failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== EF Images (Events) =====
const efMetaFile = path.join(projectRoot, 'ef_images_metadata.json');
function readEfMeta() {
  try {
    if (!fs.existsSync(efMetaFile)) return [];
    const parsed = JSON.parse(fs.readFileSync(efMetaFile, 'utf8'));
    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === 'object') {
      return Object.entries(parsed).map(([name, value]) => ({
        name,
        filename: name,
        path: value?.path || value?.url || ('/EFimages/' + name),
        url: value?.url || value?.path || ('/EFimages/' + name),
        caption: value?.caption || ''
      }));
    }
    return [];
  } catch (e) { return []; }
}
function writeEfMeta(arr) {
  try { fs.writeFileSync(efMetaFile, JSON.stringify(arr, null, 2)); } catch (e) {}
}

const uploadEf = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => cb(null, efDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    const name = `${Date.now()}-${Math.random().toString(36).slice(2,8)}${ext}`;
    cb(null, name);
  }
})});

app.get('/ef-images', (req, res) => {
  const images = readEfMeta();
  res.json({ success: true, images });
});

app.post('/upload-ef', requireAdminKey, uploadEf.single('photo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file' });
    const caption = (req.body.caption || '').toString();
    const filename = req.file.filename;
    const relPath = ('/EFimages/' + filename);
    const meta = readEfMeta();
    meta.unshift({ name: filename, path: relPath, url: relPath, caption });
    writeEfMeta(meta);
    res.json({ success: true, filename, path: relPath, caption });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/remove-ef-photo', requireAdminKey, express.json(), (req, res) => {
  try {
    const { filename } = req.body || {};
    if (!filename) return res.status(400).json({ success: false, error: 'No filename' });
    const info = getManagedImageInfo({ filename, destination: 'events' });
    const full = path.resolve(info.folder, info.filename);
    if (fs.existsSync(full)) fs.unlinkSync(full);
    const meta = readEfMeta().filter(i => !sameManagedImage(i, info));
    writeEfMeta(meta);
    const content = readContent();
    content.eventFundraiserImages = (content.eventFundraiserImages || []).filter(i => !sameManagedImage(i, info));
    content.updatedAt = new Date().toISOString();
    writeContent(content);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


// ===== Subscriber notifications =====
function normalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return '';
  return email;
}

function subscribersFilePath() {
  return path.join(dataDir, 'email_subscribers.json');
}

function legacySubscribersFilePath() {
  return path.join(projectRoot, 'email_subscribers.json');
}

function readSubscribers() {
  const files = [subscribersFilePath(), legacySubscribersFilePath()];
  const byEmail = new Map();
  for (const file of files) {
    try {
      if (!fs.existsSync(file)) continue;
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8') || '[]');
      const list = Array.isArray(parsed) ? parsed : [];
      list.forEach(item => {
        const email = normalizeEmail(item?.email || item);
        if (!email) return;
        byEmail.set(email, typeof item === 'object' ? { ...item, email } : { email });
      });
    } catch (error) {
      console.warn('Subscriber read failed:', file, error.message);
    }
  }
  return [...byEmail.values()].sort((a, b) => String(a.email).localeCompare(String(b.email)));
}

function writeSubscribers(subscribers) {
  const cleaned = [];
  const seen = new Set();
  (subscribers || []).forEach(item => {
    const email = normalizeEmail(item?.email || item);
    if (!email || seen.has(email)) return;
    seen.add(email);
    cleaned.push(typeof item === 'object' ? { ...item, email } : { email });
  });
  fs.writeFileSync(subscribersFilePath(), JSON.stringify(cleaned, null, 2));
  return cleaned;
}

function formatEmailDate(dateKey) {
  if (!dateKey) return 'TBD';
  const d = new Date(`${dateKey}T00:00:00`);
  if (Number.isNaN(d.getTime())) return dateKey;
  return d.toLocaleDateString('en-US', { month: '2-digit', day: '2-digit', year: 'numeric' });
}

function formatEmailTime(value) {
  const raw = String(value || '').trim();
  if (!raw) return 'TBD';
  const cleaned = raw.replace(/\s+/g, ' ').replace(/\b(am|pm)\s*(am|pm)\b/ig, '$1').trim();
  const match = cleaned.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/i);
  if (!match) return cleaned.toUpperCase().replace(/\s*([AP]M)$/i, ' $1');
  let hour = Number(match[1]);
  const minute = match[2] || '00';
  let suffix = match[3] ? match[3].toUpperCase() : '';
  if (!suffix) {
    suffix = hour >= 12 ? 'PM' : 'AM';
    if (hour > 12) hour -= 12;
    if (hour === 0) hour = 12;
  }
  return `${hour}:${minute} ${suffix}`;
}

function getUpcomingGames(content, limit = 5) {
  const games = Array.isArray(content?.gameSchedules) ? content.gameSchedules : [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const sorted = [...games].sort((a, b) => `${a.date || ''} ${a.time || ''}`.localeCompare(`${b.date || ''} ${b.time || ''}`));
  const upcoming = sorted.filter(game => {
    const d = new Date(`${game.date}T00:00:00`);
    return !Number.isNaN(d.getTime()) && d >= today;
  });
  return (upcoming.length ? upcoming : sorted).slice(0, limit);
}

function escapeEmailHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function buildNextGamesRows(games) {
  if (!games.length) {
    return '<tr><td colspan="5">No upcoming games are currently scheduled.</td></tr>';
  }
  return games.map(game => {
    const matchup = `${game.team1 || 'TBD'} vs ${game.team2 || 'TBD'}`;
    return `<tr><td>${escapeEmailHtml(formatEmailDate(game.date))}</td><td>${escapeEmailHtml(formatEmailTime(game.time))}</td><td>${escapeEmailHtml(game.division || 'All')}</td><td>${escapeEmailHtml(matchup)}</td><td>${escapeEmailHtml(game.park || 'TBD')}</td></tr>`;
  }).join('\n');
}

function buildScheduleUpdateEmail(content, options = {}) {
  const games = getUpcomingGames(content, Number(options.limit || 5));
  const rows = buildNextGamesRows(games);
  const subject = options.subject || 'LAMSL Weekly Schedule Update';
  const textLines = [
    'Hello LAMSL Subscriber,',
    '',
    'The game schedule has been updated. Below is a snapshot of the upcoming games currently scheduled.',
    '',
    ...games.map(game => `${formatEmailDate(game.date)} ${formatEmailTime(game.time)} - ${game.team1 || 'TBD'} vs ${game.team2 || 'TBD'} - ${game.park || 'TBD'}`),
    '',
    'View the full schedule: https://www.lamsl.com/schedule.html',
    '',
    'LAMSL Support Team\nlamslsupport@gmail.com\nhttps://www.lamsl.com'
  ];
  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>${escapeEmailHtml(subject)}</title></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;color:#222;">
<div style="width:100%;padding:30px 0;"><div style="max-width:700px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #d9d9d9;">
<div style="background:#12324A;color:#fff;text-align:center;padding:24px;"><h1 style="margin:0;font-size:28px;">LAMSL Weekly Schedule Update</h1></div>
<div style="padding:30px;"><h2 style="margin-top:0;color:#12324A;">Hello LAMSL Subscriber,</h2>
<p style="font-size:16px;line-height:1.6;">The game schedule has been updated. Below is a snapshot of the upcoming games currently scheduled.</p>
<div style="background:#f1f5fb;border-left:5px solid #C86A2F;padding:12px 15px;margin-bottom:15px;font-weight:bold;color:#12324A;">Next Games Mini Schedule</div>
<table style="width:100%;border-collapse:collapse;margin-bottom:25px;"><thead><tr><th style="background:#12324A;color:#fff;padding:12px;text-align:left;">Date</th><th style="background:#12324A;color:#fff;padding:12px;text-align:left;">Time</th><th style="background:#12324A;color:#fff;padding:12px;text-align:left;">Division</th><th style="background:#12324A;color:#fff;padding:12px;text-align:left;">Matchup</th><th style="background:#12324A;color:#fff;padding:12px;text-align:left;">Park</th></tr></thead><tbody>${rows}</tbody></table>
<div style="text-align:center;margin-top:30px;"><a href="https://www.lamsl.com/schedule.html" style="display:inline-block;background:#12324A;color:#fff;text-decoration:none;padding:14px 24px;border-radius:6px;font-weight:bold;">View Full Schedule</a></div>
</div><div style="background:#f1f1f1;padding:20px;text-align:center;font-size:12px;color:#666;">LAMSL Support Team<br>lamslsupport@gmail.com<br>https://www.lamsl.com<br><br>You are receiving this email because you subscribed to LAMSL schedule notifications.</div>
</div></div></body></html>`;
  return { subject, html, text: textLines.join('\n'), games };
}

function smtpConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && (process.env.MAIL_FROM || process.env.SMTP_FROM));
}

function readSmtpResponse(socket) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error('SMTP response timeout')), 20000);
    const onData = chunk => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/).filter(Boolean);
      if (lines.length && /^\d{3}\s/.test(lines[lines.length - 1])) {
        cleanup();
        resolve(buffer);
      }
    };
    const onError = error => { cleanup(); reject(error); };
    const cleanup = () => { clearTimeout(timer); socket.off('data', onData); socket.off('error', onError); };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

async function smtpCommand(socket, command, expected = /^[23]/) {
  if (command) socket.write(command + '\r\n');
  const response = await readSmtpResponse(socket);
  const code = response.slice(0, 3);
  if (!expected.test(code)) throw new Error(`SMTP command failed (${code}): ${response.trim()}`);
  return response;
}

function getSmtpPort() {
  return Number(process.env.SMTP_PORT || 587);
}

function smtpSecureMode() {
  const explicit = String(process.env.SMTP_SECURE || '').trim().toLowerCase();
  if (['true', '1', 'yes'].includes(explicit)) return true;
  if (['false', '0', 'no'].includes(explicit)) return false;
  return getSmtpPort() === 465;
}

function openSmtpSocket() {
  const host = process.env.SMTP_HOST;
  const port = getSmtpPort();
  const secure = smtpSecureMode();
  return new Promise((resolve, reject) => {
    const socket = secure ? tls.connect({ host, port, servername: host }) : net.connect({ host, port });
    socket.setTimeout(30000);
    socket.once('secureConnect', () => resolve(socket));
    socket.once('connect', () => { if (!secure) resolve(socket); });
    socket.once('error', reject);
    socket.once('timeout', () => reject(new Error('SMTP connection timeout')));
  });
}

function upgradeSmtpSocketToTls(socket) {
  const host = process.env.SMTP_HOST;
  return new Promise((resolve, reject) => {
    socket.removeAllListeners('timeout');
    const secureSocket = tls.connect({ socket, servername: host }, () => {
      secureSocket.setTimeout(30000);
      resolve(secureSocket);
    });
    secureSocket.once('error', reject);
    secureSocket.once('timeout', () => reject(new Error('SMTP TLS connection timeout')));
  });
}

function buildRawEmail({ from, to, subject, html, text }) {
  const boundary = `LAMSL-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
    '',
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    html,
    '',
    `--${boundary}--`,
    ''
  ].join('\r\n');
}

async function sendSmtpEmail({ to, subject, html, text }) {
  const from = process.env.MAIL_FROM || process.env.SMTP_FROM;
  let socket = await openSmtpSocket();
  try {
    await smtpCommand(socket, null);
    await smtpCommand(socket, `EHLO ${process.env.SMTP_EHLO_DOMAIN || 'lamsl.com'}`);
    if (!smtpSecureMode()) {
      await smtpCommand(socket, 'STARTTLS', /^2/);
      socket = await upgradeSmtpSocketToTls(socket);
      await smtpCommand(socket, `EHLO ${process.env.SMTP_EHLO_DOMAIN || 'lamsl.com'}`);
    }
    await smtpCommand(socket, `AUTH PLAIN ${Buffer.from(`\0${process.env.SMTP_USER}\0${process.env.SMTP_PASS}`).toString('base64')}`);
    await smtpCommand(socket, `MAIL FROM:<${from.match(/<([^>]+)>/)?.[1] || from}>`);
    await smtpCommand(socket, `RCPT TO:<${to}>`);
    await smtpCommand(socket, 'DATA', /^3/);
    socket.write(buildRawEmail({ from, to, subject, html, text }).replace(/\r?\n\.\r?\n/g, '\r\n..\r\n') + '\r\n.\r\n');
    await smtpCommand(socket, null);
    await smtpCommand(socket, 'QUIT', /^[23]/).catch(() => null);
  } finally {
    socket.end();
  }
}

function logNotification(entry) {
  fs.appendFileSync(path.join(logsDir, 'notifications.log'), JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
}

async function sendScheduleUpdateNotification(content, options = {}) {
  const subscribers = readSubscribers();
  const email = buildScheduleUpdateEmail(content, options);
  const result = { success: true, configured: smtpConfigured(), subscriberCount: subscribers.length, sent: 0, failed: 0, preview: email };
  if (!subscribers.length) {
    logNotification({ type: 'schedule-update', status: 'skipped-no-subscribers', options });
    return result;
  }
  if (!smtpConfigured()) {
    logNotification({ type: 'schedule-update', status: 'preview-only-smtp-not-configured', subscriberCount: subscribers.length, options, subject: email.subject });
    result.success = false;
    result.error = 'SMTP is not configured. Add SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and MAIL_FROM in Render.';
    return result;
  }
  for (const subscriber of subscribers) {
    try {
      await sendSmtpEmail({ to: subscriber.email, subject: email.subject, html: email.html, text: email.text });
      result.sent += 1;
    } catch (error) {
      result.failed += 1;
      logNotification({ type: 'schedule-update', status: 'send-failed', to: subscriber.email, error: error.message });
    }
  }
  logNotification({ type: 'schedule-update', status: 'sent', subscriberCount: subscribers.length, sent: result.sent, failed: result.failed, automatic: !!options.automatic });
  return result;
}

function scheduleSignature(content) {
  const games = Array.isArray(content?.gameSchedules) ? content.gameSchedules : [];
  return crypto.createHash('sha256').update(JSON.stringify(games.map(g => ({ id: g.id, date: g.date, time: g.time, park: g.park, division: g.division, team1: g.team1, team2: g.team2, status: g.status })))).digest('hex');
}

app.get('/api/subscribers', requireAdminKey, (req, res) => {
  const subscribers = readSubscribers();
  res.json({ success: true, count: subscribers.length, subscribers: subscribers.map(item => ({ email: item.email, subscribedAt: item.subscribedAt || null })) });
});


app.get('/api/notifications/status', (req, res) => {
  const subscribers = readSubscribers();
  res.json({
    success: true,
    smtpConfigured: smtpConfigured(),
    subscriberCount: subscribers.length,
    smtp: {
      hostConfigured: !!process.env.SMTP_HOST,
      port: String(getSmtpPort()),
      secure: smtpSecureMode(),
      userConfigured: !!process.env.SMTP_USER,
      passConfigured: !!process.env.SMTP_PASS,
      fromConfigured: !!(process.env.MAIL_FROM || process.env.SMTP_FROM)
    },
    requiredVariables: ['SMTP_HOST','SMTP_PORT','SMTP_USER','SMTP_PASS','MAIL_FROM']
  });
});

app.get('/api/notifications/schedule-preview', requireAdminKey, (req, res) => {
  const content = readContent();
  const preview = buildScheduleUpdateEmail(content, { limit: Number(req.query.limit || 5) });
  res.json({ success: true, subscriberCount: readSubscribers().length, smtpConfigured: smtpConfigured(), preview });
});

app.post('/api/notifications/send-schedule-update', requireAdminKey, async (req, res) => {
  try {
    const content = readContent();
    const result = await sendScheduleUpdateNotification(content, { manual: true, reason: req.body?.reason || 'manual-admin-send' });
    res.status(result.success ? 200 : 400).json(result);
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== Notifications legacy aliases =====
app.post('/notify-schedule-update', requireAdminKey, async (req, res) => {
  try {
    const result = await sendScheduleUpdateNotification(readContent(), { manual: true, reason: req.body?.reason || 'legacy-notify-schedule-update' });
    res.status(result.success ? 200 : 400).json(result);
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/notify-announcement', requireAdminKey, (req, res) => {
  try {
    const payload = req.body || {};
    const ln = JSON.stringify({ ts: new Date().toISOString(), type: 'announcement', payload }) + '\n';
    fs.appendFileSync(path.join(logsDir, 'notifications.log'), ln);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ===== Team photo uploads =====
function safeFolderSegment(value, fallback = 'unknown') {
  const cleaned = String(value || fallback)
    .trim()
    .replace(/[\\/]/g, '-')
    .replace(/[^a-zA-Z0-9 ._()-]/g, '')
    .replace(/\s+/g, ' ')
    .slice(0, 80);
  return cleaned || fallback;
}

function normalizeTeamPhotoUrl(record) {
  if (!record || typeof record !== 'object') return null;
  const raw = record.url || record.path || '';
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) return { ...record, url: raw, path: raw };
  const fixed = raw.startsWith('/') ? raw : '/' + raw;
  return { ...record, url: fixed, path: fixed };
}

const uploadTeam = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const team = safeFolderSegment(req.body.team || req.query.team, 'unknown');
      const division = safeFolderSegment(req.body.division || req.query.division, 'Misc');
      const folder = path.join(teamProfileDir, division, team);
      fs.mkdirSync(folder, { recursive: true });
      cb(null, folder);
    } catch (error) {
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase() || '.jpg';
    const name = `team-photo-${Date.now()}${ext}`;
    cb(null, name);
  }
})});

const teamMetaFile = path.join(dataDir, 'team_profile_metadata.json');
function readTeamMeta() { try { return fs.existsSync(teamMetaFile) ? JSON.parse(fs.readFileSync(teamMetaFile, 'utf8')) : {}; } catch (e) { return {}; } }
function writeTeamMeta(m) { try { fs.writeFileSync(teamMetaFile, JSON.stringify(m, null, 2)); } catch (e) {} }

function handleTeamPhotoUpload(req, res) {
  uploadTeam.single('photo')(req, res, (uploadError) => {
    try {
      if (uploadError) {
        return res.status(400).json({ success: false, error: uploadError.message || 'Team photo upload failed.' });
      }
      if (!req.file) return res.status(400).json({ success: false, error: 'No team photo file was received. Use form field name "photo".' });
      const team = safeFolderSegment(req.body.team || req.query.team, 'unknown');
      const division = safeFolderSegment(req.body.division || req.query.division, 'Misc');
      const publicFolder = `/TeamProfileImages/${encodeURIComponent(division)}/${encodeURIComponent(team)}`;
      const relPath = `${publicFolder}/${encodeURIComponent(req.file.filename)}`;
      const record = {
        team,
        division,
        filename: req.file.filename,
        folder: `TeamProfileImages/${division}/${team}`,
        path: relPath,
        url: relPath,
        uploadedAt: new Date().toISOString()
      };

      const meta = readTeamMeta();
      meta[team] = Array.isArray(meta[team]) ? meta[team] : [];
      meta[team].unshift(record);
      writeTeamMeta(meta);

      const content = readContent();
      content.teamPhotos = content.teamPhotos && typeof content.teamPhotos === 'object' && !Array.isArray(content.teamPhotos) ? content.teamPhotos : {};
      content.teamPhotos[team] = record;
      content.updatedAt = new Date().toISOString();
      writeContent(content);

      res.json({ success: true, ...record });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message, stack: process.env.NODE_ENV === 'production' ? undefined : e.stack });
    }
  });
}

app.post('/upload-team-photo', requireTeamContentAuth, handleTeamPhotoUpload);
app.post('/api/upload-team-photo', requireTeamContentAuth, handleTeamPhotoUpload);


function getTeamPhotoRecord(team) {
  const content = readContent();
  if (content.teamPhotos && content.teamPhotos[team]) return normalizeTeamPhotoUrl(content.teamPhotos[team]);
  const meta = readTeamMeta();
  const list = meta[team];
  if (Array.isArray(list) && list.length) return normalizeTeamPhotoUrl(list[0]);
  return null;
}

app.get('/team-profile-photo', (req, res) => {
  const team = String(req.query.team || '').trim();
  if (!team) return res.status(400).json({ success: false, error: 'Missing team.' });
  res.json({ success: true, photo: getTeamPhotoRecord(team) });
});

app.get('/api/team-profile-photo', (req, res) => {
  const team = String(req.query.team || '').trim();
  if (!team) return res.status(400).json({ success: false, error: 'Missing team.' });
  res.json({ success: true, photo: getTeamPhotoRecord(team) });
});

app.get('/api/team-metadata', (req, res) => {
  res.json({ success: true, teams: readTeamMeta() });
});

app.post('/api/team-metadata', requireAdminKey, (req, res) => {
  try {
    writeTeamMeta(req.body || {});
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});


// ===== Roster data =====
app.get('/api/rosters', (req, res) => {
  const content = readContent();
  res.json({ success: true, rosters: content.rosters || {}, teamPlayers: content.teamPlayers || {} });
});

app.post('/api/rosters', requireTeamContentAuth, (req, res) => {
  try {
    const content = readContent();
    const incoming = req.body || {};
    content.rosters = incoming.rosters && typeof incoming.rosters === 'object' ? incoming.rosters : (content.rosters || {});
    content.teamPlayers = incoming.teamPlayers && typeof incoming.teamPlayers === 'object' ? incoming.teamPlayers : (content.teamPlayers || {});
    content.updatedAt = new Date().toISOString();
    writeContent(content);
    res.json({ success: true, rosters: content.rosters, teamPlayers: content.teamPlayers });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>LAMSL Backend</title></head>
<body>
  <h1>LAMSL Backend</h1>
  <p>This service exposes API endpoints only.</p>
  <ul>
    <li><a href="/health">/health</a></li>
    <li><a href="/api/admin-health">/api/admin-health</a></li>
    <li><a href="/api/content">/api/content</a></li>
  </ul>
  <p>Use the admin key for protected endpoints.</p>
</body>
</html>`);
});

// Health endpoint for automated checks
app.get('/health', (req, res) => {
  try {
    const checks = {
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      dirs: {
        uploads: fs.existsSync(uploadDir),
        efImages: fs.existsSync(efDir),
        data: fs.existsSync(dataDir),
        teamProfileImages: fs.existsSync(teamProfileDir)
      }
    };
    res.json({ ok: true, checks });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/admin-health', (req, res) => {
  res.json({ adminApiKeyConfigured: !!ADMIN_API_KEY });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend running at http://localhost:${PORT}`);
});
