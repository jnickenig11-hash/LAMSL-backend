import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import crypto from 'crypto';

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
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!payload.exp || Date.now() > payload.exp) return null;
  if (!['admin', 'umpire'].includes(String(payload.role || '').toLowerCase())) return null;
  return payload;
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
  if (verifySessionToken(token)) return next();
  if (getStaticSession(req)) return next();
  return res.status(403).json({ success: false, error: 'Forbidden: admin login/session token or valid API key required' });
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
const teamProfileDir = path.join(persistentRoot, 'teamProfile images');
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

// Email signup endpoint
app.post('/api/subscribe', (req, res) => {
  const { email } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email'
    });
  }

  const subscribersFile = path.join(projectRoot, 'email_subscribers.json');
  let subscribers = [];
  try { subscribers = fs.existsSync(subscribersFile) ? JSON.parse(fs.readFileSync(subscribersFile, 'utf8') || '[]') : []; } catch (e) { subscribers = []; }
  if (!subscribers.some(item => String(item.email || item).toLowerCase() === email.toLowerCase())) {
    subscribers.push({ email, subscribedAt: new Date().toISOString() });
    fs.writeFileSync(subscribersFile, JSON.stringify(subscribers, null, 2));
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
app.use('/teamProfile images', express.static(teamProfileDir));
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

app.post('/api/update', requireAdminKey, (req, res) => {
  try {
    const current = loadContent();
    const incoming = req.body && typeof req.body === 'object' ? req.body : {};
    const next = {
      ...current,
      ...incoming,
      gameSchedules: Array.isArray(incoming.gameSchedules) ? incoming.gameSchedules : (current.gameSchedules || []),
      practiceSchedules: Array.isArray(incoming.practiceSchedules) ? incoming.practiceSchedules : (current.practiceSchedules || []),
      slideshow: Array.isArray(incoming.slideshow) ? incoming.slideshow : (current.slideshow || []),
      eventFundraiserImages: Array.isArray(incoming.eventFundraiserImages) ? incoming.eventFundraiserImages : (current.eventFundraiserImages || []),
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
    res.json({ success: true, content: next });
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
    const full = path.join(efDir, filename);
    if (fs.existsSync(full)) fs.unlinkSync(full);
    const meta = readEfMeta().filter(i => i.name !== filename);
    writeEfMeta(meta);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ===== Notifications (no-op/stub) =====
app.post('/notify-schedule-update', requireAdminKey, (req, res) => {
  try {
    const payload = req.body || {};
    const ln = JSON.stringify({ ts: new Date().toISOString(), type: 'schedule-update', payload }) + '\n';
    fs.appendFileSync(path.join(logsDir, 'notifications.log'), ln);
    res.json({ success: true });
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
const uploadTeam = multer({ storage: multer.diskStorage({
  destination: (req, file, cb) => {
    const team = (req.body.team || 'unknown').toString();
    const division = (req.body.division || '').toString();
    const folder = path.join(teamProfileDir, division || 'Misc', team || 'unknown');
    fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    const name = `${Date.now()}${ext}`;
    cb(null, name);
  }
})});

const teamMetaFile = path.join(projectRoot, 'team_profile_metadata.json');
function readTeamMeta() { try { return fs.existsSync(teamMetaFile) ? JSON.parse(fs.readFileSync(teamMetaFile, 'utf8')) : {}; } catch (e) { return {}; } }
function writeTeamMeta(m) { try { fs.writeFileSync(teamMetaFile, JSON.stringify(m, null, 2)); } catch (e) {} }

app.post('/upload-team-photo', requireAdminKey, uploadTeam.single('photo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file' });
    const team = (req.body.team || 'unknown').toString();
    const division = (req.body.division || '').toString();
    const relFolder = path.join('teamProfile images', division || 'Misc', team || 'unknown').replace(/\\/g, '/');
    const meta = readTeamMeta();
    meta[team] = meta[team] || [];
    meta[team].unshift({ filename: req.file.filename, folder: relFolder, path: path.join(relFolder, req.file.filename).replace(/\\/g, '/') });
    writeTeamMeta(meta);
    res.json({ success: true, folder: path.join(division || 'Misc', team || 'unknown').replace(/\\/g, '/'), filename: req.file.filename, path: path.join(relFolder, req.file.filename).replace(/\\/g, '/') });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
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

app.post('/api/rosters', requireAdminKey, (req, res) => {
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
