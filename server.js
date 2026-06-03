import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import cors from 'cors';

const app = express();
app.use(express.json());
app.use(cors());

// Ensure required directories exist
const uploadDir = path.join(process.cwd(), 'uploads');
const logsDir = path.join(process.cwd(), 'logs');
const efDir = path.join(process.cwd(), '..', 'EF_Images');
const dataDir = path.join(process.cwd(), 'data');
const teamProfileDir = path.join(process.cwd(), '..', 'teamProfile images');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
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

  fs.appendFileSync('subscribers.txt', email + '\n');

  res.json({
    success: true,
    message: 'Email subscribed'
  });
});

// Image upload endpoint
const upload = multer({ dest: 'uploads/' });

app.post('/api/upload-image', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: 'No file uploaded'
    });
  }

  const url = '/uploads/' + req.file.filename;

  res.json({
    success: true,
    url
  });
});

// Serve uploaded images
app.use('/uploads', express.static('uploads'));

// Admin action logging endpoint
app.post('/api/log-admin-action', (req, res) => {
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
const contentFile = path.join(dataDir, 'content.json');
function readContent() {
  try {
    if (!fs.existsSync(contentFile)) return {
      homepageMessage: '',
      zelle: {},
      gameSchedules: [],
      gameScores: [],
      slideshow: []
    };
    return JSON.parse(fs.readFileSync(contentFile, 'utf8'));
  } catch (e) {
    return { homepageMessage: '', zelle: {}, gameSchedules: [], gameScores: [], slideshow: [] };
  }
}

app.get('/api/content', (req, res) => {
  const content = readContent();
  res.json(content);
});

app.post('/api/update', (req, res) => {
  try {
    const body = req.body || {};
    fs.writeFileSync(contentFile, JSON.stringify(body, null, 2));
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ===== EF Images (Events) =====
const efMetaFile = path.join(process.cwd(), '..', 'ef_images_metadata.json');
function readEfMeta() {
  try {
    if (!fs.existsSync(efMetaFile)) return [];
    return JSON.parse(fs.readFileSync(efMetaFile, 'utf8'));
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

app.post('/upload-ef', uploadEf.single('photo'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'No file' });
    const caption = (req.body.caption || '').toString();
    const filename = req.file.filename;
    const relPath = path.join('EF_Images', filename).replace(/\\/g, '/');
    const meta = readEfMeta();
    meta.unshift({ name: filename, path: relPath, caption });
    writeEfMeta(meta);
    res.json({ success: true, filename, path: relPath, caption });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/remove-ef-photo', express.json(), (req, res) => {
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
app.post('/notify-schedule-update', (req, res) => {
  try {
    const payload = req.body || {};
    const ln = JSON.stringify({ ts: new Date().toISOString(), type: 'schedule-update', payload }) + '\n';
    fs.appendFileSync(path.join(logsDir, 'notifications.log'), ln);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/notify-announcement', (req, res) => {
  try {
    const payload = req.body || {};
    const ln = JSON.stringify({ ts: new Date().toISOString(), type: 'announcement', payload }) + '\n';
    fs.appendFileSync(path.join(logsDir, 'notifications.log'), ln);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ===== Team photo uploads =====n
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

const teamMetaFile = path.join(process.cwd(), '..', 'team_profile_metadata.json');
function readTeamMeta() { try { return fs.existsSync(teamMetaFile) ? JSON.parse(fs.readFileSync(teamMetaFile, 'utf8')) : {}; } catch (e) { return {}; } }
function writeTeamMeta(m) { try { fs.writeFileSync(teamMetaFile, JSON.stringify(m, null, 2)); } catch (e) {} }

app.post('/upload-team-photo', uploadTeam.single('photo'), (req, res) => {
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

app.listen(3000, () => {
  console.log('Backend running at http://localhost:3000');
});
