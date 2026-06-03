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
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
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

app.listen(3000, () => {
  console.log('Backend running at http://localhost:3000');
});
