import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import cors from 'cors';

const app = express();
app.use(express.json());
app.use(cors());

// Ensure uploads folder exists
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
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

app.listen(3000, () => {
  console.log('Backend running at http://localhost:3000');
});
