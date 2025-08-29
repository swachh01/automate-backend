const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ===================== MySQL Setup =====================
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ✅ Test DB connection
db.getConnection()
  .then(connection => {
    console.log('✅ Connected to MySQL database');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Failed to connect to MySQL:', err.message);
    process.exit(1);
  });

// ===================== Multer Setup =====================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Make sure this folder exists
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `profile_${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });

// ===================== AUTH =====================
// Signup
app.post('/signup', async (req, res) => {
  const { name, college, password } = req.body;
  if (!name || !college || !password) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  try {
    const [result] = await db.query(
      `INSERT INTO users (name, college, password) VALUES (?, ?, ?)`,
      [name, college, password]
    );
    res.json({ success: true, message: 'User created', userId: 
result.insertId });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ success: false, 
message: 'Missing credentials' });

  try {
    const [results] = await db.query(
      `SELECT * FROM users WHERE name = ? AND password = ?`,
      [name, password]
    );
    if (results.length > 0) {
      const user = results[0];
      res.json({ success: true, message: 'Login successful', userId: 
user.id, name: user.name });
    } else {
      res.json({ success: false, message: 'Invalid username or password' 
});
    }
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== OTP & Password =====================
app.post('/sendOtp', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: 
'Missing phone' });
  res.json({ success: true, message: 'OTP sent' });
});

app.post('/verifyOtp', (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ success: false, 
message: 'Missing phone or OTP' });
  res.json({ success: true, message: 'OTP verified' });
});

app.post('/savePassword', async (req, res) => {
  const { phone, newPassword } = req.body;
  if (!phone || !newPassword) return res.status(400).json({ success: 
false, message: 'Missing fields' });
  try {
    await db.query(
      `UPDATE users SET password = ? WHERE phone = ?`,
      [newPassword, phone]
    );
    res.json({ success: true, message: 'Password updated' });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== PROFILE =====================
app.post('/updateProfile', upload.single('profile_pic'), async (req, res) => { 
  const { userId, dob, degree, year } = req.body;
  if (!userId || !dob || !degree || !year) return res.status(400).json({ 
success: false, message: 'Missing fields' });

  let profilePicPath = req.file ? req.file.path : null;

  try {
    await db.query(
      `UPDATE users SET dob = ?, degree = ?, year = ?, profile_pic = ? 
WHERE id = ?`,
      [dob, degree, year, profilePicPath, userId]
    );
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== TRAVEL PLANS =====================
app.post('/addTravelPlan', async (req, res) => {
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) return res.status(400).json({ 
success: false, message: 'Missing fields' });

  try {
    const [existing] = await db.query(
      `SELECT * FROM travel_plans WHERE user_id = ?`,
      [userId]
    );
    if (existing.length > 0) {
      await db.query(
        `UPDATE travel_plans SET destination = ?, time = ? WHERE user_id = 
?`,
        [destination, new Date(time), userId]
      );
      res.json({ success: true, message: 'Travel plan updated' });
    } else {
      await db.query(
        `INSERT INTO travel_plans (user_id, destination, time) VALUES (?, 
?, ?)`,
        [userId, destination, new Date(time)]
      );
      res.json({ success: true, message: 'Travel plan added' });
    }
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/getUsersGoing', async (req, res) => {
  try {
    const [results] = await db.query(`
      SELECT u.id AS userId, u.name AS username, u.college, t.destination, 
t.time
      FROM travel_plans t
      JOIN users u ON t.user_id = u.id
      ORDER BY t.time ASC
    `);
    res.json({ success: true, users: results });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/getUserTravelPlan', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ success: false, message: 
'Missing userId' });

  try {
    const [results] = await db.query(
      `SELECT * FROM travel_plans WHERE user_id = ?`,
      [userId]
    );
    res.json(results[0] || null);
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== CHAT =====================
app.post('/sendMessage', async (req, res) => {
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) return res.status(400).json({ 
success: false, message: 'Missing fields' });

  try {
    const [result] = await db.query(
      `INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, 
?, ?)`,
      [senderId, receiverId, message]
    );
    res.json({ success: true, message: 'Message sent', messageId: 
result.insertId });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/getMessages', async (req, res) => {
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) return res.status(400).json({ success: 
false, message: 'Missing senderId or receiverId' });

  try {
    const [results] = await db.query(
      `SELECT * FROM messages 
       WHERE (sender_id = ? AND receiver_id = ?) 
          OR (sender_id = ? AND receiver_id = ?) 
       ORDER BY timestamp ASC`,
      [senderId, receiverId, receiverId, senderId]
    );
    res.json({ success: true, messages: results });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== MISC =====================
app.get("/health", (req, res) => res.status(200).send("OK"));

// ===================== START SERVER =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

