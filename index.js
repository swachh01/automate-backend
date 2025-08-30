// index.js - Reloaded Automate
const twilio = require('twilio');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, 
process.env.TWILIO_AUTH_TOKEN);
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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

db.getConnection()
  .then(conn => { console.log('✅ Connected to MySQL'); conn.release(); })
  .catch(err => { console.error('❌ MySQL connection failed:', 
err.message); process.exit(1); });

// ===================== Multer Setup =====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, 
`profile_${Date.now()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage });

// ===================== HELPER =====================
function needDB(res) {
  if (!db) {
    res.status(503).json({ success: false, message: "DB not ready" });
    return false;
  }
  return true;
}

// ===================== HEALTH =====================
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/', (req, res) => res.send('Backend running 🚀'));

// ===================== AUTH =====================

// ✅ Signup - save name, college, gender, phone (blank password first)
app.post("/signup", (req, res) => {
  const { name, college, gender, phone } = req.body;

  if (!name || !college || !gender || !phone) {
    return res.status(400).json({ success: false, message: `Missing 
required fields` });
  }

  const sql = `INSERT INTO users (name, college, gender, phone, password) 
VALUES (?, ?, ?, ?, ?)`;
  pool.query(sql, [name, college, gender, phone, ""], (err, result) => {
    if (err) {
      console.error("❌ Signup error:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }

    res.json({
      success: true,
      message: "User registered successfully",
      userId: result.insertId
    });
  });
});


// Login
app.post('/login', async (req, res) => {
  if (!needDB(res)) return;
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ success: false, 
message: 'Missing credentials' });

  try {
    const [rows] = await db.query(`SELECT id, name FROM users WHERE 
phone=? AND password=?`, [phone, password]);
    if (!rows.length) return res.json({ success: false, message: `Invalid 
phone or password` });
    const user = rows[0];
    res.json({ success: true, userId: user.id, name: user.name, message: 
'Login successful' });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== OTP & PASSWORD =====================

app.post('/sendOtp', async (req, res) => {
  if (!needDB(res)) return;
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: 
'Missing phone' });

  try {
    const code = ("" + Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

    // Save OTP in DB
    await db.query(
      `INSERT INTO otps (phone, code, expires_at) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE code=VALUES(code), 
expires_at=VALUES(expires_at)`,
      [phone, code, expiresAt]
    );

    // Send OTP via Twilio
    await client.messages.create({
      body: `Your OTP code is ${code}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone.startsWith('+') ? phone : `+91${phone}`
    });

    // Optionally create user if not exists
    await db.query(
      `INSERT IGNORE INTO users (phone, name, college) VALUES (?, 'User', 
'')`,
      [phone]
    );

    res.json({ success: true, message: 'OTP sent' });
  } catch (err) {
    console.error("sendOtp error:", err);
    res.status(500).json({ success: false, message: 'Failed to send OTP' 
});
  }
});


app.post('/verifyOtp', async (req, res) => {
  if (!needDB(res)) return;
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ success: false, 
message: 'Missing phone or otp' });

  try {
    const [rows] = await db.query('SELECT code, expires_at FROM otps WHERE phone=?', [phone]); 
    if (!rows.length) return res.json({ success: false, message: `No OTP 
found` });

    const rec = rows[0];
    if (rec.code !== otp) return res.json({ success: false, message: 
'Invalid OTP' });
    if (new Date(rec.expires_at) < new Date()) return res.json({ success: 
false, message: 'OTP expired' });

    await db.query('DELETE FROM otps WHERE phone=?', [phone]);

    res.json({ success: true, message: 'OTP verified' });
  } catch (err) {
    console.error("verifyOtp error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});


app.post("/savePassword", (req, res) => {
  const { phone, password } = req.body;

  console.log("📩 SavePassword request body:", req.body);  // 👈 DEBUG

  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Phone and 
password required` });
  }

  const sql = "UPDATE users SET password = ? WHERE phone = ?";
  pool.query(sql, [password, phone], (err, result) => {
    if (err) {
      console.error("❌ Save password error:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }

    if (result.affectedRows === 0) {
      console.log("⚠️ No rows updated. Phone not found:", phone);
      return res.status(404).json({ success: false, message: `User not 
found` });
    }

    res.json({ success: true, message: "Password updated successfully" });
  });
});


// ===================== PROFILE =====================

// ✅ Update Profile (dob, degree, year, profile_pic)
app.post("/updateProfile", upload.single("profile_pic"), (req, res) => {
  const { userId, dob, degree, year } = req.body;
  const profilePic = req.file ? req.file.filename : null;

  if (!userId) {
    return res.status(400).json({ success: false, message: `Missing 
userId` });
  }

  let sql = "UPDATE users SET ";
  let fields = [];
  let values = [];

  if (dob) { fields.push("dob = ?"); values.push(dob); }
  if (degree) { fields.push("degree = ?"); values.push(degree); }
  if (year) { fields.push("year = ?"); values.push(year); }
  if (profilePic) { fields.push("profile_pic = ?"); 
values.push(profilePic); }

  if (fields.length === 0) {
    return res.status(400).json({ success: false, message: `No fields to 
update` });
  }

  sql += fields.join(", ") + " WHERE id = ?";
  values.push(userId);

  pool.query(sql, values, (err, result) => {
    if (err) {
      console.error("❌ Update profile error:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }

    res.json({ success: true, message: "Profile updated successfully" });
  });
});


// ===================== TRAVEL PLANS =====================
app.post('/addTravelPlan', async (req, res) => {
  if (!needDB(res)) return;
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) return res.status(400).json({ 
success: false, message: 'Missing fields' });

  try {
    const [existing] = await db.query('SELECT id FROM travel_plans WHERE user_id=?', [userId]);
    if (existing.length) {
      await db.query(
        `UPDATE travel_plans SET destination=?, 
time=CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d %H:%i:%s'), '+05:30', '+00:00') 
WHERE user_id=?`,
        [destination, time, userId]
      );
      res.json({ success: true, message: 'Travel plan updated' });
    } else {
      await db.query(
        `INSERT INTO travel_plans (user_id, destination, time) VALUES (?, 
?, CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d %H:%i:%s'), '+05:30', '+00:00'))`,
        [userId, destination, time]
      );
      res.json({ success: true, message: 'Travel plan added' });
    }
  } catch (err) {
    console.error("addTravelPlan error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/getUserTravelPlan', async (req, res) => {
  if (!needDB(res)) return;
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ success: false, message: 
'Missing userId' });
  try {
    const [rows] = await db.query(`SELECT destination, 
DATE_FORMAT(CONVERT_TZ(time,'+00:00','+05:30'), '%Y-%m-%d %H:%i:%s') AS 
time FROM travel_plans WHERE user_id=?`, [userId]);
    res.json(rows[0] || null);
  } catch (err) {
    console.error("getUserTravelPlan error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/going-users', async (req, res) => {
  if (!needDB(res)) return;
  try {
    const [rows] = await db.query(
      `SELECT u.id AS userId, u.name AS username, u.college, 
t.destination,
              DATE_FORMAT(t.time, '%Y-%m-%dT%H:%i:%s.000Z') AS time
       FROM travel_plans t JOIN users u ON t.user_id = u.id
       ORDER BY t.time ASC`
    );
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error("going-users error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// Cleanup expired travel plans every minute
setInterval(async () => {
  try {
    const [result] = await db.query('DELETE FROM travel_plans WHERE time <= UTC_TIMESTAMP()');
    if (result.affectedRows > 0) console.log(`🧹 Deleted 
${result.affectedRows} expired travel plans`);
  } catch (err) {
    console.error("cleanup error:", err.message);
  }
}, 60 * 1000);

// ===================== CHAT =====================
app.post('/sendMessage', async (req, res) => {
  if (!needDB(res)) return;
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) return res.status(400).json({ 
success: false, message: 'Missing fields' });

  try {
    const [result] = await db.query(`INSERT INTO messages (sender_id, 
receiver_id, message) VALUES (?, ?, ?)`, [senderId, receiverId, message]);
    res.json({ success: true, message: 'Message sent', messageId: 
result.insertId });
  } catch (err) {
    console.error("sendMessage error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/getMessages', async (req, res) => {
  if (!needDB(res)) return;
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) return res.status(400).json({ success: 
false, message: 'Missing senderId or receiverId' });

  try {
    const [rows] = await db.query(
      `SELECT id, sender_id AS senderId, receiver_id AS receiverId, 
message,
              DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp,
              is_read AS isRead
       FROM messages
       WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND 
receiver_id=?)
       ORDER BY timestamp ASC`,
      [senderId, receiverId, receiverId, senderId]
    );
    res.json({ success: true, messages: rows });
  } catch (err) {
    console.error("getMessages error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// Recent chats
app.get('/getChatUsers', async (req, res) => {
  if (!needDB(res)) return;
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ success: false, message: 
'Missing userId' });

  try {
    const [rows] = await db.query(
      `SELECT u.id, u.name AS username,
              (SELECT m.message FROM messages m
               WHERE (m.sender_id=u.id AND m.receiver_id=?) OR 
(m.sender_id=? AND m.receiver_id=u.id)
               ORDER BY m.timestamp DESC LIMIT 1) AS lastMessage,
              (SELECT UNIX_TIMESTAMP(m.timestamp)*1000 FROM messages m
               WHERE (m.sender_id=u.id AND m.receiver_id=?) OR 
(m.sender_id=? AND m.receiver_id=u.id)
               ORDER BY m.timestamp DESC LIMIT 1) AS timestamp,
              (SELECT COUNT(*) FROM messages m
               WHERE m.receiver_id=? AND m.sender_id=u.id AND m.is_read=0) 
AS unreadCount
       FROM users u
       WHERE u.id != ?
       HAVING lastMessage IS NOT NULL
       ORDER BY timestamp DESC`,
      [userId, userId, userId, userId, userId, userId]
    );
    res.json({ success: true, chats: rows });
  } catch (err) {
    console.error("getChatUsers error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/markMessagesRead', async (req, res) => {
  if (!needDB(res)) return;
  const { userId, otherUserId } = req.body;
  if (!userId || !otherUserId) return res.status(400).json({ success: 
false, message: 'Missing fields' });
  try {
    await db.query(`UPDATE messages SET is_read=1 WHERE receiver_id=? AND 
sender_id=? AND is_read=0`, [userId, otherUserId]);
    res.json({ success: true });
  } catch (err) {
    console.error("markMessagesRead error:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ===================== START SERVER =====================
const PORT = process.env.PORT || 8080;
app.listen(PORT,"0.0.0.0", () => console.log(`🚀 Server running on port ${PORT}`));

