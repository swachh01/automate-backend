// index.js
const otpStore = {};
const express = require("express");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const mysql = require("mysql2/promise");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// ---- Static files (profile uploads) ----
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ---- Multer for profile image ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 
"uploads")),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, `profile_${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// ---- MySQL (non-blocking startup) ----
let pool = null;
(async () => {
  try {
    pool = await mysql.createPool({
      host: process.env.MYSQLHOST,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
      port: process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
    console.log("✅ MySQL pool ready");

    await ensureTables();
    console.log("✅ Tables ensured");
  } catch (e) {
    console.error("❌ MySQL init error:", e.message);
  }
})();

async function ensureTables() {
  if (!pool) return;

  const createUsers = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100),
      college VARCHAR(150),
      gender VARCHAR(20),
      phone VARCHAR(20) UNIQUE,
      password VARCHAR(255),
      dob VARCHAR(20),
      degree VARCHAR(100),
      year VARCHAR(20),
      profile_pic VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
  `;

  const createOtps = `
    CREATE TABLE IF NOT EXISTS otps (
      id INT AUTO_INCREMENT PRIMARY KEY,
      phone VARCHAR(20) UNIQUE,
      code VARCHAR(10),
      expires_at DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
  `;

  const createMessages = `
    CREATE TABLE IF NOT EXISTS messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      sender_id INT NOT NULL,
      receiver_id INT NOT NULL,
      message TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_read TINYINT(1) DEFAULT 0,
      CONSTRAINT fk_msg_sender FOREIGN KEY (sender_id) REFERENCES 
users(id) ON DELETE CASCADE,
      CONSTRAINT fk_msg_receiver FOREIGN KEY (receiver_id) REFERENCES 
users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB;
  `;

  const createTravelPlans = `
    CREATE TABLE IF NOT EXISTS travel_plans (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      destination VARCHAR(255) NOT NULL,
      time DATETIME NOT NULL,           -- stored in UTC
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_plan_user FOREIGN KEY (user_id) REFERENCES users(id) 
ON DELETE CASCADE,
      INDEX idx_time (time)
    ) ENGINE=InnoDB;
  `;

  await pool.query(createUsers);
  await pool.query(createOtps);
  await pool.query(createMessages);
  await pool.query(createTravelPlans);
}

// ---- Helper: require DB in route ----
function needDB(res) {
  if (!pool) {
    res.status(503).json({ success: false, message: "DB not ready" });
    return false;
  }
  return true;
}

// ===================== HEALTH =====================
app.get("/health", (req, res) => res.status(200).send("OK"));
app.get("/", (req, res) => res.send("Backend running fine 🚀"));

// ===================== AUTH & OTP FLOW =====================
// Stage 1: /signup (name, college, gender, phone)
app.post("/signup", async (req, res) => {
  if (!needDB(res)) return;
  const { name, college, gender, phone } = req.body;
  if (!name || !college || !gender || !phone) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  try {
    await pool.query(
      `
      INSERT INTO users (name, college, gender, phone)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE name=VALUES(name), college=VALUES(college), 
gender=VALUES(gender)
      `,
      [name, college, gender, phone]
    );
    const [rows] = await pool.query(`SELECT id FROM users WHERE phone = 
?`, [phone]); 
    return res.json({ success: true, userId: rows[0]?.id || null, message: 
"Profile saved" });
  } catch (e) {
    console.error("signup error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// Stage 2: send OTP

app.post("/sendOtp", (req, res) => {
  const { phone } = req.body;
  const otp = Math.floor(1000 + Math.random() * 9000);

  // save otp in memory
  otpStore[phone] = otp;

  console.log(`Generated OTP for ${phone}: ${otp}`);

  res.json({
    success: true,
    message: "OTP generated",
    otp: otp   // return for testing only
  });
});

// Stage 2: verify OTP


app.post("/verifyOtp", (req, res) => {
  const { phone, otp } = req.body;
  console.log(`Verifying OTP for ${phone}: entered=${otp}, 
expected=${otpStore[phone]}`);

  if (otpStore[phone] && otpStore[phone].toString() === otp.toString()) {
    delete otpStore[phone]; // clear OTP after successful verification
    return res.json({ success: true, message: "OTP verified" });
  }

  res.json({ success: false, message: "Invalid OTP" });
});

// Stage 3: save password
app.post("/savePassword", async (req, res) => {
  if (!needDB(res)) return;
  const { phone, newPassword } = req.body;
  if (!phone || !newPassword) {
    return res.status(400).json({ success: false, message: `Missing phone 
or newPassword` });
  }
  try {
    const [result] = await pool.query(`UPDATE users SET password=? WHERE 
phone=?`, [newPassword, phone]);
    if (result.affectedRows === 0) return res.json({ success: false, 
message: "User not found" });
    return res.json({ success: true, message: "Password saved" });
  } catch (e) {
    console.error("savePassword error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// Login (phone + password)
app.post("/login", async (req, res) => {
  if (!needDB(res)) return;
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ success: false, 
message: "Missing credentials" });

  try {
    const [rows] = await pool.query(`SELECT id, name FROM users WHERE 
phone=? AND password=?`, [phone, password]);
    if (!rows.length) return res.json({ success: false, message: `Invalid 
phone or password` });
    const user = rows[0];
    return res.json({ success: true, userId: user.id, name: user.name, 
message: "Login successful" });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// Stage 4: update profile
app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  if (!needDB(res)) return;
  const { userId, dob, degree, year } = req.body;
  if (!userId || !dob || !degree || !year) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  const picPath = req.file ? `/uploads/${req.file.filename}` : null;
  try {
    await pool.query(
      `UPDATE users SET dob=?, degree=?, year=?, profile_pic=? WHERE 
id=?`,
      [dob, degree, year, picPath, userId]
    );
    return res.json({ success: true, message: "Profile updated" });
  } catch (e) {
    console.error("updateProfile error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// ===================== TRAVEL PLANS =====================
app.post("/addTravelPlan", async (req, res) => {
  if (!needDB(res)) return;
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  try {
    const [existing] = await pool.query(`SELECT id FROM travel_plans WHERE 
user_id=?`, [userId]); // ✅ fixed
    if (existing.length) {
      await pool.query(
        `UPDATE travel_plans
         SET destination=?, time=CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d 
%H:%i:%s'), '+05:30', '+00:00')
         WHERE user_id=?`,
        [destination, time, userId]
      );
      return res.json({ success: true, message: "Travel plan updated" });
    } else {
      await pool.query(
        `INSERT INTO travel_plans (user_id, destination, time)
         VALUES (?, ?, CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d %H:%i:%s'), 
'+05:30', '+00:00'))`,
        [userId, destination, time]
      );
      return res.json({ success: true, message: "Travel plan added" });
    }
  } catch (e) {
    console.error("addTravelPlan error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// Get a user's plan
app.get("/getUserTravelPlan", async (req, res) => {
  if (!needDB(res)) return;
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ success: false, message: 
"Missing userId" });
  try {
    const [rows] = await pool.query(
      `SELECT destination,
              DATE_FORMAT(CONVERT_TZ(time, '+00:00', '+05:30'), '%Y-%m-%d 
%H:%i:%s') AS time
       FROM travel_plans WHERE user_id=?`,
      [userId]
    );
    return res.json(rows[0] || null);
  } catch (e) {
    console.error("getUserTravelPlan error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// List all going users
app.get("/going-users", async (req, res) => {
  if (!needDB(res)) return;
  try {
    const [rows] = await pool.query(
      `SELECT u.id AS userId, u.name AS username, u.college,
              t.destination,
              DATE_FORMAT(t.time, '%Y-%m-%dT%H:%i:%s.000Z') AS time
       FROM travel_plans t
       JOIN users u ON t.user_id = u.id
       ORDER BY t.time ASC`
    );
    return res.json({ success: true, users: rows });
  } catch (e) {
    console.error("going-users error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// Cleanup expired plans
setInterval(async () => {
  if (!pool) return;
  try {
    const [result] = await pool.query(`DELETE FROM travel_plans WHERE time 
<= UTC_TIMESTAMP()`);
    if (result.affectedRows > 0) {
      console.log(`🧹 Deleted ${result.affectedRows} expired travel 
plan(s)`);
    }
  } catch (e) {
    console.error("cleanup error:", e.message);
  }
}, 60 * 1000);

// ===================== CHAT =====================
app.post("/sendMessage", async (req, res) => {
  if (!needDB(res)) return;
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  try {
    const [result] = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, 
?, ?)`,
      [senderId, receiverId, message]
    );
    return res.json({ success: true, message: "Message sent", messageId: 
result.insertId });
  } catch (e) {
    console.error("sendMessage error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

app.get("/getMessages", async (req, res) => {
  if (!needDB(res)) return;
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) {
    return res.status(400).json({ success: false, message: `Missing 
senderId or receiverId` });
  }
  try {
    const [rows] = await pool.query(
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
    return res.json({ success: true, messages: rows });
  } catch (e) {
    console.error("getMessages error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// recent chat list
app.get("/getChatUsers", async (req, res) => {
  if (!needDB(res)) return;
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ success: false, message: 
"Missing userId" });

  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.name AS username,
              (SELECT m.message FROM messages m
               WHERE (m.sender_id=u.id AND m.receiver_id=?) OR 
(m.sender_id=? AND m.receiver_id=u.id)
               ORDER BY m.timestamp DESC LIMIT 1) AS lastMessage,
              (SELECT UNIX_TIMESTAMP(m.timestamp) * 1000 FROM messages m
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
    return res.json({ success: true, chats: rows });
  } catch (e) {
    console.error("getChatUsers error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

app.post("/markMessagesRead", async (req, res) => {
  if (!needDB(res)) return;
  const { userId, otherUserId } = req.body;
  if (!userId || !otherUserId) return res.status(400).json({ success: 
false, message: "Missing fields" });
  try {
    await pool.query(
      `UPDATE messages SET is_read=1 WHERE receiver_id=? AND sender_id=? 
AND is_read=0`,
      [userId, otherUserId]
    );
    return res.json({ success: true });
  } catch (e) {
    console.error("markMessagesRead error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

app.get("/unreadCount/:userId", async (req, res) => {
  if (!needDB(res)) return;
  const userId = Number(req.params.userId);
  if (!userId) return res.status(400).json({ success: false, message: 
"Missing userId" });
  try {
    const [rows] = await pool.query(
      `SELECT COUNT(*) AS count FROM messages WHERE receiver_id=? AND 
is_read=0`,
      [userId]
    );
    return res.json({ success: true, count: rows[0]?.count || 0 });
  } catch (e) {
    console.error("unreadCount error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

app.delete("/deleteChat/:userId/:receiverId", async (req, res) => {
  if (!needDB(res)) return;
  const { userId, receiverId } = req.params;
  try {
    await pool.query(
      `DELETE FROM messages
       WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND 
receiver_id=?)`,
      [userId, receiverId, receiverId, userId]
    );
    return res.json({ success: true, message: "Chat deleted successfully" 
});
  } catch (e) {
    console.error("deleteChat error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

app.delete("/deleteMessage/:messageId", async (req, res) => {
  if (!needDB(res)) return;
  const { messageId } = req.params;
  try {
    await pool.query("DELETE FROM messages WHERE id=?", [messageId]);
    return res.json({ success: true });
  } catch (e) {
    console.error("deleteMessage error:", e);
    return res.status(500).json({ success: false, message: `Database 
error` });
  }
});

// ===================== START =====================
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Server listening on 
${PORT}`));

