require("dotenv").config();

const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);
const otpStore = {};
const signupStore = {};

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const mysql = require("mysql2");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

cloudinary.config({
  secure: true,
});

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
app.use("/uploads", express.static(UPLOAD_DIR));

const pool = mysql.createPool({
  host: process.env.MYSQLHOST || "localhost",
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: process.env.MYSQLDATABASE || "yourdbname",
  port: process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306,
  connectionLimit: 20,
  waitForConnections: true,
  acquireTimeout: 60000,
  timeout: 60000
});

const db = pool.promise();

pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
    connection.release();
  }
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'reloaded_automate_profiles',
    allowed_formats: ['jpg', 'jpeg', 'png', 'heic'],
    transformation: [{ width: 500, height: 500, crop: 'limit', format: 'jpg' }]
  }
});
const upload = multer({ storage: storage });

// ---------- Helpers ----------
async function getUserByPhone(phone) {
  try {
    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE phone = ?`,
      [phone]
    );
    return rows && rows[0] ? rows[0] : null;
  } catch (error) {
    console.error("Error in getUserByPhone:", error);
    return null;
  }
}

// ---------- Routes ----------

// Health
app.get("/health", async (_req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: "OK", timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("❌ Health check failed:", err);
    res.status(500).json({ status: "ERROR", message: `Database connection failed: ${err.message}` });
  }
});

// Debug endpoint to check memory stores
app.get("/debug/stores", (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: "Not available in production" });
  }
  res.json({
    otpStore: Object.keys(otpStore).map(phone => ({
      phone,
      hasOtp: !!otpStore[phone].otp,
      expires: new Date(otpStore[phone].expires)
    })),
    signupStore: Object.keys(signupStore).map(phone => ({
      phone,
      data: signupStore[phone]
    }))
  });
});

// Debug endpoint to check users
app.get('/debug/users', async (req, res) => {
  try {
    const [rows] = await db.execute(`SELECT id, name FROM users LIMIT 10`);
    res.json({ users: rows });
  } catch (error) {
    res.json({ error: error.message });
  }
});

app.post("/signup", async (req, res) => {
  try {
    const { name, college, gender, phone } = req.body || {};
    console.log("📩 /signup RAW body:", req.body);
    console.log("📩 /signup PARSED:", { name, college, gender, phone });
    
    if (!name || !college || !gender || !phone) {
      console.log("❌ Missing fields:", { hasName: !!name, hasCollege: !!college, hasGender: !!gender, hasPhone: !!phone });
      return res.status(400).json({ success: false, message: `Missing required fields: name, college, gender, phone` });
    }
    
    if (name.trim().length < 4) {
      return res.status(400).json({ success: false, message: `Name must be at least 4 characters long` });
    }
    
    const [existingUser] = await db.query(`SELECT id FROM users WHERE phone = ?`, [phone]);
    if (existingUser.length > 0) {
      console.log("❌ User already exists for phone:", phone);
      return res.status(400).json({ success: false, message: `User with this phone number already exists` });
    }
    
    const signupData = { name: name.trim(), college: college.trim(), gender };
    signupStore[phone] = signupData;
    console.log("✅ Stored signup data for phone:", phone);
    console.log("✅ Signup data:", signupData);
    console.log("✅ Current signupStore keys:", Object.keys(signupStore));
    
    return res.json({ success: true, message: `Signup data received. Please verify OTP.` });
  } catch (err) {
    console.error("❌ /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/sendOtp", (req, res) => {
  const { phone } = req.body;
  console.log("📩 /sendOtp request:", { phone });
  
  if (!phone) {
    return res.status(400).json({ success: false, message: `Phone required` });
  }
  
  const otp = Math.floor(1000 + Math.random() * 9000);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  otpStore[phone] = { otp: otp.toString(), expires: expiresAt };
  console.log(`📩 Generated OTP for ${phone}: ${otp}, expires: ${new Date(expiresAt)}`);
  
  client.messages
    .create({
      body: `Your OTP is ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: `+91${phone}`
    })
    .then(() => {
      console.log(`✅ SMS sent successfully to ${phone}`);
      res.json({
        success: true,
        message: "OTP sent successfully",
        ...(process.env.NODE_ENV === 'development' && { otp })
      });
    })
    .catch(err => {
      console.error("❌ SMS Error:", err);
      res.status(500).json({ success: false, message: "Failed to send SMS" });
    });
});

app.post("/verifyOtp", async (req, res) => {
  try {
    const { phone, otp } = req.body;
    console.log("📩 /verifyOtp request:", { phone, otp: otp ? "****" : "missing" });
    
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: `Phone and OTP required` });
    }
    
    const entry = otpStore[phone];
    console.log("📊 Stored OTP entry:", entry ? { hasOtp: !!entry.otp, expires: new Date(entry.expires), now: new Date() } : "not found");
    
    if (!entry) {
      return res.status(400).json({ success: false, message: `No OTP found for this phone. Please request a new OTP.` });
    }
    
    if (Date.now() > entry.expires) {
      delete otpStore[phone];
      return res.status(400).json({ success: false, message: `OTP expired. Please request a new OTP.` });
    }
    
    if (entry.otp !== otp.toString()) {
      console.log(`❌ OTP mismatch: stored="${entry.otp}", received="${otp}"`);
      return res.status(400).json({ success: false, message: `Invalid OTP` });
    }
    
    const signupData = signupStore[phone];
    console.log("📊 Signup data for phone", phone, ":", signupData);
    console.log("📊 All signupStore keys:", Object.keys(signupStore));
    
    if (!signupData) {
      console.log("❌ No signup data found for phone:", phone);
      return res.status(400).json({ success: false, message: `Signup data missing. Please complete signup process first.` });
    }
    
    if (!signupData.name || !signupData.college || !signupData.gender) {
      console.log("❌ Invalid signup data:", signupData);
      return res.status(400).json({ success: false, message: `Invalid signup data. Please restart signup process.` });
    }
    
    delete otpStore[phone];
    console.log("🔄 Creating user with data:", signupData);
    
    const [result] = await db.query(
      `INSERT INTO users (name, college, password, phone, gender, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [signupData.name, signupData.college, "", phone, signupData.gender]
    );
    
    delete signupStore[phone];
    console.log(`✅ User created: ID=${result.insertId}, Name="${signupData.name}", Phone=${phone}`);
    
    return res.json({
      success: true,
      message: "OTP verified and user created successfully",
      userId: result.insertId,
      user: {
        id: result.insertId,
        name: signupData.name,
        college: signupData.college,
        phone: phone,
        gender: signupData.gender
      }
    });
  } catch (err) {
    console.error("❌ Error in /verifyOtp:", err);
    return res.status(500).json({ success: false, message: `Database error: ` + err.message });
  }
});

app.post("/savePassword", async (req, res) => {
  try {
    const { phone, newPassword } = req.body;
    console.log("📩 /savePassword request:", { phone: phone ? "***" + phone.slice(-4) : "missing", hasPassword: !!newPassword });
    
    if (!phone || !newPassword) {
      return res.status(400).json({ success: false, message: `Phone and password required` });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters long" });
    }
    
    const [updateResult] = await db.query(`UPDATE users SET password = ? WHERE phone = ?`, [newPassword, phone]);
    console.log("📊 Update result:", updateResult);
    
    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ success: false, message: `User not found` });
    }
    
    const [userRows] = await db.query(`SELECT id FROM users WHERE phone = ?`, [phone]);
    if (userRows.length === 0) {
      return res.status(404).json({ success: false, message: `User not found after update` });
    }
    
    const userId = userRows[0].id;
    console.log(`✅ Password updated for phone: ***${phone.slice(-4)} -> userId: ${userId}`);
    
    return res.json({ success: true, message: `Password updated successfully`, userId: userId });
  } catch (err) {
    console.error("❌ Error in /savePassword:", err);
    return res.status(500).json({ success: false, message: `Database error`, error: process.env.NODE_ENV === 'development' ? err.message : undefined });
  }
});

app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
  console.log("📩 /login body:", { phone, hasPassword: !!password });
  
  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Missing phone or password` });
  }
  
  try {
    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE phone = ? AND password = ?`,
      [phone, password]
    );
    
    if (!rows.length) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }
    
    const user = rows[0];
    console.log(`✅ Login successful for user: ${user.name} (ID: ${user.id})`);
    
    const userResponseObject = { ...user, year: user.year || 0 };
    res.json({
      success: true,
      message: "Login successful",
      user: userResponseObject,
    });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/addTravelPlan", async (req, res) => {
  try {
    const { userId, destination, time } = req.body;
    const actualTime = time;
    console.log("📩 /addTravelPlan request:", req.body);
    
    if (!userId || !destination || !actualTime) {
      console.log("❌ Missing fields");
      return res.status(400).json({ success: false, message: `Missing required fields: userId, destination, and time` });
    }
    
    const query = `INSERT INTO travel_plans (user_id, destination, time) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE destination = VALUES(destination), time = VALUES(time)`;
    const [result] = await db.query(query, [userId, destination, actualTime]);
    
    let message = "Plan submitted successfully";
    if (result.affectedRows > 1) {
      message = "Plan updated successfully";
    }
    
    console.log(`✅ Travel plan saved for userId=${userId} to ${destination}`);
    res.json({
      success: true,
      message: message,
      id: result.insertId
    });
  } catch (err) {
    console.error("❌ Error saving travel plan:", err);
    res.status(500).json({ success: false, message: "Database error", error: process.env.NODE_ENV === 'development' ? err.message : undefined });
  }
});

app.get("/getUserTravelPlan/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    console.log(`📩 /getUserTravelPlan/${userId} request`);
    
    if (!userId) {
      return res.status(400).json({ success: false, message: `User ID is required` });
    }
    
    const [results] = await db.query(
      `SELECT 
        tp.id, 
        tp.destination, 
        tp.time, 
        u.name, 
        u.college, 
        u.gender, 
        u.profile_pic 
       FROM travel_plans tp 
       JOIN users u ON tp.user_id = u.id 
       WHERE tp.user_id = ? AND tp.time > NOW() 
       ORDER BY tp.time ASC`,
      [userId]
    );
    
    console.log(`Travel Plan fetched for user ${userId}:`, results);
    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error(`❌ Error fetching travel plan for user ${userId}:`, err);
    res.status(500).json({ success: false, message: "Database error", users: [] });
  }
});

app.get("/getUserTravelPlan", async (req, res) => {
  try {
    await db.query('DELETE FROM travel_plans WHERE time < NOW()');
    const [results] = await db.query(
      `SELECT 
        tp.id, 
        tp.destination, 
        tp.time, 
        u.name, 
        u.college, 
        u.gender, 
        u.profile_pic 
      FROM travel_plans tp 
      JOIN users u ON tp.user_id = u.id 
      WHERE tp.time > NOW() 
      ORDER BY tp.time ASC`
    );
    
    console.log("All Travel Plans fetched:", results);
    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error("❌ Error fetching all travel plans:", err);
    res.json({ success: false, message: "Database error", users: [] });
  }
});

// It has been corrected to get the other user's name and profile picture.
app.get("/getChatUsers/:userId", async (req, res) => {
  const currentUserId = req.params.userId;
  try {
    const query = `
      SELECT 
        u.id, 
        u.name AS username, 
        u.profile_pic, 
        m.message AS lastMessage, 
        m.timestamp 
      FROM 
        (SELECT 
          LEAST(sender_id, receiver_id) as user1,
          GREATEST(sender_id, receiver_id) as user2, 
          MAX(id) as max_id 
        FROM messages 
        WHERE sender_id = ? OR receiver_id = ? 
        GROUP BY user1, user2) AS latest 
      JOIN messages m ON m.id = latest.max_id 
      JOIN users u ON u.id = IF(latest.user1 = ?, latest.user2, latest.user1) 
      ORDER BY m.timestamp DESC;
    `;
    const [chats] = await db.query(query, [currentUserId, currentUserId, currentUserId]);
    res.json({ success: true, chats: chats });
  } catch (err) {
    console.error("❌ Error fetching chat users:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get("/getUsersGoing", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
        tp.user_id, 
        tp.destination, 
        DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as time, 
        u.name, 
        u.college, 
        u.profile_pic, 
        u.gender 
      FROM travel_plans tp 
      JOIN users u ON tp.user_id = u.id 
      WHERE tp.time >= CURDATE() 
      ORDER BY tp.time ASC`
    );
    
    const usersGoing = rows.map(row => ({
      userId: row.user_id,
      name: row.name,
      destination: row.destination,
      time: row.time,
      college: row.college,
      // --- THIS IS THE FIX ---
      // The key is now "profile_pic" to match the Android model
      profile_pic: row.profile_pic,
      gender: row.gender
    }));
    
    res.json({ success: true, users: usersGoing });
  } catch (err) {
    console.error("❌ Error fetching users going:", err);
    res.status(500).json({ success: false, message: "Database error", users: [] });
  }
});

app.get("/getUserByPhone", async (req, res) => {
  const phone = req.query.phone;
  console.log("📩 /getUserByPhone query:", req.query);
  
  if (!phone) {
    return res.status(400).json({ success: false, message: "Missing phone" });
  }
  
  try {
    const [results] = await db.query(`SELECT * FROM users WHERE phone = ?`, [phone]);
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: `User not found` });
    }
    
    const user = results[0];
    res.json({ success: true, userId: user.id, user });
  } catch (err) {
    console.error("❌ /getUserByPhone error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    const { userId, dob, degree, year } = req.body || {};
    console.log("📩 /updateProfile fields:", req.body);
    console.log("📎 /updateProfile file received via Cloudinary:", !!req.file);

    if (!userId) {
      return res.status(400).json({ success: false, message: `Missing userId` });
    }

    const sets = [];
    const params = [];

    if (dob) { sets.push("dob = ?"); params.push(dob); }
    if (degree) { sets.push("degree = ?"); params.push(degree); }
    if (year) { sets.push("year = ?"); params.push(year); }

    if (req.file && req.file.path) {
      console.log("✅ Image uploaded to Cloudinary URL:", req.file.path);
      sets.push("profile_pic = ?");
      params.push(req.file.path);
    }

    if (sets.length === 0) {
      return res.status(400).json({ success: false, message: `Nothing to update` });
    }

    const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
    params.push(userId);

    const [result] = await db.query(sql, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: `User not found` });
    }

    const [rows] = await db.query(`SELECT id, name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE id = ?`, [userId]);
    console.log(`✅ Profile updated for userId: ${userId}`);

    res.json({
      success: true,
      message: "Profile updated",
      user: rows[0],
    });
  } catch (err) {
    console.error("❌ /updateProfile error:", err);
    res.status(500).json({ success: false, message: `Internal Server Error` });
  }
});

app.post('/sendMessage', async (req, res) => {
  try {
    const { senderId, receiverId, message } = req.body;
    if (!senderId || !receiverId || !message) {
      return res.status(400).json({ success: false, message: `senderId, receiverId, and message are required` });
    }
    
    const [userCheck] = await db.execute(`SELECT id FROM users WHERE id IN (?, ?)`, [senderId, receiverId]);
    if (userCheck.length !== 2) {
      return res.status(400).json({ success: false, message: `One or both users do not exist` });
    }
    
    const [result] = await db.execute(`INSERT INTO messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())`, [senderId, receiverId, message]);
    res.json({ success: true, message: 'Message sent successfully', messageId: result.insertId });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ success: false, message: `Failed to send message` });
  }
});

app.get('/getMessages', async (req, res) => {
  try {
    const { senderId, receiverId } = req.query;

    if (!senderId || !receiverId) {
      return res.status(400).json({ success: false, message: 'senderId and receiverId are required' });
    }

const query = `
  SELECT id, sender_id as senderId, receiver_id as receiverId,
         message, timestamp,
         CASE 
           WHEN receiver_id = ? THEN COALESCE(is_read, 0)
           ELSE 1 
         END as isRead
  FROM messages
  WHERE
    ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
  AND
    NOT (sender_id = ? AND deleted_by_sender = TRUE)
  AND
    NOT (receiver_id = ? AND deleted_by_receiver = TRUE)
  ORDER BY timestamp ASC
`;

const [rows] = await db.execute(query, [receiverId, senderId, receiverId, receiverId, senderId, senderId, receiverId]);
    res.json({
      success: true,
      messages: rows || []
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ success: false, message: `Failed to fetch messages` });
  }
});

// in index.js
app.get('/getChatUsers', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: `userId is required` });
    }

    const query = `
      SELECT DISTINCT 
        u.id, 
        u.name as username, 
        u.college, 
        u.profile_pic, 
        latest.last_message as lastMessage, 
        latest.last_timestamp as timestamp, 
        0 as unreadCount 
      FROM users u 
      INNER JOIN (
        SELECT 
          CASE 
            WHEN sender_id = ? THEN receiver_id 
            ELSE sender_id 
          END as other_user_id, 
          message as last_message, 
          created_at as last_timestamp, 
          ROW_NUMBER() OVER (
            PARTITION BY CASE 
              WHEN sender_id = ? THEN receiver_id 
              ELSE sender_id 
            END 
            ORDER BY created_at DESC 
          ) as rn 
        FROM messages 
        WHERE 
          (sender_id = ? OR receiver_id = ?) 
          AND NOT (sender_id = ? AND deleted_by_sender = TRUE) 
          AND NOT (receiver_id = ? AND deleted_by_receiver = TRUE) 
      ) latest ON u.id = latest.other_user_id AND latest.rn = 1 
      ORDER BY latest.last_timestamp DESC
    `;

    const [rows] = await db.execute(query, [userId, userId, userId, userId, userId, userId]);
    res.json({ success: true, chats: rows || [] });
  } catch (error) {
    console.error('Error fetching chat users:', error);
    res.status(500).json({ success: false, message: `Failed to fetch chat users` });
  }
});

app.post("/deleteMessageForMe", async (req, res) => {
  try {
    const { messageId, userId } = req.body;

    if (!messageId || !userId) {
      return res.status(400).json({ success: false, message: `messageId and userId are required` });
    }

    const [messages] = await db.query(`SELECT sender_id, receiver_id FROM messages WHERE id = ?`, [messageId]);
    if (messages.length === 0) {
      return res.status(404).json({ success: false, message: `Message not found` });
    }
    const message = messages[0];

    let updateQuery;
    if (userId == message.sender_id) {
      updateQuery = `UPDATE messages SET deleted_by_sender = TRUE WHERE id = ?`;
    } else if (userId == message.receiver_id) {
      updateQuery = `UPDATE messages SET deleted_by_receiver = TRUE WHERE id = ?`;
    } else {
      return res.status(403).json({ success: false, message: `You can only delete messages from your own chats.` });
    }

    await db.query(updateQuery, [messageId]);

    res.json({ success: true, message: "Message hidden successfully" });

  } catch (error) {
    console.error('Error in /deleteMessageForMe:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Mark messages as read
app.post('/markMessagesRead', async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: `userId and otherUserId are required` });
    }
    
    const query = `UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0`;
    const [result] = await db.execute(query, [otherUserId, userId]);
    
    console.log(`Marked ${result.affectedRows} messages as read for user ${userId} from user ${otherUserId}`);
    res.json({ success: true, message: 'Messages marked as read', markedCount: result.affectedRows });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ success: false, message: `Failed to mark messages as read` });
  }
});

app.get('/getUnreadCount', async (req, res) => {
  try {
    const { userId, otherUserId } = req.query;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: `userId and otherUserId are required` });
    }
    
    const query = `SELECT COUNT(*) as unreadCount FROM messages WHERE sender_id = ? AND receiver_id = ? AND is_read = 0`;
    const [rows] = await db.execute(query, [otherUserId, userId]);
    const unreadCount = rows[0].unreadCount;
    
    console.log(`Unread count for user ${userId} from user ${otherUserId}: ${unreadCount}`);
    res.json({ success: true, unreadCount: unreadCount });
  } catch (error) {
    console.error('Error getting unread count:', error);
    res.status(500).json({ success: false, message: `Failed to get unread count` });
  }
});

app.get('/getTotalUnreadCount/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) {
      return res.status(400).json({ success: false, message: `userId is required` });
    }
    
    const query = `SELECT COUNT(*) as totalUnreadCount FROM messages WHERE receiver_id = ? AND is_read = 0`;
    const [rows] = await db.execute(query, [userId]);
    const totalUnreadCount = rows[0].totalUnreadCount;
    
    console.log(`Total unread count for user ${userId}: ${totalUnreadCount}`);
    res.json({ success: true, totalUnreadCount: totalUnreadCount });
  } catch (error) {
    console.error('Error getting total unread count:', error);
    res.status(500).json({ success: false, message: `Failed to get total unread count` });
  }
});

app.post("/hideChat", async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;

    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: `userId and otherUserId are required` });
    }

    const hideSentQuery = `
      UPDATE messages 
      SET deleted_by_sender = TRUE 
      WHERE sender_id = ? AND receiver_id = ?
    `;
    await db.execute(hideSentQuery, [userId, otherUserId]);

    const hideReceivedQuery = `
      UPDATE messages 
      SET deleted_by_receiver = TRUE 
      WHERE receiver_id = ? AND sender_id = ?
    `;
    await db.execute(hideReceivedQuery, [userId, otherUserId]);

    res.json({ success: true, message: 'Chat hidden successfully' });

  } catch (error) {
    console.error('Error in /hideChat:', error);
    res.status(500).json({ success: false, message: 'Failed to hide chat' });
  }
});

app.delete('/deleteMessage/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ success: false, message: `userId is required in the request body` });
    }
    
    const query = 'DELETE FROM messages WHERE id = ? AND sender_id = ?';
    const [result] = await db.execute(query, [messageId, userId]);
    
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Message deleted successfully' });
    } else {
      res.status(403).json({ success: false, message: `Forbidden: You can only delete your own messages` });
    }
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ success: false, message: `Failed to delete message` });
  }
});

app.get("/travel-plans/destinations", async (req, res) => {
    try {
        await db.query('DELETE FROM travel_plans WHERE time < NOW()');

        const query = `
            SELECT
                ANY_VALUE(destination) as destination,
                COUNT(user_id) as userCount
            FROM travel_plans
            WHERE time > NOW()
            GROUP BY LOWER(destination)
            ORDER BY LOWER(destination) ASC;
        `;
        const [destinations] = await db.query(query);

        res.json({ success: true, destinations: destinations || [] });

    } catch (err) {
        console.error("❌ Error fetching travel plan destinations:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});


app.get("/travel-plans/by-destination", async (req, res) => {
    try {
        const { destination } = req.query;

        if (!destination) {
            return res.status(400).json({ success: false, message: "Destination query parameter is required." });
        }

        const query = `
            SELECT
                u.id,
                u.name,
                u.college,
                u.gender,
                u.profile_pic,
                tp.time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            -- Compare the lowercase versions of both the column and the input
            WHERE LOWER(tp.destination) = LOWER(?) AND tp.time > NOW()
            ORDER BY tp.time ASC;
        `;
        const [users] = await db.query(query, [destination]);

        res.json({ success: true, users: users || [] });

    } catch (err)
    {
        console.error("❌ Error fetching users by destination:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

// ---------- Start Server ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
