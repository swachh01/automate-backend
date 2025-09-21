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
const router = express.Router();

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

// Function to automatically update expired trips
async function updateExpiredTrips() {
  try {
    const updateQuery = `
      UPDATE travel_plans 
      SET status = 'Completed' 
      WHERE status = 'Active' AND time < NOW()
    `;
    const [result] = await db.query(updateQuery);
    if (result.affectedRows > 0) {
      console.log(`✅ Auto-updated ${result.affectedRows} expired trips to Completed status`);
    }
  } catch (error) {
    console.error('❌ Error auto-updating expired trips:', error);
  }
}

// Run every 30 minutes to update expired trips
setInterval(updateExpiredTrips, 30 * 60 * 1000);

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

app.get('/debug/routes', (req, res) => {
  const routes = [];
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      routes.push(middleware.route.path);
    } else if (middleware.name === 'router') {
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          routes.push(handler.route.path);
        }
      });
    }
  });
  res.json({ routes });
});

app.post("/signup", async (req, res) => {
  try {
    const { name, college, gender, phone } = req.body || {};
    if (!name || !college || !gender || !phone) {
      return res.status(400).json({ success: false, message: `Missing required fields: name, college, gender, phone` });
    }
    if (name.trim().length < 4) {
      return res.status(400).json({ success: false, message: `Name must be at least 4 characters long` });
    }
    const [existingUser] = await db.query(`SELECT id FROM users WHERE phone = ?`, [phone]);
    if (existingUser.length > 0) {
      return res.status(400).json({ success: false, message: `User with this phone number already exists` });
    }
    const signupData = { name: name.trim(), college: college.trim(), gender };
    signupStore[phone] = signupData;
    return res.json({ success: true, message: `Signup data received. Please verify OTP.` });
  } catch (err) {
    console.error("❌ /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/sendOtp", (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ success: false, message: `Phone required` });
  }
  const otp = Math.floor(1000 + Math.random() * 9000);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  otpStore[phone] = { otp: otp.toString(), expires: expiresAt };
  client.messages
    .create({
      body: `Your OTP is ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: `+91${phone}`
    })
    .then(() => {
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
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: `Phone and OTP required` });
    }
    const entry = otpStore[phone];
    if (!entry) {
      return res.status(400).json({ success: false, message: `No OTP found for this phone. Please request a new OTP.` });
    }
    if (Date.now() > entry.expires) {
      delete otpStore[phone];
      return res.status(400).json({ success: false, message: `OTP expired. Please request a new OTP.` });
    }
    if (entry.otp !== otp.toString()) {
      return res.status(400).json({ success: false, message: `Invalid OTP` });
    }
    const signupData = signupStore[phone];
    if (!signupData) {
      return res.status(400).json({ success: false, message: `Signup data missing. Please complete signup process first.` });
    }
    delete otpStore[phone];
    const [result] = await db.query(
      `INSERT INTO users (name, college, password, phone, gender, created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [signupData.name, signupData.college, "", phone, signupData.gender]
    );
    delete signupStore[phone];
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
    if (!phone || !newPassword) {
      return res.status(400).json({ success: false, message: `Phone and password required` });
    }
    if (newPassword.length < 7 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword) || !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(newPassword)) {
      return res.status(400).json({ success: false, message: "Password must be at least 7 characters and include letters, numbers, and symbols." });
    }
    const [updateResult] = await db.query(`UPDATE users SET password = ? WHERE phone = ?`, [newPassword, phone]);
    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ success: false, message: `User not found` });
    }
    const [userRows] = await db.query(`SELECT id FROM users WHERE phone = ?`, [phone]);
    const userId = userRows[0].id;
    return res.json({ success: true, message: `Password updated successfully`, userId: userId });
  } catch (err) {
    console.error("❌ Error in /savePassword:", err);
    return res.status(500).json({ success: false, message: `Database error` });
  }
});

app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
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
    res.json({ success: true, message: "Login successful", user: { ...user, year: user.year || 0 } });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    const { userId, dob, degree, year } = req.body || {};
    if (!userId) {
      return res.status(400).json({ success: false, message: `Missing userId` });
    }
    const sets = [];
    const params = [];
    if (dob) { sets.push("dob = ?"); params.push(dob); }
    if (degree) { sets.push("degree = ?"); params.push(degree); }
    if (year) { sets.push("year = ?"); params.push(year); }
    if (req.file && req.file.path) {
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
    res.json({ success: true, message: "Profile updated", user: rows[0] });
  } catch (err) {
    console.error("❌ /updateProfile error:", err);
    res.status(500).json({ success: false, message: `Internal Server Error` });
  }
});

// --- TRAVEL PLAN ROUTES ---
app.post("/addTravelPlan", async (req, res) => {
  try {
    const { userId, fromPlace, toPlace, time } = req.body;
    if (!userId || !fromPlace || !toPlace || !time) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: userId, fromPlace, toPlace, and time"
      });
    }

    // Check if user already has an active trip
    const [existingTrip] = await db.query(
      `SELECT id FROM travel_plans WHERE user_id = ? AND status = 'Active'`,
      [userId]
    );

    if (existingTrip.length > 0) {
      // Update existing active trip
      const query = `UPDATE travel_plans 
                     SET from_place = ?, to_place = ?, time = ?, created_at = NOW()
                     WHERE user_id = ? AND status = 'Active'`;
      await db.query(query, [fromPlace, toPlace, time, userId]);
      
      res.json({
        success: true,
        message: "Travel plan updated successfully",
        id: existingTrip[0].id
      });
    } else {
      // Create new trip
      const query = `INSERT INTO travel_plans (user_id, from_place, to_place, time, status, fare, created_at)
                     VALUES (?, ?, ?, ?, 'Active', 0.00, NOW())`;
      const [result] = await db.query(query, [userId, fromPlace, toPlace, time]);
      
      res.json({
        success: true,
        message: "Travel plan created successfully",
        id: result.insertId
      });
    }
  } catch (err) {
    console.error("❌ Error saving travel plan:", err);
    res.status(500).json({
      success: false,
      message: "Database error"
    });
  }
});

app.get("/getUserTravelPlan/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required"
      });
    }

    const [results] = await db.query(
      `SELECT
        tp.id,
        tp.from_place as fromPlace,
        tp.to_place as toPlace,
        tp.time,
        tp.status,
        u.name,
        u.college,
        u.gender,
        u.profile_pic
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id
      WHERE tp.user_id = ? AND tp.status = 'Active'
      ORDER BY tp.time ASC`,
      [userId]
    );

    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error(`❌ Error fetching travel plan for user ${userId}:`, err);
    res.status(500).json({
      success: false,
      message: "Database error",
      users: []
    });
  }
});

// --- CHAT ROUTES ---
app.get('/getMessages', async (req, res) => {
  try {
    const { sender_id, receiver_id } = req.query;
    if (!sender_id || !receiver_id) {
      return res.status(400).json({ success: false, message: 'sender_id and receiver_id are required' });
    }
    const sql = `
      SELECT * FROM messages
      WHERE (sender_id = ? AND receiver_id = ?)
         OR (sender_id = ? AND receiver_id = ?)
      ORDER BY timestamp ASC
    `;
    const [messages] = await db.query(sql, [sender_id, receiver_id, receiver_id, sender_id]);
    const hiddenSql = `SELECT message_id FROM hidden_messages WHERE user_id = ?`;
    const [hiddenMessages] = await db.query(hiddenSql, [sender_id]);
    const hiddenIds = hiddenMessages.map(h => h.message_id);
    const visibleMessages = messages.filter(msg => !hiddenIds.includes(msg.id));
    res.json({ success: true, messages: visibleMessages });
  } catch (error) {
    console.error('❌ Error fetching messages:', error);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/sendMessage', async (req, res) => {
  try {
    const { sender_id, receiver_id, message } = req.body;
    const blockCheckQuery = `
      SELECT * FROM blocked_users
      WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
    `;
    const [blockedRows] = await db.query(blockCheckQuery, [sender_id, receiver_id, receiver_id, sender_id]);
    if (blockedRows.length > 0) {
      return res.status(403).json({ success: false, message: 'This user cannot be messaged.' });
    }
    if (!sender_id || !receiver_id || !message) {
      return res.status(400).json({ success: false, message: 'sender_id, receiver_id, and message are required' });
    }
    const query = `
      INSERT INTO messages (sender_id, receiver_id, message, timestamp)
      VALUES (?, ?, ?, NOW())
    `;
    const [result] = await db.query(query, [sender_id, receiver_id, message]);
    res.json({ success: true, message: 'Message sent successfully', messageId: result.insertId });
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: `Failed to send message` });
  }
});

app.get('/getChatUsers', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: `userId is required` });
    }
    const query = `
      SELECT DISTINCT
        u.id, u.name as username, u.college, u.profile_pic,
        latest.last_message as lastMessage, latest.last_timestamp as timestamp, 0 as unreadCount
      FROM users u
      INNER JOIN (
        SELECT
          CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as other_user_id,
          message as last_message, timestamp as last_timestamp,
          ROW_NUMBER() OVER (
            PARTITION BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
            ORDER BY timestamp DESC
          ) as rn
        FROM messages
        WHERE (sender_id = ? OR receiver_id = ?)
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
    if (userId != message.sender_id && userId != message.receiver_id) {
      return res.status(403).json({ success: false, message: `You can only delete messages from your own chats.` });
    }
    await db.query(`INSERT IGNORE INTO hidden_messages (message_id, user_id, hidden_at) VALUES (?, ?, NOW())`, [messageId, userId]);
    res.json({ success: true, message: "Message hidden successfully" });
  } catch (error) {
    console.error('Error in /deleteMessageForMe:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/block', async (req, res) => {
  try {
    const { blocker_id, blocked_id } = req.body;
    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocker and blocked IDs are required.' });
    }
    await db.query('INSERT INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)', [blocker_id, blocked_id]);
    res.json({ success: true, message: 'User blocked successfully.' });
  } catch (err) {
    console.error("❌ Error blocking user:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/unblock', async (req, res) => {
  try {
    const { blocker_id, blocked_id } = req.body;
    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocker and blocked IDs are required.' });
    }
    await db.query('DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?', [blocker_id, blocked_id]);
    res.json({ success: true, message: 'User unblocked successfully.' });
  } catch (err) {
    console.error("❌ Error unblocking user:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.get('/checkBlockStatus', async (req, res) => {
  try {
    const { user1_id, user2_id } = req.query;
    if (!user1_id || !user2_id) {
      return res.status(400).json({ success: false, message: 'Both user IDs are required.' });
    }
    const query = `
      SELECT * FROM blocked_users
      WHERE (blocker_id = ? AND blocked_id = ?)
         OR (blocker_id = ? AND blocked_id = ?)
    `;
    const [rows] = await db.query(query, [user1_id, user2_id, user2_id, user1_id]);
    if (rows.length > 0) {
      res.json({ success: true, isBlocked: true, blockerId: rows[0].blocker_id });
    } else {
      res.json({ success: true, isBlocked: false });
    }
  } catch (err) {
    console.error("❌ Error checking block status:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// --- UPDATED TRAVEL & TRIP HISTORY WORKFLOW ---

// For "See Who's Going": Only shows trips with 'Active' status and future time
app.get("/getUsersGoing", async (req, res) => {
  try {
    // First update expired trips
    await updateExpiredTrips();
    
    const query = `
      SELECT
        tp.user_id, tp.from_place as fromPlace, tp.to_place as toPlace,
        DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as time,
        u.name, u.college, u.profile_pic, u.gender
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id
      WHERE tp.status = 'Active' AND tp.time > NOW()
      ORDER BY tp.time ASC`;
      
    const [rows] = await db.query(query);
    const usersGoing = rows.map(row => ({
      userId: row.user_id, id: row.user_id, name: row.name,
      fromPlace: row.fromPlace, toPlace: row.toPlace, time: row.time,
      college: row.college, profile_pic: row.profile_pic, gender: row.gender
    }));
    res.json({ success: true, users: usersGoing });
  } catch (err) {
    console.error("❌ Error fetching users going:", err);
    res.status(500).json({ success: false, message: "Database error", users: [] });
  }
});

app.get("/travel-plans/destinations", async (req, res) => {
  try {
    // Only shows destinations that have active travelers
    const query = `
      SELECT ANY_VALUE(to_place) as destination, COUNT(user_id) as userCount
      FROM travel_plans
      WHERE status = 'Active' AND time > NOW()
      GROUP BY LOWER(to_place)
      ORDER BY LOWER(to_place) ASC;
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
      return res.status(400).json({
        success: false,
        message: "Destination query parameter is required."
      });
    }

    const query = `
      SELECT
        u.id, u.name, u.college, u.gender, u.profile_pic,
        tp.from_place as fromPlace, tp.to_place as toPlace, tp.time
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id
      WHERE LOWER(tp.to_place) = LOWER(?) AND tp.status = 'Active' AND tp.time > NOW()
      ORDER BY tp.time ASC;
    `;
    const [users] = await db.query(query, [destination]);
    res.json({ success: true, users: users || [] });
  } catch (err) {
    console.error("❌ Error fetching users by destination:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

// Main Trip History endpoint - Shows ALL trips for a user
app.get('/tripHistory/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // First update expired trips to Completed status
    await updateExpiredTrips();

    // Fetch ALL trips for the user (Active, Completed, Cancelled)
    const offset = (page - 1) * limit;
    const historyQuery = `
      SELECT
        tp.id, tp.from_place, tp.to_place,
        DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as travel_time,
        tp.fare, tp.status, tp.added_fare,
        CONVERT_TZ(tp.created_at, '+00:00', '+05:30') as created_at
      FROM travel_plans tp
      WHERE tp.user_id = ?
      ORDER BY tp.created_at DESC
      LIMIT ? OFFSET ?
    `;
    const [trips] = await db.query(historyQuery, [parseInt(userId), parseInt(limit), parseInt(offset)]);
    
    const countQuery = 'SELECT COUNT(*) as total FROM travel_plans WHERE user_id = ?';
    const [countResult] = await db.query(countQuery, [parseInt(userId)]);
    const totalTrips = countResult[0].total;

    res.json({
      success: true,
      data: {
        trips: trips,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalTrips / limit),
          totalTrips: totalTrips,
          hasMore: offset + trips.length < totalTrips
        }
      }
    });
  } catch (error) {
    console.error('Error fetching trip history:', error);
    res.status(500).json({ success: false, message: 'Error fetching trip history' });
  }
});

// Cancel a trip (changes status to 'Cancelled')
app.put('/trip/cancel/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { userId } = req.body;
    
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }
    
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    // Check if trip belongs to user
    const [tripCheck] = await db.query('SELECT user_id FROM travel_plans WHERE id = ?', [parseInt(tripId)]);
    if (tripCheck.length === 0) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }
    
    if (tripCheck[0].user_id !== parseInt(userId)) {
      return res.status(403).json({ success: false, message: 'Unauthorized to cancel this trip' });
    }

    const [result] = await db.query('UPDATE travel_plans SET status = ? WHERE id = ?', ['Cancelled', parseInt(tripId)]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Trip cancelled successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error('Error cancelling trip:', error);
    res.status(500).json({ success: false, message: 'Error cancelling trip' });
  }
});

// Add fare to a completed trip
app.put('/trip/addFare/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { userId, fare } = req.body;
    
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }
    
    if (!userId || fare === undefined || isNaN(fare)) {
      return res.status(400).json({ success: false, message: 'User ID and valid fare amount are required' });
    }

    // Check if trip belongs to user and is completed
    const [tripCheck] = await db.query(
      'SELECT user_id, status FROM travel_plans WHERE id = ?', 
      [parseInt(tripId)]
    );
    
    if (tripCheck.length === 0) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }
    
    if (tripCheck[0].user_id !== parseInt(userId)) {
      return res.status(403).json({ success: false, message: 'Unauthorized to update this trip' });
    }
    
    if (tripCheck[0].status !== 'Completed') {
      return res.status(400).json({ success: false, message: 'Can only add fare to completed trips' });
    }

    const [result] = await db.query(
      'UPDATE travel_plans SET added_fare = ? WHERE id = ?', 
      [parseFloat(fare), parseInt(tripId)]
    );
    
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Fare added successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error('Error adding fare:', error);
    res.status(500).json({ success: false, message: 'Error adding fare' });
  }
});

// Get completed trips that need fare input
app.get('/completedTrips/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // First update expired trips
    await updateExpiredTrips();

    // Get completed trips without added fare
    const query = `
      SELECT 
        tp.id, tp.from_place, tp.to_place, 
        DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as travel_time,
        tp.status, tp.added_fare
      FROM travel_plans tp
      WHERE tp.user_id = ? AND tp.status = 'Completed' AND tp.added_fare IS NULL
      ORDER BY tp.time DESC
    `;

    const [completedTrips] = await db.query(query, [parseInt(userId)]);
    res.json({ success: true, data: completedTrips });
  } catch (error) {
    console.error('Error fetching completed trips:', error);
    res.status(500).json({ success: false, message: 'Error fetching completed trips' });
  }
});

// Delete a trip permanently from history
app.delete('/tripHistory/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { userId } = req.body;
    
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }
    
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required' });
    }

    // Check if trip belongs to user
    const [tripCheck] = await db.query('SELECT user_id FROM travel_plans WHERE id = ?', [parseInt(tripId)]);
    if (tripCheck.length === 0) {
      return res.status(404).json({ success: false, message: 'Trip not found' });
    }
    
    if (tripCheck[0].user_id !== parseInt(userId)) {
      return res.status(403).json({ success: false, message: 'Unauthorized to delete this trip' });
    }

    const [result] = await db.query('DELETE FROM travel_plans WHERE id = ?', [parseInt(tripId)]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Trip deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error('Error deleting trip:', error);
    res.status(500).json({ success: false, message: 'Error deleting trip' });
  }
});

// Trip Statistics Route
app.get('/tripStats/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const statsQuery = `
      SELECT
        COUNT(*) as total_trips,
        COUNT(CASE WHEN status = 'Completed' THEN 1 END) as completed_trips,
        COUNT(CASE WHEN status = 'Cancelled' THEN 1 END) as cancelled_trips,
        COUNT(CASE WHEN status = 'Active' THEN 1 END) as active_trips,
        COUNT(DISTINCT to_place) as unique_destinations,
        COALESCE(SUM(added_fare), 0) as total_fare_spent,
        MIN(created_at) as first_trip_date,
        MAX(created_at) as last_trip_date
      FROM travel_plans
      WHERE user_id = ?
    `;
    const [statsResult] = await db.query(statsQuery, [parseInt(userId)]);
    
    const destinationsQuery = `
      SELECT to_place as destination, COUNT(*) as visit_count
      FROM travel_plans
      WHERE user_id = ?
      GROUP BY to_place
      ORDER BY visit_count DESC
      LIMIT 5
    `;
    const [topDestinations] = await db.query(destinationsQuery, [parseInt(userId)]);

    res.json({
      success: true,
      data: { 
        statistics: statsResult[0], 
        topDestinations: topDestinations 
      }
    });
  } catch (error) {
    console.error('Error fetching trip statistics:', error);
    res.status(500).json({ success: false, message: 'Error fetching trip statistics' });
  }
});

// Auto-update completed trips endpoint (can be called manually or via cron)
app.post('/autoUpdateCompletedTrips', async (req, res) => {
  try {
    const updateQuery = `
      UPDATE travel_plans
      SET status = 'Completed'
      WHERE status = 'Active' AND time < NOW()
    `;
    const [result] = await db.query(updateQuery);
    res.json({ 
      success: true, 
      message: `Updated ${result.affectedRows} expired trips to completed status` 
    });
  } catch (error) {
    console.error('Error auto-updating trips:', error);
    res.status(500).json({ success: false, message: 'Error auto-updating trips' });
  }
});

// Additional missing routes from original code
app.get("/getUserByPhone", async (req, res) => {
  const phone = req.query.phone;
  if (!phone) {
    return res.status(400).json({ success: false, message: "Missing phone" });
  }
  try {
    const [results] = await db.query(`SELECT * FROM users WHERE phone = ?`, [phone]);
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    const user = results[0];
    res.json({ success: true, userId: user.id, user });
  } catch (err) {
    console.error("❌ /getUserByPhone error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Mark messages as read
app.post('/markMessagesRead', async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }
    const query = `UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0`;
    const [result] = await db.execute(query, [otherUserId, userId]);
    res.json({ success: true, message: 'Messages marked as read', markedCount: result.affectedRows });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ success: false, message: 'Failed to mark messages as read' });
  }
});

// Get unread count
app.get('/getUnreadCount', async (req, res) => {
  try {
    const { userId, otherUserId } = req.query;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }
    const query = `SELECT COUNT(*) as unreadCount FROM messages WHERE sender_id = ? AND receiver_id = ? AND is_read = 0`;
    const [rows] = await db.execute(query, [otherUserId, userId]);
    res.json({ success: true, unreadCount: rows[0].unreadCount });
  } catch (error) {
    console.error('Error getting unread count:', error);
    res.status(500).json({ success: false, message: 'Failed to get unread count' });
  }
});

// Get total unread count
app.get('/getTotalUnreadCount/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'userId is required' });
    }
    const query = `SELECT COUNT(*) as totalUnreadCount FROM messages WHERE receiver_id = ? AND is_read = 0`;
    const [rows] = await db.execute(query, [userId]);
    res.json({ success: true, totalUnreadCount: rows[0].totalUnreadCount });
  } catch (error) {
    console.error('Error getting total unread count:', error);
    res.status(500).json({ success: false, message: 'Failed to get total unread count' });
  }
});

// Hide chat
app.post("/hideChat", async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }

    const hideSentQuery = `UPDATE messages SET deleted_by_sender = TRUE WHERE sender_id = ? AND receiver_id = ?`;
    await db.execute(hideSentQuery, [userId, otherUserId]);

    const hideReceivedQuery = `UPDATE messages SET deleted_by_receiver = TRUE WHERE receiver_id = ? AND sender_id = ?`;
    await db.execute(hideReceivedQuery, [userId, otherUserId]);

    res.json({ success: true, message: 'Chat hidden successfully' });
  } catch (error) {
    console.error('Error in /hideChat:', error);
    res.status(500).json({ success: false, message: 'Failed to hide chat' });
  }
});

// Delete message
app.delete('/deleteMessage/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { userId } = req.body;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'userId is required in the request body' });
    }

    const query = 'DELETE FROM messages WHERE id = ? AND sender_id = ?';
    const [result] = await db.execute(query, [messageId, userId]);

    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Message deleted successfully' });
    } else {
      res.status(403).json({ success: false, message: 'Forbidden: You can only delete your own messages' });
    }
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ success: false, message: 'Failed to delete message' });
  }
});

// ---------- Start Server ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
