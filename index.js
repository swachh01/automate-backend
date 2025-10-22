require("dotenv").config();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcrypt'); // ADD THIS LINE - bcrypt was missing

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);
const otpStore = {};
const signupStore = {};

const express = require("express");
const cors = require("cors");
const path = require("path");
const { encrypt, decrypt } = require('./cryptoHelper');
const fs = require("fs");
const multer = require("multer");
const mysql = require("mysql2");

const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});
const router = express.Router();

const saltRounds = 12;

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

cloudinary.config({
  secure: true,
});

const onlineUsers = new Map();

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

async function updateUserPresence(userId, isOnline) {
  try {
    const query = `
      INSERT INTO user_presence (user_id, is_online, last_seen, updated_at)
      VALUES (?, ?, NOW(), NOW())
      ON DUPLICATE KEY UPDATE
        is_online = VALUES(is_online),
        last_seen = VALUES(last_seen),
        updated_at = VALUES(updated_at)
    `;
    await db.query(query, [userId, isOnline]);
  } catch (error) {
    console.error('❌ Error updating user presence:', error);
  }
}

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  // Handle user going online
  socket.on('user_online', async (userId) => {
    try {
      onlineUsers.set(userId.toString(), {
        socketId: socket.id,
        lastSeen: new Date(),
        isOnline: true
      });

      // Update database
      await updateUserPresence(userId, true);

      // Broadcast to all other clients that this user is online
      socket.broadcast.emit('user_status_changed', {
        userId: userId.toString(),
        isOnline: true,
        lastSeen: new Date()
      });

      console.log(`✅ User ${userId} is now online`);
    } catch (error) {
      console.error('❌ Error handling user_online:', error);
    }
  });

  socket.on('user_offline', async (userId) => {
    try {
      onlineUsers.delete(userId.toString());
      await updateUserPresence(userId, false);
      
      socket.broadcast.emit('user_status_changed', {
        userId: userId.toString(),
        isOnline: false,
        lastSeen: new Date()
      });

      console.log(`📴 User ${userId} manually went offline`);
    } catch (error) {
      console.error('❌ Error handling user_offline:', error);
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    try {
      // Find user by socket ID
      let disconnectedUserId = null;
      for (let [userId, userData] of onlineUsers.entries()) {
        if (userData.socketId === socket.id) {
          disconnectedUserId = userId;
          break;
        }
      }

      if (disconnectedUserId) {
        onlineUsers.delete(disconnectedUserId);
        
        // Update database
        await updateUserPresence(disconnectedUserId, false);

        // Broadcast to all clients that this user is offline
        socket.broadcast.emit('user_status_changed', {
          userId: disconnectedUserId,
          isOnline: false,
          lastSeen: new Date()
        });

        console.log(`📴 User ${disconnectedUserId} disconnected`);
      }
    } catch (error) {
      console.error('❌ Error handling disconnect:', error);
    }
  });

  // Handle typing indicators
  socket.on('typing_start', (data) => {
    socket.broadcast.emit('user_typing', {
      userId: data.userId,
      chatWithUserId: data.chatWithUserId,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    socket.broadcast.emit('user_typing', {
      userId: data.userId,
      chatWithUserId: data.chatWithUserId,
      isTyping: false
    });
  });
});

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
      return res.status(400).json({ success: false, message: `Missing required fields.` });
    }
    if (name.trim().length < 4) {
      return res.status(400).json({ success: false, message: `Name must be at least 4 characters long` });
    }

    // ✨ MODIFIED LOGIC: Check for a user with a 'completed' status
    const [existingUser] = await db.query(`SELECT id, signup_status FROM users WHERE phone = ?`, [phone]);

    // Only block the signup if the user exists AND their status is 'completed'
    if (existingUser.length > 0 && existingUser[0].signup_status === 'completed') {
      return res.status(400).json({ success: false, message: `A user with this phone number already has a completed account.` });
    }

    // If user is 'pending' or doesn't exist, we proceed by storing Stage 1 data
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
      return res.status(400).json({ success: false, message: `No OTP found for this phone.` });
    }
    if (Date.now() > entry.expires) {
      delete otpStore[phone];
      return res.status(400).json({ success: false, message: `OTP expired.` });
    }
    if (entry.otp !== otp.toString()) {
      return res.status(400).json({ success: false, message: `Invalid OTP` });
    }
    const signupData = signupStore[phone];
    if (!signupData) {
      return res.status(400).json({ success: false, message: `Signup data missing.` });
    }
    delete otpStore[phone];

    // ✨ MODIFIED LOGIC: This query now handles both new and restarting users.
    // It INSERTS a new user with status 'pending'.
    // If the phone number already exists, it UPDATES their Stage 1 details instead.
    const query = `
      INSERT INTO users (name, college, phone, gender, password, created_at, signup_status) 
      VALUES (?, ?, ?, ?, '', NOW(), 'pending')
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        college = VALUES(college),
        gender = VALUES(gender);
    `;

    await db.query(query, [signupData.name, signupData.college, phone, signupData.gender]);

    // Fetch the user's ID after the insert/update to ensure we have it
    const [userRows] = await db.query('SELECT id FROM users WHERE phone = ?', [phone]);
    const userId = userRows[0].id;

    delete signupStore[phone];

    return res.json({
      success: true,
      message: "OTP verified successfully",
      userId: userId,
      user: {
        id: userId,
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

    // CORRECTED: Hash the password before saving
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    const [updateResult] = await db.query(`UPDATE users SET password = ? WHERE phone = ?`, [hashedPassword, phone]);

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
      `SELECT id, name, college, phone, gender, dob, degree, year, profile_pic, password FROM users WHERE phone = ?`,
      [phone]
    );
    if (!rows.length) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }

    const user = rows[0];
    let isPasswordValid = false;

    // Check if password is already hashed (bcrypt hashes start with $2a$, $2b$, or $2y$)
    if (user.password.startsWith('$2') && user.password.length > 50) {
      // It's a bcrypt hash, use bcrypt.compare
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      // It's plain text, do direct comparison AND hash it for future use
      if (user.password === password) {
        isPasswordValid = true;
        // Update to hashed password for future logins
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);
      }
    }

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }

    // Remove password from response
    delete user.password;
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

    // ✨ NEW "GRADUATION" STEP: Mark the user as fully signed up.
    await db.query(`UPDATE users SET signup_status = 'completed' WHERE id = ?`, [userId]);

    const [rows] = await db.query(`SELECT id, name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE id = ?`, [userId]);
    res.json({ success: true, message: "Profile updated and signup complete!", user: rows[0] });
  } catch (err) {
    console.error("❌ /updateProfile error:", err);
    res.status(500).json({ success: false, message: `Internal Server Error` });
  }
});

app.post("/addTravelPlan", async (req, res) => {
  try {
    // ✨ Now expecting latitude and longitude from the app
    const { userId, fromPlace, toPlace, time, toPlaceLat, toPlaceLng } = req.body;

    // ✨ Updated validation to check for coordinates
    if (!userId || !fromPlace || !toPlace || !time || toPlaceLat === undefined || toPlaceLng === undefined) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields, including destination coordinates."
      });
    }

    const formattedTime = new Date(time);

    // ✨ Updated query to insert the new coordinate columns
    const query = `
      INSERT INTO travel_plans (user_id, from_place, to_place, time, status, to_place_lat, to_place_lng)
      VALUES (?, ?, ?, ?, 'Active', ?, ?)
      ON DUPLICATE KEY UPDATE
        from_place = VALUES(from_place),
        to_place = VALUES(to_place),
        time = VALUES(time),
        status = 'Active',
        to_place_lat = VALUES(to_place_lat),
        to_place_lng = VALUES(to_place_lng)`;

    // ✨ Updated parameters to include the new coordinate values
    const [result] = await db.query(query, [userId, fromPlace, toPlace, formattedTime, toPlaceLat, toPlaceLng]);

    let message = "Plan submitted successfully";
    if (result.affectedRows > 1) {
      message = "Plan updated successfully";
    }

    res.json({
        success: true,
        message: message,
        id: result.insertId
    });

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
        u.name,
        u.college,
        u.gender,
        u.profile_pic
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id
      WHERE tp.user_id = ? AND tp.time > NOW() AND tp.status = 'Active'
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

    // Your logic for hiding messages remains the same
    const hiddenSql = `SELECT message_id FROM hidden_messages WHERE user_id = ?`;
    const [hiddenMessages] = await db.query(hiddenSql, [sender_id]);
    const hiddenIds = hiddenMessages.map(h => h.message_id);
    const visibleMessages = messages.filter(msg => !hiddenIds.includes(msg.id));

    // ✨ Decrypt the visible messages before sending them to the client
    const decryptedMessages = visibleMessages.map(msg => {
        return {
            ...msg, // Copy all original fields (id, sender_id, etc.)
            message: decrypt(msg.message) // Overwrite the message field with the decrypted version
        };
    });

    res.json({ success: true, messages: decryptedMessages });
  } catch (error) {
    console.error('❌ Error fetching messages:', error);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});


app.post('/sendMessage', async (req, res) => {
  try {
    const { sender_id, receiver_id, message } = req.body;

    // Block check logic remains the same
    const blockCheckQuery = `
      SELECT * FROM blocked_users
      WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
    `;
    const [blockedRows] = await db.query(blockCheckQuery, [sender_id, receiver_id, receiver_id, sender_id]);
    if (blockedRows.length > 0) {
      return res.status(403).json({ success: false, message: 'This user cannot be messaged.' });
    }

    // Validation remains the same
    if (!sender_id || !receiver_id || !message) {
      return res.status(400).json({ success: false, message: 'sender_id, receiver_id, and message are required' });
    }

    // ✨ Encrypt the message before saving
    const encryptedMessage = encrypt(message);

    const query = `
      INSERT INTO messages (sender_id, receiver_id, message, timestamp)
      VALUES (?, ?, ?, NOW())
    `;
    // Save the encrypted message to the database
    const [result] = await db.query(query, [sender_id, receiver_id, encryptedMessage]);

    res.json({ success: true, message: 'Message sent successfully', messageId: result.insertId });
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: `Failed to send message` });
  }
});

// In your index.js file

app.get('/getChatUsers', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: `userId is required` });
    }

    // This query is now updated to exclude messages hidden by the current user
    const query = `
      SELECT DISTINCT
        u.id, u.name as username, u.college, u.profile_pic,
        latest.last_message as lastMessage, 
        latest.last_timestamp as timestamp, 
        0 as unreadCount
      FROM users u
      INNER JOIN (
        SELECT
          CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END as other_user_id,
          m.message as last_message, 
          m.timestamp as last_timestamp,
          ROW_NUMBER() OVER (
            PARTITION BY CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
            ORDER BY m.timestamp DESC
          ) as rn
        FROM messages m
        
        -- ✨ MODIFICATION: Join with hidden_messages to find messages hidden by the current user
        LEFT JOIN hidden_messages hm ON m.id = hm.message_id AND hm.user_id = ?
        
        -- ✨ MODIFICATION: Filter the main message pool to exclude hidden ones
        WHERE 
          (m.sender_id = ? OR m.receiver_id = ?) 
          AND hm.message_id IS NULL -- This ensures we only get messages that are NOT hidden
          
      ) latest ON u.id = latest.other_user_id AND latest.rn = 1
      ORDER BY latest.last_timestamp DESC
    `;

    // We now need to pass the userId 5 times to fill in all the '?' placeholders
    const params = [userId, userId, userId, userId, userId];
    const [rows] = await db.execute(query, params);

    // Decrypt the last message for each chat before sending
    const decryptedChats = rows.map(chat => {
        return {
            ...chat,
            lastMessage: decrypt(chat.lastMessage)
        };
    });

    res.json({ success: true, chats: decryptedChats || [] });

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

app.get("/getUsersGoing", async (req, res) => {
    const { currentUserId } = req.query;

    if (!currentUserId) {
        return res.status(400).json({ success: false, message: 'Current user ID is required.' });
    }

    try {
        const friendsQuery = `
            SELECT DISTINCT
                CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
        `;
        const [friendRows] = await db.query(friendsQuery, [currentUserId, currentUserId, currentUserId]);
        const friendIds = new Set(friendRows.map(row => row.friend_id));
        friendIds.add(parseInt(currentUserId));

        const plansQuery = `
            SELECT
                tp.user_id,
                u.name,
                u.profile_pic,
                u.gender,
                u.profile_visibility,
                tp.from_place as fromPlace,
                tp.to_place as toPlace,
                DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            ORDER BY tp.time ASC
        `;
        const [rows] = await db.query(plansQuery);

        const usersGoing = rows.map(user => {
            let finalProfilePic = user.profile_pic;

            if (user.profile_visibility === 'none') {
                finalProfilePic = 'default';
            } 
            else if (user.profile_visibility === 'friends' && !friendIds.has(user.user_id)) {
                finalProfilePic = 'default';
            }

            return {
                id: user.user_id,
                userId: user.user_id,
                name: user.name,
                fromPlace: user.fromPlace,
                toPlace: user.toPlace,
                time: user.time,
                gender: user.gender,
                profile_pic: finalProfilePic
            };
        });

        res.json({ success: true, users: usersGoing });
    } catch (err) {
        console.error("❌ Error fetching users going:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.get("/travel-plans/destinations", async (req, res) => {
  try {
    const query = `
      SELECT
        ANY_VALUE(to_place) as destination, -- Selects one representative name from each group
        COUNT(user_id) as userCount
      FROM travel_plans
      WHERE 
        status = 'Active' 
        AND time > NOW() 
        AND to_place_lat IS NOT NULL 
        AND to_place_lng IS NOT NULL
      -- ✨ THE FIX: Group by rounded coordinates to cluster nearby locations
      GROUP BY 
        ROUND(to_place_lat, 3), 
        ROUND(to_place_lng, 3)
      ORDER BY 
        userCount DESC; -- Order by most popular destinations
    `;
    const [destinations] = await db.query(query);
    res.json({ success: true, destinations: destinations || [] });
  } catch (err) {
    console.error("❌ Error fetching travel plan destinations:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

router.get('/travel-plans/by-destination', async (req, res) => {
    const { destination, currentUserId } = req.query;

    if (!destination || !currentUserId) {
        return res.status(400).json({ success: false, message: 'Destination and currentUserId are required.' });
    }

    try {
        const friendsQuery = `
            SELECT DISTINCT
                CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
        `;
        const [friendRows] = await db.query(friendsQuery, [currentUserId, currentUserId, currentUserId]);
        const friendIds = new Set(friendRows.map(row => row.friend_id));
        friendIds.add(parseInt(currentUserId));

        const plansQuery = `
            SELECT
                u.id, u.name, u.college, u.gender, u.profile_pic, u.profile_visibility,
                tp.from_place as fromPlace,
                tp.to_place as toPlace,
                DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z') as time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            WHERE tp.to_place = ?
            ORDER BY tp.time ASC
        `;
        const [users] = await db.query(plansQuery, [destination]);

        const filteredUsers = users.map(user => {
            let finalProfilePic = user.profile_pic;

            if (user.profile_visibility === 'none') {
                finalProfilePic = 'default';
            } else if (user.profile_visibility === 'friends' && !friendIds.has(user.id)) {
                finalProfilePic = 'default';
            }

            return {
                ...user,
                profile_pic: finalProfilePic
            };
        });

        res.json({ success: true, users: filteredUsers });

    } catch (error) {
        console.error('❌ Error fetching users by destination:', error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// In your index.js file

router.get('/tripHistory/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // This update query remains the same and is correct.
    const updateStatusQuery = `
      UPDATE travel_plans SET status = 'Completed' 
      WHERE user_id = ? AND status = 'Active' AND time < NOW()`;
    await db.query(updateStatusQuery, [parseInt(userId)]);

    const offset = (page - 1) * limit;

    // ✨ THIS QUERY IS THE FIX ✨
    const historyQuery = `
      SELECT
        tp.id, 
        tp.from_place, 
        tp.to_place,
        -- Changed CONVERT_TZ to a standard UTC format string
        DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
        tp.fare, 
        tp.status
      FROM travel_plans tp
      WHERE tp.user_id = ?
      ORDER BY tp.time DESC
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

router.put('/trip/cancel/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
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

router.put('/trip/complete/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { fare } = req.body;
    if (!tripId || isNaN(tripId) || fare === undefined) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID or missing fare' });
    }
    const [result] = await db.query('UPDATE travel_plans SET fare = ? WHERE id = ?', [parseFloat(fare), parseInt(tripId)]);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Trip fare updated successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error('Error completing trip:', error);
    res.status(500).json({ success: false, message: 'Error updating trip fare' });
  }
});

router.delete('/tripHistory/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
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

router.get('/checkCompletedTrips/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const query = `
      SELECT tp.id, tp.from_place, tp.to_place, tp.time, u.name as user_name
      FROM travel_plans tp
      LEFT JOIN users u ON tp.user_id = u.id
      WHERE tp.user_id = ? AND tp.status = 'Active' AND tp.time < NOW()
      ORDER BY tp.time DESC
    `;

    const [completedTrips] = await db.query(query, [parseInt(userId)]);
    res.json({ success: true, data: completedTrips });
  } catch (error) {
    console.error('Error checking completed trips:', error);
    res.status(500).json({ success: false, message: 'Error checking completed trips' });
  }
});

router.put('/completeTrip/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { fare, didGo } = req.body;

    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }

    let updateQuery, queryParams;
    if (didGo === true) {
      updateQuery = 'UPDATE travel_plans SET status = ?, fare = ? WHERE id = ?';
      queryParams = ['Completed', parseFloat(fare) || 0.00, parseInt(tripId)];
    } else {
      updateQuery = 'UPDATE travel_plans SET status = ? WHERE id = ?';
      queryParams = ['Cancelled', parseInt(tripId)];
    }

    const [result] = await db.query(updateQuery, queryParams);
    if (result.affectedRows > 0) {
      const status = didGo ? 'completed' : 'marked as cancelled';
      res.json({ success: true, message: `Trip ${status} successfully` });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error('Error completing trip:', error);
    res.status(500).json({ success: false, message: 'Error completing trip' });
  }
});

router.post('/autoUpdateCompletedTrips', async (req, res) => {
  try {
    const updateQuery = `
      UPDATE travel_plans
      SET status = 'Completed'
      WHERE status = 'Active' AND time < DATE_SUB(NOW(), INTERVAL 2 HOUR)
    `;
    const [result] = await db.query(updateQuery);
    res.json({ success: true, message: `Updated ${result.affectedRows} overdue trips` });
  } catch (error) {
    console.error('Error auto-updating trips:', error);
    res.status(500).json({ success: false, message: 'Error auto-updating trips' });
  }
});

router.get('/tripStats/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const statsQuery = `
      SELECT
        COUNT(*) as total_trips,
        COUNT(DISTINCT to_place) as unique_destinations,
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
      data: { statistics: statsResult[0], topDestinations: topDestinations }
    });
  } catch (error) {
    console.error('Error fetching trip statistics:', error);
    res.status(500).json({ success: false, message: 'Error fetching trip statistics' });
  }
});

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

// In index.js

router.get('/favorites/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!userId) {
        return res.status(400).json({ success: false, message: `User ID is required.` });
    }
    try {
        const query = `
            SELECT id, user_id, routeName, from_place, to_place
            SELECT id, user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng
            FROM favorites
            WHERE user_id = ?
            ORDER BY routeName ASC
        `;
        const [favorites] = await db.query(query, [userId]);
        res.json({ success: true, favorites: favorites });
    } catch (error) {
        console.error('❌ Error fetching favorites:', error);
        res.status(500).json({ success: false, message: `Database error while fetching favorites.` });
    }
});

// In index.js

router.post('/favorites', async (req, res) => {
    // Expecting new fields from the app
    const { userId, routeName, fromPlace, toPlace } = req.body;
    // ✨ Now expecting all coordinate fields
    const { userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;

    if (!userId || !routeName || !fromPlace || !toPlace) {
        return res.status(400).json({ success: false, message: 'Missing required fields.' });
    if (!userId || !routeName || !fromPlace || !toPlace || fromPlaceLat === undefined || fromPlaceLng === undefined || toPlaceLat === undefined || toPlaceLng === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required fields, including all coordinates.' });
    }
    try {
        const query = `
            INSERT INTO favorites (user_id, routeName, from_place, to_place)
            VALUES (?, ?, ?, ?)
            INSERT INTO favorites (user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [userId, routeName, fromPlace, toPlace];
        const values = [userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng];
        const [result] = await db.query(query, values);

        res.status(201).json({
            success: true,
            message: 'Favorite route added successfully.',
            favoriteId: result.insertId
        });
    } catch (error) {
        console.error('❌ Error adding favorite:', error);
        res.status(500).json({ success: false, message: 'Database error while adding favorite.' });
    }
});

router.delete('/favorites/:userId/:favoriteId', async (req, res) => {
    const { userId, favoriteId } = req.params;

    if (!userId || !favoriteId) {
        return res.status(400).json({ success: false, message: 'User ID and Favorite ID are required.' });
    }

    try {
        const query = `DELETE FROM favorites WHERE id = ? AND user_id = ?`;
        const [result] = await db.query(query, [favoriteId, userId]);

        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Favorite deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'Favorite not found or you do not have permission.' });
        }

    } catch (error) {
        console.error('❌ Error deleting favorite:', error);
        res.status(500).json({ success: false, message: 'Database error while deleting favorite.' });
    }
});

router.put('/settings/visibility', async (req, res) => {
    const { userId, visibility } = req.body;

    const allowedVisibilities = ['everyone', 'friends', 'none'];
    if (!userId || !visibility || !allowedVisibilities.includes(visibility)) {
        return res.status(400).json({ success: false, message: 'Invalid input provided.' });
    }

    try {
        const query = 'UPDATE users SET profile_visibility = ? WHERE id = ?';
        await db.query(query, [visibility, userId]);
        res.json({ success: true, message: 'Visibility updated successfully.' });
    } catch (error) {
        console.error('❌ Error updating visibility:', error);
        res.status(500).json({ success: false, message: 'Database error.' });
    }
});

// CORRECTED: Change Password Route - Fixed to match the API call from your Android app
app.post('/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        // 1. Validate input
        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Validate new password length
        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 6 characters long'
            });
        }

        // 2. Fetch the user's current password from the database
        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);

        if (rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const user = rows[0];
        const currentHashedPassword = user.password;

        // 3. Compare the provided currentPassword with the one in the database
        const isMatch = await bcrypt.compare(currentPassword, currentHashedPassword);

        if (!isMatch) {
            return res.status(400).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        // 4. Check if new password is different from current password
        const isSamePassword = await bcrypt.compare(newPassword, currentHashedPassword);

        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password must be different from current password'
            });
        }

        // 5. Hash the new password and update in database
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);

        // 6. Send success response
        res.json({ 
            success: true, 
            message: 'Password changed successfully' 
        });

    } catch (error) {
        console.error('❌ Error changing password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.get('/api/online-users', (req, res) => {
  try {
    const users = Array.from(onlineUsers.entries()).map(([userId, data]) => ({
      userId,
      isOnline: data.isOnline,
      lastSeen: data.lastSeen
    }));
    res.json({ success: true, onlineUsers: users });
  } catch (error) {
    console.error('❌ Error getting online users:', error);
    res.status(500).json({ success: false, message: 'Error fetching online users' });
  }
});

// Check specific user's online status
app.get('/api/user-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check in-memory first for real-time status
    const onlineData = onlineUsers.get(userId);
    if (onlineData) {
      return res.json({
        success: true,
        userId,
        isOnline: true,
        lastSeen: onlineData.lastSeen
      });
    }

    // If not in memory, check database for last seen
    const [rows] = await db.query(
      'SELECT is_online, last_seen FROM user_presence WHERE user_id = ?',
      [userId]
    );

    if (rows.length > 0) {
      res.json({
        success: true,
        userId,
        isOnline: false,
        lastSeen: rows[0].last_seen
      });
    } else {
      res.json({
        success: true,
        userId,
        isOnline: false,
        lastSeen: null
      });
    }
  } catch (error) {
    console.error('❌ Error checking user status:', error);
    res.status(500).json({ success: false, message: 'Error checking user status' });
  }
});

// Use router for all router-defined routes
app.use(router);

// ---------- Start Server ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
