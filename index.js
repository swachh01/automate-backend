require("dotenv").config();
const activeChatSessions = new Map();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs'); 
const admin = require("firebase-admin");

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  // Fallback for local development
  serviceAccount = require("./firebase-service-account.json");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

const express = require("express");
const cors = require("cors");
const path = require("path");
const { encrypt, decrypt } = require('./cryptoHelper');
const fs = require("fs");
const multer = require("multer");
const mysql = require("mysql2");

const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket','polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000
});
const router = express.Router();

const saltRounds = 12;

app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

cloudinary.config({
  secure: true,
});

const onlineUsers = new Map();

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
  timezone: 'Z',
  connectionLimit: 20,
  waitForConnections: true,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
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

// ================= SOCKET.IO LOGIC =================

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  socket.on('user_online', async (userId) => {
    try {
        onlineUsers.set(userId.toString(), {
            socketId: socket.id,
            lastSeen: new Date(),
            isOnline: true
        });
        await updateUserPresence(userId, true);
        
        socket.join(`chat_${userId}`);
        console.log(`✅ User ${userId} joined private chat room: chat_${userId}`);
        
        socket.broadcast.emit('user_status_changed', {
            userId: userId.toString(),
            isOnline: true,
            lastSeen: new Date()
        });
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
    } catch (error) {
      console.error(' Error handling user_offline:', error);
    }
  });

  socket.on('disconnect', async () => {
    try {
      let disconnectedUserId = null;
      for (let [userId, userData] of onlineUsers.entries()) {
        if (userData.socketId === socket.id) {
          disconnectedUserId = userId;
          break;
        }
      }
      if (disconnectedUserId) {
        onlineUsers.delete(disconnectedUserId);
        await updateUserPresence(disconnectedUserId, false);
        socket.broadcast.emit('user_status_changed', {
          userId: disconnectedUserId,
          isOnline: false,
          lastSeen: new Date()
        });
      }
    } catch (error) {
      console.error('❌ Error handling disconnect:', error);
    }
  });

 socket.on('chat_opened', (data) => {
    const { userId, chatPartnerId, groupId } = data;
    if (chatPartnerId) {
        activeChatSessions.set(userId.toString(), `user_${chatPartnerId}`);
    } else if (groupId) {
        activeChatSessions.set(userId.toString(), `group_${groupId}`);
    }
});

socket.on('chat_closed', (data) => {
    const { userId } = data;
    activeChatSessions.delete(userId.toString());
});

  socket.on('typing_start', (data) => {
    socket.to(`chat_${data.chatWithUserId}`).emit('user_typing', {
      userId: data.userId,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    socket.to(`chat_${data.chatWithUserId}`).emit('user_typing', {
      userId: data.userId,
      isTyping: false
    });
  });

socket.on('i_delivered_messages', (data) => {
    socket.to(`chat_${data.partnerId}`).emit('partner_delivered_messages', {
        userId: data.partnerId 
    });
  });

socket.on('i_read_messages', (data) => {
    socket.to(`chat_${data.partnerId}`).emit('partner_read_messages', {
        userId: data.partnerId
    });
});  

  socket.on('join_group', (groupId) => {
    socket.join(`group_${groupId}`);
  });

  socket.on('new_group_message_sent', (data) => {
    socket.to(`group_${data.groupId}`).emit('new_group_message', data.messageObject);
});

socket.on('group_typing_start', async (data) => {
  try {
    const { userId, groupId } = data;
    const [userRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
    
    if (userRows.length > 0) {
      const userName = userRows[0].name;
      socket.to(`group_${groupId}`).emit('group_user_typing', {
        userId: userId,
        userName: userName,
        groupId: groupId,
        isTyping: true
      });
    }
  } catch (error) {
    console.error('Error handling group_typing_start:', error);
  }
});

socket.on('group_typing_stop', async (data) => {
  try {
    const { userId, groupId } = data;
    const [userRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
    
    if (userRows.length > 0) {
      const userName = userRows[0].name;
      socket.to(`group_${groupId}`).emit('group_user_typing', {
        userId: userId,
        userName: userName,
        groupId: groupId,
        isTyping: false
      });
    }
  } catch (error) {
    console.error('Error handling group_typing_stop:', error);
  }
});

socket.on('group_read', async (data) => {
    try {
        const [recentMessages] = await db.query(`
            SELECT 
                gm.message_id,
                COUNT(gmrs.user_id) as readByCount,
                (SELECT COUNT(*) FROM group_members WHERE group_id = ?) as totalParticipants
            FROM group_messages gm
            LEFT JOIN group_message_read_status gmrs ON gm.message_id = gmrs.message_id
            WHERE gm.group_id = ?
            AND gm.timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY gm.message_id
        `, [data.groupId, data.groupId]);
        
        socket.to(`group_${data.groupId}`).emit('group_messages_read', {
            userId: data.userId,
            groupId: data.groupId,
            updatedCounts: recentMessages
        });
        
    } catch (error) {
        console.error('Error handling group_read:', error);
    }
});

}); 

async function getUserByPhone(phone) {
  try {
    const [rows] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE phone = ?`,
      [phone]
    );
    return rows && rows[0] ? rows[0] : null;
  } catch (error) {
    console.error("Error in getUserByPhone:", error);
    return null;
  }
}

app.get("/health", async (_req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: "OK", timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("❌ Health check failed:", err);
    res.status(500).json({ status: "ERROR", message: `Database connection failed: ${err.message}` });
  }
});

app.get("/debug/stores", (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: "Not available in production" });
  }
  res.json({
    otpStore: "OTP is now stored in the database ('otp' table).",
    signupStore: "DB"
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

// ================= CREATE ACCOUNT =================

app.post("/create-account", async (req, res) => {
    const TAG = "/create-account";
    try {
        const { first_name, last_name, college, gender, phone, country_code, password } = req.body;

        if (!first_name || !last_name || !college || !gender || !phone || !country_code || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        if (password.length < 7 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
            return res.status(400).json({ success: false, message: "Password must be at least 7 characters and include letters, numbers, and symbols." });
        }

        console.log(TAG, `Attempting to create account for phone: ${country_code}${phone}`);

        const [existingUser] = await db.query(
            `SELECT id, signup_status FROM users WHERE phone = ? AND country_code = ?`,
            [phone, country_code]
        );

        if (existingUser.length > 0 && existingUser[0].signup_status === 'completed') {
            return res.status(409).json({ success: false, message: "A user with this phone number already exists." });
        }
        
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const query = `
            INSERT INTO users (first_name, last_name, college, gender, phone, country_code, password, signup_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NOW())
            ON DUPLICATE KEY UPDATE
                first_name = VALUES(first_name),
                last_name = VALUES(last_name),
                college = VALUES(college),
                gender = VALUES(gender),
                password = VALUES(password),
                signup_status = 'pending',
                updated_at = NOW();
        `;
        
        await db.query(query, [first_name, last_name, college, gender, phone, country_code, hashedPassword]);

        const [userRows] = await db.query(
            `SELECT id, CONCAT(first_name, ' ', last_name) as name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE phone = ? AND country_code = ?`,
            [phone, country_code]
        );
        
        if (userRows.length === 0) {
             return res.status(500).json({ success: false, message: "Failed to create account." });
        }
        
        const newUser = userRows[0];

        res.status(201).json({
            success: true,
            message: "Account created successfully. Please complete your profile.",
            user: newUser
        });

    } catch (err) {
        console.error(TAG, "❌ Error in /create-account:", err);
        res.status(500).json({ 
            success: false, 
            message: "Server error during account creation.",
            error: err.message
        });
    }
});

// ================= LOGIN =================

app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Missing phone or password` });
  }
  try {
    const [rows] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as name, college, phone, gender, dob, degree, year, profile_pic, password FROM users WHERE phone = ?`,
      [phone]
    );
    if (!rows.length) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }
    
    const user = rows[0];
    let isPasswordValid = false;

    if (user.password.startsWith('$2') && user.password.length > 50) {
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      if (user.password === password) {
        isPasswordValid = true;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);
      }
    }

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }

    delete user.password;
    res.json({ success: true, message: "Login successful", user: { ...user, year: user.year || 0 } });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ================= UPDATE PROFILE =================

app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    console.log("=== Update Profile Request ===");
    
    const { userId, dob, degree, year } = req.body || {};
    
    if (!userId) {
      return res.status(400).json({ success: false, message: "Missing userId" });
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
      return res.status(400).json({ success: false, message: "Nothing to update" });
    }
    
    const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
    params.push(userId);
    
    const [result] = await db.query(sql, params);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
      
    await db.query("UPDATE users SET signup_status = 'completed' WHERE id = ?", [userId]);
    
    const [rows] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE id = ?`,
      [userId]
    );
    
    console.log("Updated user:", rows[0]);
    
    res.json({ success: true, message: "Profile updated and signup complete!", user: rows[0] });
  } catch (err) {
    console.error("=== /updateProfile ERROR ===");
    res.status(500).json({ success: false, message: "Internal Server Error", error: err.message });
  } 
});

// ================= ADD TRAVEL PLAN =================

app.post("/addTravelPlan", async (req, res) => {
    const TAG = "/addTravelPlan"; 
    let connection; 

    try {
        const { userId, fromPlace, toPlace, time, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;

        if (!userId || !fromPlace || !toPlace || !time ||
            fromPlaceLat === undefined || fromPlaceLng === undefined ||
            toPlaceLat === undefined || toPlaceLng === undefined) {
            return res.status(400).json({
                success: false,
                message: "Missing required fields."
            });
        }
        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) { throw new Error("Invalid date format."); }
        } catch (timeError) {
             return res.status(400).json({ success: false, message: "Invalid time format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        const planQuery = `
          INSERT INTO travel_plans
            (user_id, from_place, to_place, time, status,
             from_place_lat, from_place_lng, to_place_lat, to_place_lng,
             created_at, updated_at)
          VALUES (?, ?, ?, ?, 'Active', ?, ?, ?, ?, NOW(), NOW());
        `;
        const [planResult] = await connection.query(planQuery, [
            userId, fromPlace, toPlace, formattedTime,
            fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng
        ]);

        const newPlanId = planResult.insertId;
        if (!newPlanId) {
             await connection.rollback();
             connection.release();
             throw new Error("Travel plan insert failed.");
        }

        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; 
        await connection.query(groupQuery, [toPlace]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [toPlace]);
        if (groupRows.length === 0) {
            await connection.rollback();
            connection.release();
            throw new Error(`Failed to find group_id.`);
        }
        const groupId = groupRows[0].group_id;

        const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
        await connection.query(memberQuery, [groupId, userId]);

        await connection.commit();

        try {
            const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
            const joinerName = userRows.length > 0 ? userRows[0].name : "Someone";

            const [matchingUsers] = await connection.query(`
                SELECT DISTINCT u.fcm_token 
                FROM travel_plans tp
                JOIN users u ON tp.user_id = u.id
                WHERE tp.to_place = ? 
                  AND tp.status = 'Active'
                  AND tp.user_id != ? 
                  AND u.fcm_token IS NOT NULL
                  AND u.fcm_token != ''
                  AND u.trip_alerts_enabled = 1
            `, [toPlace, userId]);

            if (matchingUsers.length > 0) {
                const tokens = matchingUsers.map(u => u.fcm_token);
                const messagePayload = {
                    tokens: tokens,
                    notification: {
                        title: "New Travel Buddy!",
                        body: `${joinerName} is also going to ${toPlace}!`
                    },
                    android: {
                        priority: "high",
                        notification: {
                            channelId: "channel_custom_sound_v2",
                            sound: "custom_notification",
                            priority: "high",
                            defaultSound: false
                        }
                    },
                    data: {
                        type: "travel_match",
                        destinationName: String(toPlace),
                        groupId: String(groupId)
                    }
                };
                await admin.messaging().sendEachForMulticast(messagePayload);
            }
        } catch (notifyError) {
            console.error(TAG, "⚠️ Error sending travel match notification:", notifyError.message);
        }

        res.status(201).json({
            success: true,
            message: "Plan submitted successfully and group joined",
            id: newPlanId
        });

    } catch (err) {
        if (connection) {
            try { await connection.rollback(); } catch (e) {}
        }
        console.error(TAG, `❌ Error saving travel plan:`, err);
        res.status(500).json({ success: false, message: "Server error occurred." });
    } finally {
        if (connection) { connection.release(); }
    }
});

app.get('/users/destination', async (req, res) => {
    const TAG = "/users/destination";
    const { groupId, userId } = req.query; 

    if (!groupId || !userId) {
        return res.status(400).json({ success: false, message: 'Missing groupId or userId' });
    }

    const currentGroupId = parseInt(groupId);
    const currentUserId = parseInt(userId);

    try {
        const query = `
            SELECT
                u.id,           
                u.id as userId, 
                CONCAT(u.first_name, ' ', u.last_name) as name,
                u.college,
                u.profile_pic AS profilePic,
                u.gender,
                tp.time,        
                tp.from_place AS fromPlace, 
                tp.to_place AS toPlace     
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            INNER JOIN travel_plans tp ON u.id = tp.user_id
                AND tp.status = 'Active' 
                AND tp.to_place = (SELECT group_name FROM \`group_table\` WHERE group_id = ?)
            WHERE
                gm.group_id = ?       
                AND gm.user_id != ?   
            ORDER BY
                tp.time ASC; 
        `;
        const [users] = await db.execute(query, [currentGroupId, currentGroupId, currentUserId]);

        const responseUsers = users.map(user => ({
            ...user,
            id: user.id, 
            userId: user.id 
        }));

        res.json({ success: true, users: responseUsers }); 

    } catch (error) {
        console.error(TAG, `Error fetching active users:`, error);
        res.status(500).json({ success: false, message: 'Server error fetching users' });
    }
});

app.post("/updateFcmToken", async (req, res) => {
    const { userId, token } = req.body;
    try {
        await db.query("UPDATE users SET fcm_token = ? WHERE id = ?", [token, userId]);
        res.json({ success: true, message: "Token updated" });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get("/getUserTravelPlan/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!userId) {
      return res.status(400).json({ success: false, message: "User ID required" });
    }
    const [results] = await db.query(
      `SELECT
        tp.id,
        tp.from_place as fromPlace,
        tp.to_place as toPlace,
        tp.time,
        CONCAT(u.first_name, ' ', u.last_name) as name,
        u.college,
        u.gender,
        u.profile_pic
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id  
      WHERE tp.user_id = ? 
        AND tp.time > UTC_TIMESTAMP() 
        AND tp.status = 'Active'
      ORDER BY tp.time ASC`,
      [userId]
    );
      
    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error(`Error fetching travel plan:`, err);
    res.status(500).json({ success: false, message: "Database error", users: [] });
  }   
});

app.get('/getMessages', async (req, res) => {
  try {
    const { sender_id, receiver_id } = req.query;
    if (!sender_id || !receiver_id) {
      return res.status(400).json({ success: false, message: 'Required fields missing' });
    }

    // Select * will capture new columns (message_type, latitude, longitude, expires_at)
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
        
    const decryptedMessages = visibleMessages.map(msg => {
        return { 
            ...msg, 
            message: decrypt(msg.message) // Decrypt content 
        };
    });
        
    res.json({ success: true, messages: decryptedMessages });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Database error' });
  } 
});

app.post('/messages/delivered', async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }
    const query = `UPDATE messages SET status = 1 WHERE sender_id = ? AND receiver_id = ? AND status = 0`;
    const [result] = await db.execute(query, [otherUserId, userId]);
    res.json({ success: true, message: 'Marked delivered', updatedCount: result.affectedRows });
  } catch (error) {
    console.error('Error marking delivered:', error);
    res.status(500).json({ success: false });
  }
});

app.post('/sendMessage', async (req, res) => {
  const TAG = "/sendMessage";

  try {
    // --- UPDATED: Destructure new location fields ---
    const { sender_id, receiver_id, message, message_type, latitude, longitude, duration } = req.body;

    if (!sender_id || !receiver_id || !message) {
      return res.status(400).json({ success: false, message: 'Missing fields' });
    }

    const blockCheckQuery = `
      SELECT * FROM blocked_users
      WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
    `;
    const [blockedRows] = await db.query(blockCheckQuery, [sender_id, receiver_id, receiver_id, sender_id]);

    if (blockedRows.length > 0) {
      return res.status(403).json({ success: false, message: 'User cannot be messaged.' });
    }

    const encryptedMessage = encrypt(message);
    
    // --- UPDATED: Handle Message Type and Expiry ---
    const type = message_type || 'text';
    let expiresAt = null;

    if (type === 'location' && duration && duration > 0) {
        // Duration is in minutes
        const date = new Date();
        date.setMinutes(date.getMinutes() + duration);
        // Format for MySQL: YYYY-MM-DD HH:MM:SS
        expiresAt = date.toISOString().slice(0, 19).replace('T', ' ');
    }

    const query = `
        INSERT INTO messages 
        (sender_id, receiver_id, message, timestamp, status, message_type, latitude, longitude, expires_at) 
        VALUES (?, ?, ?, UTC_TIMESTAMP(), 0, ?, ?, ?, ?)
    `;
    const [result] = await db.query(query, [
        sender_id, receiver_id, encryptedMessage, type, latitude || null, longitude || null, expiresAt
    ]);

    if (!result.insertId) {
      return res.status(500).json({ success: false, message: 'Failed to save message' });
    }

    const newMessageId = result.insertId;
    // Fetch full message including new columns
    const [insertedMsg] = await db.query('SELECT * FROM messages WHERE id = ?', [newMessageId]);
    const msgData = insertedMsg[0];

    const messageToEmit = {
      id: msgData.id,
      sender_id: msgData.sender_id,
      receiver_id: msgData.receiver_id,
      message: message, // Send DECRYPTED to socket
      timestamp: msgData.timestamp,
      status: 0,
      message_type: msgData.message_type,
      latitude: msgData.latitude,
      longitude: msgData.longitude,
      expires_at: msgData.expires_at
    };

    io.to(`chat_${receiver_id}`).emit('new_message_received', messageToEmit);
    io.to(`chat_${sender_id}`).emit('new_message_received', messageToEmit);

    try {
      const receiverActiveChat = activeChatSessions.get(receiver_id.toString());
      const isChatOpen = receiverActiveChat === `user_${sender_id}`;
      
      if (!isChatOpen) {
        const [userRows] = await db.query("SELECT fcm_token FROM users WHERE id = ?", [receiver_id]);
        const [senderRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name, profile_pic FROM users WHERE id = ?", [sender_id]);
        const senderName = senderRows.length > 0 ? senderRows[0].name : "New Message";
        const senderPic = senderRows.length > 0 ? senderRows[0].profile_pic : "";

        if (userRows.length > 0 && userRows[0].fcm_token) {
          const messagePayload = {
            token: userRows[0].fcm_token,
            notification: { title: senderName, body: type === 'location' ? '📍 Shared a location' : message },
            android: {
              priority: "high",
              notification: { channelId: "channel_custom_sound_v2", sound: "custom_notification", priority: "high", defaultSound: false }
            },
            data: {
              type: "chat",
              senderId: sender_id.toString(),
              senderName: senderName,
              senderProfilePic: senderPic || "",
              chatPartnerId: sender_id.toString()
            }
          };
          await admin.messaging().send(messagePayload);
        }
      }
    } catch (fcmError) {
      console.error(TAG, "⚠️ Error sending FCM:", fcmError.message);
    }

    res.json({ success: true, message: 'Message sent', messageId: newMessageId });

  } catch (error) {
    console.error(TAG, '❌ Error in /sendMessage:', error);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

app.get('/getChatUsers', async (req, res) => {
    const TAG = "/getChatUsers";
    try {
        const { userId } = req.query;
        if (!userId) {
            return res.status(400).json({ success: false, message: 'userId required' });
        }
        const currentUserId = parseInt(userId);
        
        const combinedQuery = `
            WITH LatestChats AS (
                SELECT
                    'individual' AS chat_type,
                    CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS chat_id,
                    m.message AS last_message_content,
                    m.timestamp AS last_timestamp,
                    m.sender_id AS last_sender_id,
                    m.status AS last_message_status,
                    ROW_NUMBER() OVER (
                        PARTITION BY CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
                        ORDER BY m.timestamp DESC
                    ) as rn
                FROM messages m
                LEFT JOIN hidden_messages hm ON m.id = hm.message_id AND hm.user_id = ?
                WHERE
                    (m.sender_id = ? OR m.receiver_id = ?)
                    AND hm.message_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM chat_requests cr 
                        WHERE cr.sender_id = m.sender_id 
                          AND cr.receiver_id = ? 
                          AND cr.status = 'pending'
                    )
                UNION ALL
                SELECT
                    'group' AS chat_type,
                    gm.group_id AS chat_id,
                    gm.message_content AS last_message_content,
                    gm.timestamp AS last_timestamp,
                    gm.sender_id AS last_sender_id,
                    -1 AS last_message_status,
                    ROW_NUMBER() OVER (
                        PARTITION BY gm.group_id
                        ORDER BY gm.timestamp DESC
                    ) as rn
                FROM group_messages gm
                JOIN group_members gmem ON gm.group_id = gmem.group_id AND gmem.user_id = ?
                WHERE
                    gmem.user_id = ?
            )
            SELECT
                lc.chat_type,
                lc.chat_id,
                lc.last_message_content,
                lc.last_timestamp,
                lc.last_sender_id,
                lc.last_message_status,
                CONCAT(u_sender.first_name, ' ', u_sender.last_name) AS last_sender_name,
                CASE WHEN lc.chat_type = 'individual' THEN CONCAT(u_partner.first_name, ' ', u_partner.last_name) ELSE NULL END AS username,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.profile_pic ELSE NULL END AS profile_pic,
                
                -- ADDED GENDER HERE
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.gender ELSE NULL END AS gender,
                
                CASE WHEN lc.chat_type = 'group' THEN gt.group_name ELSE NULL END AS group_name,
                 (SELECT COUNT(*) FROM messages m_unread
                  WHERE lc.chat_type = 'individual'
                    AND m_unread.receiver_id = ?
                    AND m_unread.sender_id = lc.chat_id
                    AND m_unread.status < 2
                 ) AS individual_unread_count,
                 (SELECT COUNT(*) 
                  FROM group_messages gm_unread
                  WHERE lc.chat_type = 'group'
                    AND gm_unread.group_id = lc.chat_id
                    AND gm_unread.sender_id != ?
                    AND NOT EXISTS (
                        SELECT 1 
                        FROM group_message_read_status gmrs
                        WHERE gmrs.message_id = gm_unread.message_id
                          AND gmrs.user_id = ?
                    )
                 ) AS group_unread_count
            FROM LatestChats lc
            LEFT JOIN users u_partner ON lc.chat_type = 'individual' AND lc.chat_id = u_partner.id
            LEFT JOIN \`group_table\` gt ON lc.chat_type = 'group' AND lc.chat_id = gt.group_id
            LEFT JOIN users u_sender ON lc.last_sender_id = u_sender.id
            WHERE lc.rn = 1
            ORDER BY lc.last_timestamp DESC;
        `;

        const params = [
            currentUserId, currentUserId, currentUserId, 
            currentUserId, currentUserId, 
            currentUserId, 
            currentUserId, currentUserId, 
            currentUserId, 
            currentUserId, currentUserId 
        ];

        const [rows] = await db.execute(combinedQuery, params);

        const chatListItems = rows.map(row => {
            let lastMessage = "";
            try { lastMessage = row.last_message_content ? decrypt(row.last_message_content) : ""; } catch (e) { lastMessage = "[Encrypted Message]"; }

            const isGroup = row.chat_type === 'group';
            const chatId = row.chat_id; 
            const chatName = isGroup ? row.group_name : row.username;
            const profilePicUrl = isGroup ? 'default_group_icon' : row.profile_pic; 
            const unreadCount = isGroup ? row.group_unread_count : row.individual_unread_count;

            return {
                isGroup: isGroup,
                chatId: chatId,
                chatName: chatName,
                lastMessage: lastMessage,
                timestamp: row.last_timestamp, 
                unreadCount: unreadCount,
                profilePicUrl: profilePicUrl,
                gender: row.gender, // Mapped here
                lastSenderId: row.last_sender_id,
                lastSenderName: row.last_sender_name,
                lastMessageStatus: row.last_message_status 
            };
        });

        res.json({ success: true, chats: chatListItems });

    } catch (error) {
        console.error(TAG, '❌ Error fetching chat list:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch chat list' });
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

// ================= BLOCK USER =================
app.post('/block', async (req, res) => {
  try {
    const { blocker_id, blocked_id } = req.body;
    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocker and blocked IDs are required.' });
    }

    await db.query('INSERT INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)', [blocker_id, blocked_id]);

    // --- REAL-TIME UPDATE START ---
    const eventData = { blockerId: parseInt(blocker_id), blockedId: parseInt(blocked_id) };
    
    // Notify the person being blocked (so their UI disables input)
    io.to(`chat_${blocked_id}`).emit('user_blocked', eventData);
    // Notify the blocker (optional, but good for multi-device sync)
    io.to(`chat_${blocker_id}`).emit('user_blocked', eventData);
    // --- REAL-TIME UPDATE END ---

    res.json({ success: true, message: 'User blocked successfully.' });
  } catch (err) {
    console.error(" Error blocking user:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

// ================= UNBLOCK USER =================
app.post('/unblock', async (req, res) => {
  try {
    const { blocker_id, blocked_id } = req.body;
    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocker and blocked IDs are required.' });
    }

    await db.query('DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?', [blocker_id, blocked_id]);

    // --- REAL-TIME UPDATE START ---
    const eventData = { blockerId: parseInt(blocker_id), blockedId: parseInt(blocked_id) };

    // Notify the person being unblocked
    io.to(`chat_${blocked_id}`).emit('user_unblocked', eventData);
    // Notify the blocker
    io.to(`chat_${blocker_id}`).emit('user_unblocked', eventData);
    // --- REAL-TIME UPDATE END ---

    res.json({ success: true, message: 'User unblocked successfully.' });
  } catch (err) {
    console.error(" Error unblocking user:", err);
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
    console.error(" Error checking block status:", err);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/updateNotificationSettings', async (req, res) => {
    const { userId, type, enabled } = req.body;
    if (!userId || !type) {
        return res.status(400).json({ success: false, message: 'Missing fields' });
    }
    try {
        let column = "";
        if (type === "trip_alerts") column = "trip_alerts_enabled";
        if (column) {
            await db.query(`UPDATE users SET ${column} = ? WHERE id = ?`, [enabled, userId]);
            res.json({ success: true, message: 'Settings updated' });
        } else {
            res.json({ success: true, message: 'No valid setting type found' });
        }
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ success: false, message: 'Server error' });
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
                CONCAT(u.first_name, ' ', u.last_name) as name,
                u.profile_pic,
                u.gender,
                u.profile_visibility,
                tp.from_place as fromPlace,
                tp.to_place as toPlace,
                DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            WHERE tp.status = 'Active'
            ORDER BY tp.time ASC
        `;
        const [rows] = await db.query(plansQuery);

        const usersGoing = rows.map(user => {
            let finalProfilePic = user.profile_pic;
            if (user.profile_visibility === 'none') { finalProfilePic = 'default'; } 
            else if (user.profile_visibility === 'friends' && !friendIds.has(user.user_id)) { finalProfilePic = 'default'; }
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
        console.error(" Error fetching users going:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.get("/travel-plans/destinations", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'Current user ID (userId) is required as a query parameter.' });
    }
    const query = `
      SELECT
        ANY_VALUE(tp.to_place) as destination,
        COUNT(tp.user_id) as userCount,
        ANY_VALUE(g.group_id) as group_id,
        SUM(CASE WHEN tp.user_id = ? THEN 1 ELSE 0 END) > 0 AS isCurrentUserGoing
      FROM travel_plans tp
      JOIN \`group_table\` g ON tp.to_place = g.group_name
      WHERE
        tp.status = 'Active'
        AND tp.time > NOW()
        AND tp.to_place_lat IS NOT NULL
        AND tp.to_place_lng IS NOT NULL
      GROUP BY
        ROUND(tp.to_place_lat, 3),
        ROUND(tp.to_place_lng, 3)
      ORDER BY
        userCount DESC;
    `;
    const [destinations] = await db.query(query, [userId]);
    res.json({ success: true, destinations: destinations || [] });
  } catch (err) {
    console.error(" Error fetching travel plan destinations:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get('/travel-plans/by-destination', async (req, res) => {
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
                u.id, CONCAT(u.first_name, ' ', u.last_name) as name, u.college, u.gender, u.profile_pic, u.profile_visibility,
                tp.from_place as fromPlace,
                tp.to_place as toPlace,
                DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z') as time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            WHERE tp.to_place = ? AND tp.status = 'Active'
            ORDER BY tp.time ASC
        `;
        const [users] = await db.query(plansQuery, [destination]);

        const filteredUsers = users.map(user => {
            let finalProfilePic = user.profile_pic;
            if (user.profile_visibility === 'none') { finalProfilePic = 'default'; } else if (user.profile_visibility === 'friends' && !friendIds.has(user.id)) { finalProfilePic = 'default'; }
            return { ...user, profile_pic: finalProfilePic };
        });
        res.json({ success: true, users: filteredUsers });
    } catch (error) {
        console.error(' Error fetching users by destination:', error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

app.delete("/user/profile/:userId", async (req, res) => {
    const TAG = "/user/profile/:userId (DELETE)";
    try {
        const { userId } = req.params;
        if (!userId || isNaN(userId)) {
            return res.status(400).json({ success: false, message: "User ID required" });
        }
        await db.query("UPDATE users SET profile_pic = NULL WHERE id = ?", [parseInt(userId)]);
        res.json({ success: true, message: "Profile picture removed", user: { profilePic: null } });
    } catch (err) {
        console.error(TAG, "Error removing profile pic:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get('/tripHistory/:userId', async (req, res) => {
  const TAG = "GET /tripHistory/:userId";
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }
    const updateStatusQuery = `UPDATE travel_plans SET status = 'Completed' WHERE user_id = ? AND status = 'Active' AND time < NOW() AND added_fare = FALSE`;
    await db.query(updateStatusQuery, [parseInt(userId)]);
    const offset = (page - 1) * limit;
    const historyQuery = `
      SELECT
        tp.id, tp.from_place, tp.to_place,
        DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
        tp.fare, tp.status, tp.added_fare as hasAddedFare
      FROM travel_plans tp
      WHERE tp.user_id = ?
      ORDER BY tp.time DESC
      LIMIT ? OFFSET ?
    `;
    const [trips] = await db.query(historyQuery, [parseInt(userId), parseInt(limit), parseInt(offset)]);
    const processedTrips = trips.map(trip => ({
        id: trip.id,
        from_place: trip.from_place,
        to_place: trip.to_place,
        travel_time: trip.travel_time,
        fare: trip.fare ? parseFloat(trip.fare) : null,
        status: trip.status,
        hasAddedFare: Boolean(trip.hasAddedFare),
        addedFare: trip.fare ? parseFloat(trip.fare) : null
    }));
    const countQuery = 'SELECT COUNT(*) as total FROM travel_plans WHERE user_id = ?';
    const [countResult] = await db.query(countQuery, [parseInt(userId)]);
    res.json({
      success: true,
      data: {
        trips: processedTrips,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(countResult[0].total / limit),
          totalTrips: countResult[0].total,
          hasMore: offset + processedTrips.length < countResult[0].total
        }
      }
    });
  } catch (error) {
    console.error(TAG, '❌ Error fetching trip history:', error);
    res.status(500).json({ success: false, message: 'Error fetching trip history', error: error.message });
  }
});

app.put('/trip/cancel/:tripId', async (req, res) => {
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

app.get('/socket-status', (req, res) => {
  const connectedSockets = [];
  io.sockets.sockets.forEach((socket) => {
    connectedSockets.push({
      id: socket.id,
      connected: socket.connected
    });
  });
  res.json({
    success: true,
    totalConnections: io.engine.clientsCount,
    onlineUsers: Array.from(onlineUsers.keys()),
    sockets: connectedSockets
  });
});

app.put('/trip/complete/:tripId', async (req, res) => {
  const TAG = "PUT /trip/complete/:tripId";
  try {
    const { tripId } = req.params;
    const { fare, didGo } = req.body;
    if (!tripId || isNaN(tripId) || didGo === undefined) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID or missing didGo status' });
    }
    let updateQuery, queryParams;
    if (didGo === true) {
      updateQuery = 'UPDATE travel_plans SET status = ?, fare = ?, added_fare = TRUE WHERE id = ?';
      queryParams = ['Done', parseFloat(fare) || 0.00, parseInt(tripId)];
    } else {
      updateQuery = 'UPDATE travel_plans SET status = ?, fare = 0.00, added_fare = TRUE WHERE id = ?';
      queryParams = ['Cancelled', parseInt(tripId)];
    }
    const [result] = await db.query(updateQuery, queryParams);
    if (result.affectedRows > 0) {
      res.json({ success: true, message: didGo ? 'Fare added successfully' : 'Trip marked as cancelled', newStatus: didGo ? 'Done' : 'Cancelled' });
    } else {
      res.status(404).json({ success: false, message: 'Trip not found' });
    }
  } catch (error) {
    console.error(TAG, '❌ Error completing trip:', error);
    res.status(500).json({ success: false, message: 'Error completing trip' });
  }
});

app.delete('/tripHistory/:tripId', async (req, res) => {
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

app.get('/checkCompletedTrips/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }
    const query = `
      SELECT tp.id, tp.from_place, tp.to_place, tp.time, CONCAT(u.first_name, ' ', u.last_name) as user_name
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

app.post('/autoUpdateCompletedTrips', async (req, res) => {
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

app.get('/tripStats/:userId', async (req, res) => {
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

app.post('/reset-password', async (req, res) => {
    const TAG = "/reset-password";
    try {
        const { phone, country_code, newPassword } = req.body;
        if (!phone || !country_code || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Phone, country code, and new password are required'
            });
        }
        if (newPassword.length < 7 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 7 characters and include letters, numbers, and symbols." 
            });
        }
        const [userRows] = await db.query(
            'SELECT id FROM users WHERE phone = ? AND country_code = ?',
            [phone, country_code]
        );
        if (userRows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        const userId = userRows[0].id;
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error(TAG, '❌ Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get("/getUserByPhone", async (req, res) => {
    const TAG = "/getUserByPhone"; 
    const phone = req.query.phone;
    const country_code = req.query.country_code; 

    if (!phone || !country_code) { 
        return res.status(400).json({ success: false, message: "Missing required phone number or country code." });
    }
    if (!/^\+\d{1,4}$/.test(country_code)) {
         return res.status(400).json({ success: false, message: "Invalid country code format." });
    }
     if (!/^\d{10}$/.test(phone)) {
         return res.status(400).json({ success: false, message: "Invalid phone number format." });
    }

    try {
        const query = `
            SELECT id, CONCAT(first_name, ' ', last_name) as name, college, phone, country_code, gender, dob, degree, year, profile_pic
            FROM users
            WHERE phone = ? AND country_code = ?;
        `;
        const [results] = await db.query(query, [phone, country_code]);

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: "User not registered." });
        }
        const user = results[0];
        delete user.password;
        res.json({ success: true, userId: user.id, user: user });
    } catch (err) {
        console.error(TAG, `❌ Error searching for user:`, err);
        res.status(500).json({ success: false, message: "Server error." });
    }
});

app.post('/markMessagesRead', async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }
    const query = `
      UPDATE messages 
      SET status = 2 
      WHERE sender_id = ? AND receiver_id = ? AND status < 2
    `;
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
    const query = `SELECT COUNT(*) as unreadCount FROM messages WHERE sender_id = ? AND receiver_id = ? AND status < 2`;
    const [rows] = await db.execute(query, [otherUserId, userId]);
    res.json({ success: true, unreadCount: rows[0].unreadCount });
  } catch (error) {
    console.error('Error getting unread count:', error);
    res.status(500).json({ success: false, message: 'Failed to get unread count' });
  }
});

app.get('/getTotalUnreadCount', async (req, res) => {
    const TAG = "/getTotalUnreadCount"; 
    const { userId } = req.query;
    
    if (!userId) {
        return res.status(400).json({ success: false, message: 'userId is required' });
    }
    
    const currentUserId = parseInt(userId);

    try {
        const individualQuery = `
            SELECT COUNT(*) as totalUnreadCount 
            FROM messages 
            WHERE receiver_id = ? AND status < 2
        `;
        const [individualRows] = await db.execute(individualQuery, [currentUserId]);
        const individualCount = individualRows[0].totalUnreadCount;

        const groupQuery = `
            SELECT COUNT(*) as totalUnreadCount
            FROM group_messages gm
            WHERE 
                gm.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)
                AND gm.sender_id != ?
                AND NOT EXISTS (
                    SELECT 1
                    FROM group_message_read_status gmrs
                    WHERE gmrs.message_id = gm.message_id
                      AND gmrs.user_id = ?
                );
        `;
        const [groupRows] = await db.execute(groupQuery, [currentUserId, currentUserId, currentUserId]);
        const groupCount = groupRows[0].totalUnreadCount;
        const totalUnreadCount = individualCount + groupCount;
        
        res.json({ success: true, unreadCount: totalUnreadCount });
    } catch (error) {
        console.error(TAG, '❌ Error getting total unread count:', error);
        res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
});

app.post("/hideChat", async (req, res) => {
    const TAG = "/hideChat"; 
    try {
        const { userId, otherUserId } = req.body;

        if (!userId || !otherUserId) {
            return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
        }

        if (userId === otherUserId) {
             return res.status(400).json({ success: false, message: 'Cannot hide chat with yourself' });
        }
        
        const [messages] = await db.query(
            `SELECT id FROM messages 
             WHERE (sender_id = ? AND receiver_id = ?) 
                OR (sender_id = ? AND receiver_id = ?)`,
            [userId, otherUserId, otherUserId, userId]
        );

        if (messages.length === 0) {
            return res.json({ success: true, message: 'Chat hidden successfully (no messages).' });
        }

        const valuesToHide = messages.map(msg => [msg.id, userId, new Date()]);
        
        const hideQuery = `
            INSERT IGNORE INTO hidden_messages (message_id, user_id, hidden_at)
            VALUES ?
        `; 
        await db.query(hideQuery, [valuesToHide]);
        res.json({ success: true, message: 'Chat history hidden successfully.' });

    } catch (error) {
        console.error(TAG, "❌ Error in /hideChat:", error);
        res.status(500).json({ success: false, message: 'Failed to hide chat.' });
    }
});

app.post("/cleanupDeletedMessages", async (req, res) => {
    const TAG = "/cleanupDeletedMessages";
    try {
        const [deletableMessages] = await db.query(`
            SELECT message_id
            FROM hidden_messages
            GROUP BY message_id
            HAVING COUNT(DISTINCT user_id) >= 2
        `);

        if (deletableMessages.length === 0) {
            return res.status(200).json({ success: true, message: "No messages to clean up." });
        }

        const messageIdsToDelete = deletableMessages.map(msg => msg.message_id);
        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            await connection.query(`DELETE FROM messages WHERE id IN (?)`, [messageIdsToDelete]);
            await connection.query(`DELETE FROM hidden_messages WHERE message_id IN (?)`, [messageIdsToDelete]);
            await connection.commit();
            connection.release();
            res.status(200).json({ success: true, message: `Cleaned up messages.` });

        } catch (txError) {
            await connection.rollback();
            connection.release();
            console.error(TAG, "❌ Error during cleanup transaction:", txError);
            throw txError; 
        }
    } catch (error) {
        console.error(TAG, "❌ Error running cleanup task:", error);
        res.status(500).json({ success: false, message: 'Server error during message cleanup.' });
    }
});

app.delete('/deleteMessage/:messageId', async (req, res) => {
  const TAG = "DELETE /deleteMessage";
  try {
    const { messageId } = req.params;
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'userId is required' });
    }

    // 1. Fetch message details first to identify the chat room partners
    const [messages] = await db.execute('SELECT * FROM messages WHERE id = ?', [messageId]);
    
    if (messages.length === 0) {
        return res.status(404).json({ success: false, message: 'Message not found' });
    }

    const msg = messages[0];

    // Security check: Only sender can delete for everyone
    if (msg.sender_id != userId) {
        return res.status(403).json({ success: false, message: 'Only the sender can delete for everyone' });
    }

    // 2. Delete from database
    const query = 'DELETE FROM messages WHERE id = ?';
    const [result] = await db.execute(query, [messageId]);

    if (result.affectedRows > 0) {
      // 3. EMIT SOCKET EVENT TO BOTH USERS
      const eventData = { messageId: parseInt(messageId) };
      
      // Notify the receiver
      io.to(`chat_${msg.receiver_id}`).emit('message_deleted', eventData);
      
      // Notify the sender (in case they have multiple devices or just to confirm)
      io.to(`chat_${msg.sender_id}`).emit('message_deleted', eventData);

      res.json({ success: true, message: 'Message deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Message not found during delete' });
    }
  } catch (error) {
    console.error(TAG, 'Error deleting message:', error);
    res.status(500).json({ success: false, message: 'Failed to delete message' });
  }
});

app.get('/favorites/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!userId) {
        return res.status(400).json({ success: false, message: `User ID is required.` });
    }
    try {
        const query = `
            SELECT id, user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng
            FROM favorites
            WHERE user_id = ?
            ORDER BY routeName ASC
        `;
        const [favorites] = await db.query(query, [userId]);
        res.json({ success: true, favorites: favorites });
    } catch (error) {
        console.error(' Error fetching favorites:', error);
        res.status(500).json({ success: false, message: `Database error while fetching favorites.` });
    }
});

app.post('/favorites', async (req, res) => {
    const { userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;

    if (!userId || !routeName || !fromPlace || !toPlace || fromPlaceLat === undefined || fromPlaceLng === undefined || toPlaceLat === undefined || toPlaceLng === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required fields.' });
    }
    try {
        const query = `
            INSERT INTO favorites (user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const values = [userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng];
        const [result] = await db.query(query, values);

        res.status(201).json({
            success: true,
            message: 'Favorite route added successfully.',
            favoriteId: result.insertId
        });
    } catch (error) {
        console.error(' Error adding favorite:', error);
        res.status(500).json({ success: false, message: 'Database error while adding favorite.' });
    }
});

app.get("/user/:userId", async (req, res) => {
    const TAG = "/user/:userId"; 
    try {
        const { userId } = req.params; 
        const { viewerId } = req.query; 

        if (!userId || isNaN(userId)) {
            return res.status(400).json({ success: false, message: "Invalid or missing user ID." });
        }

        const query = `
            SELECT
                id, CONCAT(first_name, ' ', last_name) as name,
                college, gender, dob, degree, year, profile_pic, profile_visibility,
                EXISTS (
                    SELECT 1 FROM messages m 
                    WHERE (m.sender_id = ? AND m.receiver_id = users.id) 
                       OR (m.sender_id = users.id AND m.receiver_id = ?)
                ) as hasChat
            FROM users
            WHERE id = ?;
        `;
        const [rows] = await db.query(query, [viewerId, viewerId, parseInt(userId)]);

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found." });
        }
        const user = rows[0]; 
        user.hasChat = Boolean(user.hasChat);
        res.json({ success: true, user: user }); 
    } catch (err) {
        console.error(TAG, `❌ Error fetching user profile`, err);
        res.status(500).json({ success: false, message: "Server error." });
    }
});

app.delete('/favorites/:userId/:favoriteId', async (req, res) => {
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
            res.status(404).json({ success: false, message: 'Favorite not found.' });
        }
    } catch (error) {
        console.error(' Error deleting favorite:', error);
        res.status(500).json({ success: false, message: 'Database error.' });
    }
});

app.put('/settings/visibility', async (req, res) => {
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
        console.error(' Error updating visibility:', error);
        res.status(500).json({ success: false, message: 'Database error.' });
    }
});

app.post('/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;
        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long' });
        }
        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            return res.status(400).json({ success: false, message: 'New password must be different' });
        }
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error(' Error changing password:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
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
    console.error(' Error getting online users:', error);
    res.status(500).json({ success: false, message: 'Error fetching online users' });
  }
});

app.get('/api/user-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const onlineData = onlineUsers.get(userId);
    if (onlineData) {
      return res.json({ success: true, userId, isOnline: true, lastSeen: onlineData.lastSeen });
    }
    const [rows] = await db.query('SELECT is_online, last_seen FROM user_presence WHERE user_id = ?', [userId]);
    if (rows.length > 0) {
      res.json({ success: true, userId, isOnline: false, lastSeen: rows[0].last_seen });
    } else {
      res.json({ success: true, userId, isOnline: false, lastSeen: null });
    }
  } catch (error) {
    console.error(' Error checking user status:', error);
    res.status(500).json({ success: false, message: 'Error checking user status' });
  }
});

app.get('/group-members/:groupId', async (req, res) => {
    const TAG = "/group-members/:groupId"; 
    const { groupId } = req.params;
    if (!groupId) {
        return res.status(400).json({ success: false, message: 'Missing group ID' });
    }
    const currentGroupId = parseInt(groupId);
    try {
        const [groupRows] = await db.execute('SELECT group_icon, group_name FROM group_table WHERE group_id = ?', [currentGroupId]);
        if (groupRows.length === 0) {
            return res.status(404).json({ success: false, message: 'Group not found' });
        }
        const [members] = await db.execute(`
            SELECT u.id AS user_id, CONCAT(u.first_name, ' ', u.last_name) as name, u.phone, u.profile_pic
            FROM group_members gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ? ORDER BY u.first_name ASC
        `, [currentGroupId]);
        res.json({ success: true, group_icon: groupRows[0].group_icon, group_name: groupRows[0].group_name, members: members });
    } catch (error) {
        console.error(TAG, `Error fetching group members:`, error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/leaveGroup', async (req, res) => {
    const { userId, groupId } = req.body;
    try {
        await db.query("DELETE FROM group_members WHERE user_id = ? AND group_id = ?", [userId, groupId]);
        
        // Notify others that user left (Optional)
        io.to(`group_${groupId}`).emit('group_notification', { message: `A user has left the group` });
        
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/update-group-icon', upload.single('group_icon'), async (req, res) => {
    const TAG = "/update-group-icon";
    try {
        const groupId = req.body.group_id;
        if (!groupId || !req.file) {
            return res.status(400).json({ success: false, message: 'Missing group ID or file' });
        }
        const cloudinaryUrl = req.file.path;
        const [oldIconRows] = await db.execute('SELECT group_icon FROM group_table WHERE group_id = ?', [groupId]);
        if (oldIconRows.length > 0 && oldIconRows[0].group_icon) {
            try {
                const oldUrl = oldIconRows[0].group_icon;
                const urlParts = oldUrl.split('/');
                const fileName = urlParts[urlParts.length - 1].split('.')[0];
                await cloudinary.uploader.destroy(`${urlParts[urlParts.length - 2]}/${fileName}`);
            } catch (deleteError) {}
        }
        await db.execute('UPDATE group_table SET group_icon = ? WHERE group_id = ?', [cloudinaryUrl, groupId]);
        res.json({ success: true, message: 'Group icon updated', group_icon: cloudinaryUrl });
    } catch (error) {
        console.error(TAG, '❌ Error updating group icon:', error);
        res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
});

app.post('/remove-group-icon', async (req, res) => {
    const TAG = "/remove-group-icon";
    try {
        const { group_id } = req.body;
        if (!group_id) {
            return res.status(400).json({ success: false, message: 'Missing group ID' });
        }
        const [rows] = await db.execute('SELECT group_icon FROM group_table WHERE group_id = ?', [group_id]);
        if (rows.length > 0 && rows[0].group_icon) {
            try {
                const url = rows[0].group_icon;
                const urlParts = url.split('/');
                const fileName = urlParts[urlParts.length - 1].split('.')[0];
                await cloudinary.uploader.destroy(`${urlParts[urlParts.length - 2]}/${fileName}`);
            } catch (deleteError) {}
        }
        await db.execute('UPDATE group_table SET group_icon = NULL WHERE group_id = ?', [group_id]);
        res.json({ success: true, message: 'Group icon removed' });
    } catch (error) {
        console.error(TAG, 'Error removing group icon:', error);
        res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
});

app.get('/group/:groupId/messages', async (req, res) => {
    const TAG = "/group/:groupId/messages";
    try {
        const { groupId } = req.params;
        const { userId } = req.query;

        if (!groupId || !userId) {
            return res.status(400).json({ success: false, message: 'groupId and userId are required' });
        }

        const [memberCheck] = await db.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, userId]);
        if (memberCheck.length === 0) {
            return res.status(403).json({ success: false, message: 'You are not a member of this group' });
        }

        // FETCHING MESSAGES
        // We calculate read status dynamically using subqueries. 
        // IMPORTANT: Added LIMIT 300 to prevent packet overflow on large groups.
        const messagesQuery = `
            SELECT gm.message_id as id, gm.sender_id, gm.message_content as message, gm.timestamp,
                CONCAT(u.first_name, ' ', u.last_name) as sender_name, u.profile_pic as sender_profile_pic,
                
                (SELECT COUNT(DISTINCT gmrs.user_id) 
                 FROM group_message_read_status gmrs 
                 WHERE gmrs.message_id = gm.message_id AND gmrs.user_id != gm.sender_id) as readByCount,
                
                (SELECT COUNT(DISTINCT user_id) FROM group_members WHERE group_id = ?) as totalParticipants,
                
                CASE 
                    WHEN (SELECT COUNT(DISTINCT gmrs.user_id) 
                          FROM group_message_read_status gmrs 
                          WHERE gmrs.message_id = gm.message_id AND gmrs.user_id != gm.sender_id) >= 
                         (SELECT COUNT(DISTINCT user_id) - 1 FROM group_members WHERE group_id = ?) THEN 2
                    WHEN (SELECT COUNT(DISTINCT gmrs.user_id) 
                          FROM group_message_read_status gmrs 
                          WHERE gmrs.message_id = gm.message_id AND gmrs.user_id != gm.sender_id) > 0 THEN 1
                    ELSE 0
                END as status,
                
                EXISTS(SELECT 1 FROM group_message_read_status gmrs WHERE gmrs.message_id = gm.message_id AND gmrs.user_id = ?) as isReadByCurrentUser
            
            FROM group_messages gm 
            JOIN users u ON gm.sender_id = u.id 
            WHERE gm.group_id = ? 
            ORDER BY gm.timestamp ASC
            LIMIT 300
        `;

        // FIXED: The array below now has 4 items to match the 4 '?' in the query above.
        // 1. group_id (totalParticipants)
        // 2. group_id (status CASE)
        // 3. userId (isReadByCurrentUser)
        // 4. groupId (Main WHERE)
        const [messages] = await db.execute(messagesQuery, [groupId, groupId, userId, groupId]);

        const decryptedMessages = messages.map(msg => {
            try {
                return { 
                    ...msg, 
                    message: decrypt(msg.message), 
                    isReadByCurrentUser: Boolean(msg.isReadByCurrentUser), 
                    readByCount: parseInt(msg.readByCount || 0), 
                    status: parseInt(msg.status || 0), 
                    totalParticipants: parseInt(msg.totalParticipants || 0) 
                };
            } catch (decryptError) {
                return { ...msg, message: '[Encrypted Message]', status: 0 };
            }
        });

        res.json({ success: true, messages: decryptedMessages });

    } catch (error) {
        console.error(TAG, '❌ Error fetching group messages:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/updateGroupMessageStatus', async (req, res) => {
    res.json({ success: true, message: 'Status update not needed with real-time calculation' });
});

app.post('/group/send', async (req, res) => {
    const { senderId, groupId, content } = req.body;
    const TAG = '/group/send';
    if (!senderId || !groupId || !content) return res.status(400).json({ success: false, message: 'Missing fields' });

    try { await db.execute(`INSERT IGNORE INTO group_members (user_id, group_id, joined_at) VALUES (?, ?, NOW())`, [senderId, groupId]); } catch (e) {}

    try {
        const encryptedMessage = encrypt(content);
        const [result] = await db.execute(`INSERT INTO group_messages (group_id, sender_id, message_content, timestamp) VALUES (?, ?, ?, NOW())`, [groupId, senderId, encryptedMessage]);
        const newMessageId = result.insertId;
        const [insertedMsg] = await db.query(`SELECT gm.message_id as id, gm.sender_id, gm.message_content, gm.timestamp, CONCAT(u.first_name, ' ', u.last_name) as sender_name FROM group_messages gm 
JOIN users u ON gm.sender_id = u.id WHERE gm.message_id = ?`, [newMessageId]);
        
        if (insertedMsg.length > 0) {
            const msg = insertedMsg[0];
            io.to(`group_${groupId}`).emit('new_group_message', { ...msg, message: content, readByCount: 0, status: 0 });
        }

        try {
            const [groupMembers] = await db.query(`SELECT u.id, u.fcm_token FROM group_members gm JOIN users u ON gm.user_id = u.id WHERE gm.group_id = ? AND u.id != ? AND u.fcm_token IS NOT NULL`, 
[groupId, senderId]);
            const [senderInfo] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [senderId]);
            const senderName = senderInfo[0]?.name || "Someone";

            for (const member of groupMembers) {
                const memberActiveChat = activeChatSessions.get(member.id.toString());
                if (memberActiveChat === `group_${groupId}`) continue;

                await admin.messaging().send({
                    token: member.fcm_token,
                    notification: { title: `${senderName} in group`, body: content },
                    android: { priority: "high", notification: { channelId: "channel_custom_sound_v2", sound: "custom_notification", priority: "high", defaultSound: false } },
                    data: { type: "group_chat", groupId: groupId.toString(), senderId: senderId.toString(), senderName: senderName }
                });
            }
        } catch (e) {}

        res.json({ success: true, message: 'Message sent', messageId: newMessageId });
    } catch (error) {
        console.error(TAG, `Error sending group message:`, error);
        res.status(500).json({ success: false, message: 'Failed to send message' });
    }
});

app.get('/group/:groupId/members', async (req, res) => {
    const TAG = "/group/:groupId/members";
    const { groupId } = req.params;
    if (!groupId) return res.status(400).json({ success: false });
    try {
        const [members] = await db.execute(`SELECT u.id, u.id as userId, CONCAT(u.first_name, ' ', u.last_name) as name, u.profile_pic as profilePic FROM users u JOIN group_members gm ON u.id = 
gm.user_id WHERE gm.group_id = ? ORDER BY u.first_name ASC`, [groupId]);
        res.json({ success: true, members: members });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/group/read', async (req, res) => {
    const { user_id, group_id } = req.body;
    if (!user_id || !group_id) return res.status(400).json({ success: false });
    try {
        const query = `INSERT INTO group_message_read_status (message_id, user_id, group_id) SELECT gm.message_id, ?, gm.group_id FROM group_messages gm WHERE gm.group_id = ? AND NOT EXISTS (SELECT 
1 FROM group_message_read_status gmrs WHERE gmrs.message_id = gm.message_id AND gmrs.user_id = ?)`;
        const [result] = await db.execute(query, [user_id, group_id, user_id]);
        res.json({ success: true, newReadCount: result.affectedRows });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.get('/searchUsers', async (req, res) => {
    const { query, currentUserId } = req.query;
    try {
        const sql = `
            SELECT 
                u.id, 
                CONCAT(u.first_name, ' ', u.last_name) as name, 
                u.college, 
                u.profile_pic,
                u.gender, -- ADDED GENDER HERE
                EXISTS (
                    SELECT 1 FROM messages m 
                    WHERE (m.sender_id = ? AND m.receiver_id = u.id) 
                       OR (m.sender_id = u.id AND m.receiver_id = ?)
                ) as hasChat
            FROM users u 
            WHERE (u.first_name LIKE ? OR u.last_name LIKE ?) AND u.id != ?
            LIMIT 20
        `;
        
        const [users] = await db.execute(sql, [
            currentUserId, 
            currentUserId, 
            `%${query}%`, 
            `%${query}%`, 
            currentUserId
        ]);

        // Include gender in the mapped response
        const usersWithBoolean = users.map(u => ({
            ...u,
            hasChat: Boolean(u.hasChat)
        }));

        res.json({ success: true, users: usersWithBoolean });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Search failed' });
    }
});

app.post('/sendChatRequest', async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        await connection.execute(`INSERT INTO chat_requests (sender_id, receiver_id, status) VALUES (?, ?, 'pending') ON DUPLICATE KEY UPDATE status = status`, [senderId, receiverId]);
        const encryptedMsg = encrypt(message);
        const [msgResult] = await connection.execute(`INSERT INTO messages (sender_id, receiver_id, message, timestamp, status) VALUES (?, ?, ?, UTC_TIMESTAMP(), 0)`, [senderId, receiverId, 
encryptedMsg]);
        await connection.commit();
        io.to(`chat_${receiverId}`).emit('new_chat_request', { requestId: msgResult.insertId, senderId, message });
        res.json({ success: true });
    } catch (err) {
        await connection.rollback();
        res.status(500).json({ success: false });
    } finally {
        connection.release();
    }
});

app.get('/chatRequests', async (req, res) => {
    const { userId } = req.query;
    try {
        const sql = `SELECT cr.id as requestId, u.id as userId, CONCAT(u.first_name, ' ', u.last_name) as name, u.profile_pic, u.college, (SELECT message FROM messages m WHERE m.sender_id = u.id AND 
m.receiver_id = ? ORDER BY m.timestamp DESC LIMIT 1) as lastMessage FROM chat_requests cr JOIN users u ON cr.sender_id = u.id WHERE cr.receiver_id = ? AND cr.status = 'pending'`;
        const [requests] = await db.execute(sql, [userId, userId]);
        const decrypted = requests.map(r => ({ ...r, lastMessage: r.lastMessage ? decrypt(r.lastMessage) : "Sent a message" }));
        res.json({ success: true, requests: decrypted });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post('/handleChatRequest', async (req, res) => {
    const { userId, otherUserId, action } = req.body;
    try {
        if (action === 'accept') {
            await db.execute(`UPDATE chat_requests SET status = 'accepted' WHERE sender_id = ? AND receiver_id = ?`, [otherUserId, userId]);
            res.json({ success: true });
        } else {
            const connection = await db.getConnection();
            await connection.beginTransaction();
            await connection.execute(`DELETE FROM chat_requests WHERE sender_id = ? AND receiver_id = ?`, [otherUserId, userId]);
            await connection.execute(`DELETE FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)`, [otherUserId, userId, userId, otherUserId]);
            await connection.commit();
            connection.release();
            res.json({ success: true });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/chatRequests/count', async (req, res) => {
    const { userId } = req.query;
    try {
        const sql = `SELECT COUNT(*) as count FROM chat_requests WHERE receiver_id = ? AND status = 'pending'`;
        const [rows] = await db.execute(sql, [userId]);
        res.json({ success: true, count: rows[0].count });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.use(router);

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server listening on port ${PORT}`);
});
