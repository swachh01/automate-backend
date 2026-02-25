require("dotenv").config();
const express = require("express");
const app = express();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const activeChatSessions = new Map();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs'); 
const admin = require("firebase-admin");
const axios = require('axios');
const { parsePhoneNumberFromString } = require('libphonenumber-js');

let serviceAccount;

try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        // Use environment variable if available
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
        // Fallback to local file for development
        serviceAccount = require("./firebase-service-account.json");
    }

    // Check if Firebase is already initialized to prevent the "Already Exists" crash
    if (!admin.apps.length) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log("Firebase Admin initialized successfully.");
    } else {
        admin.app(); // Reuse the existing app instance
        console.log("Firebase Admin already initialized, reusing existing app.");
    }
} catch (e) {
    console.error("CRITICAL: Firebase Admin failed to initialize:", e.message);
    // On Cloud Run, we log the error but don't want to crash the whole server 
    // unless Firebase is absolutely mandatory for the server to even start.
}

// NOTE: DO NOT add another admin.initializeApp call here! 
// The logic above handles everything.

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per 15 minutes
    message: { 
        success: false, 
        message: "Too many attempts from this IP, please try again after 15 minutes" 
    },
    standardHeaders: true, 
    legacyHeaders: false,
});

const authenticateToken = (req, res, next) => {
    // Look for token in the 'Authorization' header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ success: false, message: "Access Denied: No Token Provided" });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // This contains the userId from the token
        next(); // Proceed to the actual route logic
    } catch (err) {
        res.status(403).json({ success: false, message: "Invalid or Expired Token" });
    }
};

const cors = require("cors");
const path = require("path");
const { encrypt, decrypt } = require('./cryptoHelper');
const fs = require("fs");
const multer = require("multer");
const mysql = require("mysql2");

const http = require('http');
const { Server } = require('socket.io');

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
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.DB_PORT || 4000, 
  ssl: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: false
  },
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
    console.error('Database connection failed:', err.message);
  } else {
    console.log('Database connected successfully');
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
    console.error('Error updating user presence:', error);
  }
}


io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('user_online', async (userId) => {
    try {
        onlineUsers.set(userId.toString(), {
            socketId: socket.id,
            lastSeen: new Date(),
            isOnline: true
        });
        await updateUserPresence(userId, true);
        
        socket.join(`chat_${userId}`);
        console.log(`User ${userId} joined private chat room: chat_${userId}`);
        
        socket.broadcast.emit('user_status_changed', {
            userId: userId.toString(),
            isOnline: true,
            lastSeen: new Date()
        });
    } catch (error) {
        console.error('Error handling user_online:', error);
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
        activeChatSessions.delete(disconnectedUserId.toString());
        await updateUserPresence(disconnectedUserId, false);
        socket.broadcast.emit('user_status_changed', {
          userId: disconnectedUserId,
          isOnline: false,
          lastSeen: new Date()
        });
      }
    } catch (error) {
      console.error('Error handling disconnect:', error);
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

// --- REPLACE THIS BLOCK ---
socket.on('join_group', (groupId) => {
    try {
        if (!groupId) return;
        const roomName = `group_${groupId}`; // Define the variable here
        socket.join(roomName);
        console.log(`Socket ${socket.id} joined room: ${roomName}`);
    } catch (err) {
        console.error("Error in join_group socket:", err);
    }
});

socket.on('leave_group', (groupId) => {
    try {
        if (!groupId) return;
        const roomName = `group_${groupId}`;
        socket.leave(roomName);
        console.log(`Socket ${socket.id} left room: ${roomName}`);
    } catch (err) {
        console.error("Error in leave_group socket:", err);
    }
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
        const { groupId, userId } = data;
        
        // Fetch updated stats for ALL recent messages in this group
        const [recentMessages] = await db.query(`
            SELECT 
                gm.message_id,
                COUNT(DISTINCT gmrs.user_id) as readByCount,
                ((SELECT COUNT(*) FROM group_members WHERE group_id = ?) - 1) as totalParticipants,
                (SELECT GROUP_CONCAT(DISTINCT u.first_name SEPARATOR ', ')
                 FROM group_message_read_status gmrs2
                 JOIN users u ON gmrs2.user_id = u.id
                 WHERE gmrs2.message_id = gm.message_id AND gmrs2.user_id != gm.sender_id) as readByNames
            FROM group_messages gm
            LEFT JOIN group_message_read_status gmrs ON gm.message_id = gmrs.message_id AND gmrs.user_id != gm.sender_id
            WHERE gm.group_id = ?
            AND gm.timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY gm.message_id
        `, [groupId, groupId]);
        
        // Broadcast the update with names and counts to everyone in the group
        io.to(`group_${groupId}`).emit('group_messages_read', {
            groupId: groupId,
            updatedCounts: recentMessages
        });
        
    } catch (error) {
        console.error('Error handling group_read:', error);
    }
});

  socket.on('update_live_location', (data) => {
  const { senderId, receiverId, lat, lng, type } = data;
  
  // Relay the update (location OR stop signal) to the receiver
  socket.to(`chat_${receiverId}`).emit('update_live_location', {
    senderId,
    lat,
    lng,
    type: type,
    targetType: 'individual'
  });

  if (type === 'stop_sharing') {
      console.log(`User ${senderId} stopped sharing with ${receiverId}`);
  }
});

  socket.on('update_group_live_location', (data) => {
    const { senderId, groupId, lat, lng, type } = data;
    
    // Relay to the group room
    socket.to(`group_${groupId}`).emit('group_live_location_update', {
      senderId,
      groupId,
      lat,
      lng,
      type: type || 'live_update'
    });

    if (type === 'stop_sharing') {
        console.log(`[GROUP] User ${senderId} stopped sharing in Group ${groupId}`);
    }
});

// ADD THIS: Backup listener in case your Java code uses the other name
socket.on('update_live_location_group', (data) => {
    const { senderId, groupId, lat, lng, type } = data;
    socket.to(`group_${groupId}`).emit('group_live_location_update', {
        senderId,
        groupId,
        lat,
        lng,
        type: type || 'live_update'
    });
});
}); 

async function getUserByPhone(phone) {
  try {
    const [rows] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as name, work_category, phone, gender, dob, work_detail, profile_pic FROM users WHERE phone = ?`,
      [phone]
    );
    return rows && rows[0] ? rows[0] : null;
  } catch (error) {
    console.error("Error in getUserByPhone:", error);
    return null;
  }
}

function normalizePhoneData(phone, countryCode) {
    // 1. Check if either is missing to prevent crashes
    if (!phone || !countryCode) {
        return { phone: phone || "", country_code: countryCode || "", isValid: false };
    }

    try {
        // 2. FIXED: Use countryCode (the parameter name) consistently
        const dialCode = countryCode.startsWith('+') ? countryCode : `+${countryCode}`;
        
        // Strip non-digits from the phone number
        const cleanPhone = phone.replace(/\D/g, '');
        const fullNumber = dialCode + cleanPhone;
        
        const phoneNumber = parsePhoneNumberFromString(fullNumber);
        
        if (phoneNumber && phoneNumber.isValid()) {
            return {
                phone: phoneNumber.nationalNumber, // e.g., "8850260443"
                country_code: `+${phoneNumber.countryCallingCode}`, // e.g., "+91"
                isValid: true
            };
        }
    } catch (e) {
        console.error("Normalization error:", e.message);
    }

    // 3. Fallback: If parsing fails, still return clean digits
    return {
        phone: phone.replace(/\D/g, ''),
        country_code: countryCode,
        isValid: false
    };
}

app.get("/health", async (_req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: "OK", timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("Health check failed:", err);
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

app.post("/create-account", authLimiter, async (req, res) => {
    const TAG = "/create-account";
    try {
        const { first_name, last_name, work_category, work_detail, gender, phone, country_code, password } = req.body;

        if (!first_name || !last_name || !work_category || !work_detail || !gender || !phone || !country_code || !password) {
            return res.status(400).json({ success: false, message: "All fields are required." });
        }

        if (password.length < 7 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
            return res.status(400).json({ success: false, message: "Password must be at least 7 characters and include letters, numbers, and symbols." });
        }

        // Normalize data to ensure clean DB entries
        const normalized = normalizePhoneData(phone, country_code);
        const finalPhone = normalized.phone;
        const finalCountryCode = normalized.country_code;

        console.log(TAG, `Attempting to create account for phone: ${finalCountryCode}${finalPhone}`);

        // Check if user exists using parameterized query
        const [existingUser] = await db.query(
            `SELECT id, signup_status FROM users WHERE phone = ? AND country_code = ?`,
            [finalPhone, finalCountryCode]
        );

        if (existingUser.length > 0 && existingUser[0].signup_status === 'completed') {
            return res.status(409).json({ success: false, message: "A user with this phone number already exists." });
        }
        
        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const query = `
            INSERT INTO users (first_name, last_name, work_category, work_detail, gender, phone, country_code, password, signup_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW())
            ON DUPLICATE KEY UPDATE
                first_name = VALUES(first_name),
                last_name = VALUES(last_name),
                work_category = VALUES(work_category),
                work_detail = VALUES(work_detail),
                gender = VALUES(gender),
                password = VALUES(password),
                signup_status = 'pending',
                updated_at = NOW();
        `;
        
        await db.query(query, [first_name, last_name, work_category, work_detail, gender, finalPhone, finalCountryCode, hashedPassword]);
        
        const [userRows] = await db.query(
            `SELECT 
                id, 
                CONCAT(first_name, ' ', last_name) as name, 
                work_category, 
                phone, 
                gender, 
                dob, 
                work_detail, 
                profile_pic,
                COALESCE(bio, '') as bio,
                COALESCE(home_location, '') as home_location
            FROM users 
            WHERE phone = ? AND country_code = ?`,
            [finalPhone, finalCountryCode]
        );
        
        if (userRows.length === 0) {
             return res.status(500).json({ success: false, message: "Failed to create account." });
        }
        
        const newUser = userRows[0];

        // NEW: Generate a short-lived token specifically for completing registration
        const token = jwt.sign(
            { userId: newUser.id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.status(201).json({
            success: true,
            message: "Account created successfully. Please complete your profile.",
            token: token, // Added token to response
            user: newUser
        });

    } catch (err) {
        console.error(TAG, "Error in /create-account:", err);
        res.status(500).json({ 
            success: false, 
            message: "Server error during account creation.",
            error: err.message
        });
    }
});

app.get("/check-phone-availability", async (req, res) => {
    const TAG = "/check-phone-availability";
    const { phone, country_code } = req.query;

    if (!phone || !country_code) {
        return res.status(400).json({ success: false, message: "Phone and country code required." });
    }

    // Normalize to ensure we search for the clean version
    const normalized = normalizePhoneData(phone, country_code);

    try {
        const [rows] = await db.query(
            `SELECT id FROM users WHERE phone = ? AND country_code = ? AND signup_status = 'completed'`,
            [normalized.phone, normalized.country_code]
        );

        if (rows.length > 0) {
            return res.json({ available: false, message: "This mobile number is already linked with another account." });
        } else {
            return res.json({ available: true });
        }
    } catch (err) {
        console.error(TAG, "Error checking availability:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/debug/check-user", async (req, res) => {
    const { phone, country_code } = req.query;
    
    try {
        const [exact] = await db.query(
            `SELECT id, phone, country_code, signup_status, 
                    CHAR_LENGTH(phone) as phone_length, 
                    CHAR_LENGTH(country_code) as code_length,
                    HEX(phone) as phone_hex,
                    HEX(country_code) as code_hex
             FROM users 
             WHERE phone = ? AND country_code = ?`,
            [phone, country_code]
        );
        
        const [withStatus] = await db.query(
            `SELECT id, phone, country_code, signup_status 
             FROM users 
             WHERE phone = ? AND country_code = ? AND signup_status = 'completed'`,
            [phone, country_code]
        );
        
        const [allWithPhone] = await db.query(
            `SELECT id, phone, country_code, signup_status 
             FROM users 
             WHERE phone = ?`,
            [phone]
        );
        
        res.json({
            searchedFor: { phone, country_code },
            exactMatch: exact,
            withCompletedStatus: withStatus,
            allWithThisPhone: allWithPhone
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ================= LOGIN =================

// Apply authLimiter to prevent brute force
app.post("/login", authLimiter, async (req, res) => {
  const { phone, password, country_code } = req.body || {}; 
  
  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Missing phone or password` });
  }

  // Normalize the incoming phone number
  let finalPhone = phone.replace(/\D/g, '');
  let query = "";
  let queryParams = [];

  if (country_code) {
      const normalized = normalizePhoneData(phone, country_code);
      finalPhone = normalized.phone;
      query = `SELECT 
        id, 
        CONCAT(first_name, ' ', last_name) as name, 
        work_category, 
        phone, 
        gender, 
        dob, 
        work_detail, 
        profile_pic, 
        password, 
        signup_status,
        COALESCE(bio, '') as bio,
        COALESCE(home_location, '') as home_location,
        home_lat,
        home_lng
       FROM users WHERE phone = ? AND country_code = ?`;
      queryParams = [finalPhone, normalized.country_code];
  } else {
      query = `SELECT 
        id, 
        CONCAT(first_name, ' ', last_name) as name, 
        work_category, 
        phone, 
        gender, 
        dob, 
        work_detail, 
        profile_pic, 
        password, 
        signup_status,
        COALESCE(bio, '') as bio,
        COALESCE(home_location, '') as home_location,
        home_lat,
        home_lng
       FROM users WHERE phone = ?`;
      queryParams = [finalPhone];
  }

  try {
    const [rows] = await db.query(query, queryParams);

    if (!rows.length) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }
    
    const user = rows[0];

    if (user.signup_status === 'pending') {
        return res.status(403).json({ 
            success: false, 
            message: "Profile incomplete. Please finish setup.",
            isPending: true,
            userId: user.id
        });
    }

    let isPasswordValid = false;

    // SECURED: Check if password is encrypted (bcrypt)
    if (user.password && user.password.startsWith('$2')) {
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      // If the password in DB is plain text (Legacy), we compare and then immediately hash it
      if (user.password === password) {
        isPasswordValid = true;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        // Auto-upgrade legacy password to bcrypt for future security
        await db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);
      }
    }

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: `Invalid credentials` });
    }
    

    const token = jwt.sign(
    { userId: user.id }, 
    process.env.JWT_SECRET, 
    { expiresIn: '30d' } // Token lasts for 30 days
);

    delete user.password;
    
    res.json({ success: true, message: "Login successful", token: token,user: user }); 

  } catch (err) {
    console.error("/login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Add authenticateToken between the path and the logic
app.post("/updateProfile", authenticateToken, upload.single("profile_pic"), async (req, res) => {
  try {
    console.log("=== Update Profile Request ===");
    const { userId, dob, bio, home_location, home_lat, home_lng } = req.body || {};

    if (!userId) {
      return res.status(400).json({ success: false, message: "Missing userId" });
    }

    if (parseInt(userId) !== req.user.userId) {
        return res.status(403).json({ 
            success: false, 
            message: "Unauthorized: You can only update your own profile." 
        });
    }

    const sets = [];
    const params = [];

    // 1. Define a strict whitelist of updateable fields
    // This ensures that even if more data is sent in req.body, 
    // only these specific columns can ever be touched.
    const updates = {
      dob: dob,
      bio: bio,
      home_location: home_location,
      home_lat: home_lat,
      home_lng: home_lng
    };

    // 2. Safely build the query parts
    for (const [column, value] of Object.entries(updates)) {
      if (value !== undefined && value !== null) {
        sets.push(`\`${column}\` = ?`); // Use backticks for column names
        params.push(value);
      }
    }
    
    // 3. Handle the file upload separately (also safe)
    if (req.file && req.file.path) {
      sets.push("`profile_pic` = ?");
      params.push(req.file.path);
    }

    if (sets.length === 0) {
      return res.status(400).json({ success: false, message: "Nothing to update" });
    }

    // 4. Construct the final SQL. 
    // Since 'sets' only contains values we explicitly pushed, it's now secure.
    const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
    params.push(userId);

    const [result] = await db.query(sql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Mark signup as completed
    await db.query("UPDATE users SET signup_status = 'completed' WHERE id = ?", [userId]);

    // Fetch updated user data
    const [rows] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) as name, work_category, 
              work_detail, phone, gender, dob, bio, home_location, 
              home_lat, home_lng, profile_pic, signup_status
       FROM users WHERE id = ?`,
      [userId]
    );

    res.json({
      success: true,
      message: "Profile updated and signup complete!",
      user: rows[0]
    });

  } catch (err) {
    console.error("=== /updateProfile ERROR ===", err);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

//==============================================ADD TRAVEL PLAN=========================================================

app.post("/addTravelPlan", async (req, res) => {
    const TAG = "/addTravelPlan"; 
    let connection; 

    try {
        // Destructure 'landmark' from req.body
        const { userId, fromPlace, toPlace, time, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng, landmark } = req.body;

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

        // Updated Query: Added 'landmark' column and value placeholder
        const planQuery = `
          INSERT INTO travel_plans
            (user_id, from_place, to_place, time, status,
             from_place_lat, from_place_lng, to_place_lat, to_place_lng,
             landmark, created_at, updated_at)
          VALUES (?, ?, ?, ?, 'Trip Active', ?, ?, ?, ?, ?, NOW(), NOW());
        `;
        
        // Pass 'landmark' (or null) to the query
        const [planResult] = await connection.query(planQuery, [
            userId, fromPlace, toPlace, formattedTime,
            fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng,
            landmark || null
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

        // Notification logic remains the same...
        try {
            const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
            const joinerName = userRows.length > 0 ? userRows[0].name : "Someone";

            const [matchingUsers] = await connection.query(`
                SELECT DISTINCT u.fcm_token 
                FROM travel_plans tp
                JOIN users u ON tp.user_id = u.id
                WHERE tp.to_place = ? 
                  AND tp.status = 'Trip Active'
                  AND tp.user_id != ? 
                  AND u.fcm_token IS NOT NULL
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
                            channelId: "channel_custom_sound_v3",
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
            console.error(TAG, "Error sending travel match notification:", notifyError.message);
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
        console.error(TAG, `Error saving travel plan:`, err);
        res.status(500).json({ success: false, message: "Server error occurred." });
    } finally {
        if (connection) { connection.release(); }
    }
});

app.post("/addCabTravelPlan", async (req, res) => {
    const TAG = "/addCabTravelPlan";
    let connection;

    try {
        // Included estimatedFare in the destructured request body
        const { userId, companyName, time, pickup, destination, landmark, estimatedFare } = req.body;

        if (!userId || !destination || !time || !companyName) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        // Validate and format date for MySQL
        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) { throw new Error("Invalid date"); }
        } catch (e) {
            return res.status(400).json({ success: false, message: "Invalid time format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        // 1. Insert into Cab Plans table (Added estimated_fare column and value)
        const query = `INSERT INTO travel_plans_cab (user_id, company_name, travel_datetime, pickup_location, destination, landmark, status, estimated_fare) 
                       VALUES (?, ?, ?, ?, ?, ?, 'Trip Active', ?)`;
        const [cabResult] = await connection.query(query, [userId, companyName, formattedTime, pickup, destination, landmark, estimatedFare || 0.00]);

        // 2. Group Logic
        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; 
        await connection.query(groupQuery, [destination]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [destination]);
        const groupId = groupRows.length > 0 ? groupRows[0].group_id : null;

        if (groupId) {
            const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
            await connection.query(memberQuery, [groupId, userId]);
        }

        await connection.commit();

        // 3. Notification Logic
        try {
            const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
            const joinerName = userRows.length > 0 ? userRows[0].name : "A traveler";

            const [matchingUsers] = await connection.query(`
                SELECT DISTINCT u.fcm_token 
                FROM travel_plans_cab tp
                JOIN users u ON tp.user_id = u.id
                WHERE tp.destination = ? 
                  AND tp.status = 'Trip Active'
                  AND tp.user_id != ? 
                  AND u.fcm_token IS NOT NULL
                  AND u.trip_alerts_enabled = 1
            `, [destination, userId]);

            if (matchingUsers.length > 0) {
                const tokens = matchingUsers.map(u => u.fcm_token).filter(t => t);
                const messagePayload = {
    tokens: tokens,
    notification: {
        title: "New Cab Buddy!",
        body: `${joinerName} is also taking a cab to ${destination}!`
    },
    android: {
        priority: "high",
        notification: {
            channelId: "channel_custom_sound_v3", // REQUIRED for Android 8+
            priority: "high",
            defaultSound: true
        }
    },
    data: {
        type: "travel_match",
        destinationName: String(destination),
        commuteType: "Cab"
    }
};
                await admin.messaging().sendEachForMulticast(messagePayload);
            }
        } catch (notifyError) {
            console.error(TAG, "Notification Error: " + notifyError.message);
        }

        res.status(201).json({ 
            success: true, 
            message: "Cab plan saved successfully",
            id: cabResult.insertId 
        });

    } catch (err) {
        if (connection) await connection.rollback();
        console.error(TAG, "Error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    } finally {
        if (connection) connection.release();
    }
});

//==========================================================================OWN VEHICLE PLAN=========================================================================================
app.post("/addOwnVehiclePlan", async (req, res) => {
    const TAG = "/addOwnVehiclePlan";
    let connection;

    try {
        // Updated destructuring to include landmark and estimatedFare
        const { userId, vehicleType, vehicleNumber, pickup, destination, time, landmark, estimatedFare } = req.body;

        if (!userId || !destination || !time || !vehicleNumber || !vehicleType) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        // Validate and format date
        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) throw new Error("Invalid date");
        } catch (e) {
            return res.status(400).json({ success: false, message: "Invalid time format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        // 1. Insert into Own Vehicle Plans table (Added landmark and estimated_fare)
        const query = `INSERT INTO travel_plans_own (user_id, vehicle_type, vehicle_number, pickup_location, destination, travel_time, landmark, estimated_fare, status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Trip Active')`;
        
        const [ownResult] = await connection.query(query, [
            userId, 
            vehicleType, 
            vehicleNumber, 
            pickup, 
            destination, 
            formattedTime, 
            landmark || null, 
            estimatedFare || 0.00
        ]);

        // 2. Group Logic (Auto create/join destination group)
        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; 
        await connection.query(groupQuery, [destination]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [destination]);
        const groupId = groupRows.length > 0 ? groupRows[0].group_id : null;

        if (groupId) {
            const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
            await connection.query(memberQuery, [groupId, userId]);
        }

        await connection.commit();

        // 3. Notification Logic (FCM)
        try {
            const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
            const joinerName = userRows.length > 0 ? userRows[0].name : "A traveler";

            const [matchingUsers] = await connection.query(`
                SELECT DISTINCT u.fcm_token 
                FROM travel_plans_own tp
                JOIN users u ON tp.user_id = u.id
                WHERE tp.destination = ? 
                  AND tp.status = 'Trip Active'
                  AND tp.user_id != ? 
                  AND u.fcm_token IS NOT NULL
                  AND u.trip_alerts_enabled = 1
            `, [destination, userId]);

            if (matchingUsers.length > 0) {
                const tokens = matchingUsers.map(u => u.fcm_token).filter(t => t);
                const messagePayload = {
    tokens: tokens,
    notification: {
        title: "New Travel Buddy!",
        body: `${joinerName} is driving to ${destination}!`
    },
    android: {
        priority: "high",
        notification: {
            channelId: "channel_custom_sound_v3",
            priority: "high",
            defaultSound: true
        }
    },
    data: {
        type: "travel_match",
        destinationName: String(destination),
        commuteType: "Own"
    }
};
                await admin.messaging().sendEachForMulticast(messagePayload);
            }
        } catch (notifyError) {
            console.error(TAG, "Notification Error: " + notifyError.message);
        }

        res.status(201).json({ 
            success: true, 
            message: "Own vehicle plan saved successfully",
            id: ownResult.insertId 
        });

    } catch (err) {
        if (connection) await connection.rollback();
        console.error(TAG, "Error:", err);
        res.status(500).json({ success: false, message: "Server error" });
    } finally {
        if (connection) connection.release();
    }
});

app.get("/travel-plans/destinations-by-type", async (req, res) => {
    const { userId, commuteType } = req.query;

    let tableName;
    let destinationCol;
    let statusFilter = "status = 'Trip Active'";

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        destinationCol = 'destination';
        statusFilter = "status = 'Trip Active' AND travel_datetime > NOW()";
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        destinationCol = 'destination';
        statusFilter = "status = 'Trip Active' AND travel_time > NOW()";
    } else {
        tableName = 'travel_plans';
        destinationCol = 'to_place'; 
        statusFilter = "status = 'Trip Active' AND time > NOW()";
    }
    
    try {
        const query = `
            SELECT 
                ${destinationCol} as destination, 
                COUNT(*) as userCount,
                SUM(CASE WHEN tp.user_id = ? THEN 1 ELSE 0 END) > 0 AS isCurrentUserGoing,
                g.group_id  -- ← Get the REAL group_id from group_table
            FROM ${tableName} tp
            LEFT JOIN \`group_table\` g ON g.group_name = tp.${destinationCol}
            WHERE ${statusFilter}
            GROUP BY tp.${destinationCol}, g.group_id
            ORDER BY userCount DESC
        `;

        const [destinations] = await db.query(query, [userId]);
        const formattedDestinations = destinations.map(d => ({
            groupId: d.group_id,  // ← Use real group_id, not index+100
            destination: d.destination,
            userCount: d.userCount,
            isCurrentUserGoing: d.isCurrentUserGoing
        }));

        res.json({ success: true, destinations: formattedDestinations });
    } catch (err) {
        console.error("Error fetching filtered destinations:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }

});

app.get('/users/destination', async (req, res) => {
    const TAG = "/users/destination";
    const { groupId, userId, commuteType, destinationName } = req.query;

    if (!userId || (!groupId && !destinationName)) {
        return res.status(400).json({ success: false, message: 'Missing required parameters' });
    }

    const currentUserId = parseInt(userId);
    let tableName = 'travel_plans';
    let fromCol = 'from_place';
    let toCol = 'to_place';
    let extraCols = ", tp.landmark, NULL as companyName, NULL as fare";
    let timeSelection = "DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z')";

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        fromCol = 'pickup_location';
        toCol = 'destination';
        // Aliased estimated_fare as 'fare' for the Android Model
        extraCols = ", tp.landmark, tp.company_name as companyName, tp.estimated_fare as fare";
        timeSelection = "DATE_FORMAT(tp.travel_datetime, '%Y-%m-%dT%H:%i:%s.000Z')";
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        fromCol = 'pickup_location';
        toCol = 'destination';
        extraCols = ", tp.landmark, tp.vehicle_type as companyName, tp.estimated_fare as fare";
        timeSelection = "DATE_FORMAT(tp.travel_time, '%Y-%m-%dT%H:%i:%s.000Z')";
    }

    try {
        // Fetch friends to determine profile visibility
        const [friendRows] = await db.query(
            `SELECT DISTINCT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id 
             FROM messages WHERE sender_id = ? OR receiver_id = ?`,
            [currentUserId, currentUserId, currentUserId]
        );
        const friendIds = new Set(friendRows.map(row => row.friend_id));

        let finalDestName = destinationName;
        if (!finalDestName && groupId) {
            const [groupRows] = await db.query("SELECT group_name FROM group_table WHERE group_id = ?", [groupId]);
            if (groupRows.length > 0) finalDestName = groupRows[0].group_name;
        }

        if (!finalDestName) {
            return res.status(404).json({ success: false, message: 'Destination not identified' });
        }

        const query = `
            SELECT
                u.id,           
                u.id as userId, 
                CONCAT(u.first_name, ' ', u.last_name) as name,
                u.work_category,
                u.work_detail,
                u.profile_pic AS profilePic,
                u.gender,
                u.profile_visibility,
                ${timeSelection} as time,
                tp.${fromCol} AS fromPlace, 
                tp.${toCol} AS toPlace
                ${extraCols}
            FROM ${tableName} tp
            JOIN users u ON tp.user_id = u.id
            WHERE
                tp.${toCol} = ?
                AND tp.status = 'Trip Active' 
                AND tp.user_id != ?   
            ORDER BY
                tp.created_at DESC
        `;

        const [users] = await db.execute(query, [finalDestName, currentUserId]);

        const responseUsers = users.map(user => ({
            ...user,
            commuteType: commuteType,
            profilePic: getVisibleProfilePic(
                { ...user, profile_pic: user.profilePic, user_id: user.id },
                currentUserId,
                friendIds
            )
        }));

        res.json({ success: true, users: responseUsers });

    } catch (error) {
        console.error(TAG, "Error fetching users:", error);
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
        u.work_category,
        u.gender,
        u.profile_pic
      FROM travel_plans tp
      JOIN users u ON tp.user_id = u.id  
      WHERE tp.user_id = ? 
        AND tp.time > UTC_TIMESTAMP() 
        AND tp.status = 'Trip Active'
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
message: decrypt(msg.message)
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
    const { 
      sender_id, 
      receiver_id, 
      message, 
      message_type, 
      latitude, 
      longitude, 
      duration,
      reply_to_id,
      quoted_message,
      quoted_user_name
    } = req.body;

    // ENHANCED LOGGING
    console.log(TAG, 'Received message:', {
      sender_id,
      receiver_id,
      message_type,
      has_lat: !!latitude,
      has_lng: !!longitude,
      duration,
      reply_to_id,
      has_quoted: !!quoted_message
    });


    if (parseInt(sender_id) !== req.user.userId) {
        return res.status(403).json({ 
            success: false, 
            message: 'Unauthorized: You cannot send messages as another user.' 
        });
    }

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
    
    const type = message_type || 'text';
    let expiresAt = null;

    // Calculate expires_at for location messages with duration
    if ((type === 'location' || type === 'live_location') && duration) {
    if (parseInt(duration) === -1) {
        // Use a far future date for "Until Stopped"
        expiresAt = '2099-12-31 23:59:59';
    } else if (parseInt(duration) > 0) {
        const date = new Date();
        date.setMinutes(date.getMinutes() + parseInt(duration));
        expiresAt = date.toISOString().slice(0, 19).replace('T', ' ');
    }
    console.log(TAG, 'Set expires_at to:', expiresAt);
}
    const hasReplyData = reply_to_id && 
                         reply_to_id !== 0 && 
                         quoted_message && 
                         quoted_user_name;

    let query, params;
    
    if (hasReplyData) {
      console.log(TAG, 'Inserting WITH reply data');
      query = `
        INSERT INTO messages 
        (sender_id, receiver_id, message, timestamp, status, message_type, latitude, longitude, expires_at, reply_to_id, quoted_message, quoted_user_name) 
        VALUES (?, ?, ?, UTC_TIMESTAMP(), 0, ?, ?, ?, ?, ?, ?, ?)
      `;
      params = [
        sender_id, 
        receiver_id, 
        encryptedMessage, 
        type, 
        latitude || null, 
        longitude || null, 
        expiresAt,
        reply_to_id,
        quoted_message,
        quoted_user_name
      ];
    } else {
      console.log(TAG, 'Inserting WITHOUT reply data');
      query = `
        INSERT INTO messages 
        (sender_id, receiver_id, message, timestamp, status, message_type, latitude, longitude, expires_at) 
        VALUES (?, ?, ?, UTC_TIMESTAMP(), 0, ?, ?, ?, ?)
      `;
      params = [
        sender_id, 
        receiver_id, 
        encryptedMessage, 
        type, 
        latitude || null, 
        longitude || null, 
        expiresAt
      ];
    }
    
    console.log(TAG, 'Executing query with params:', params);
    const [result] = await db.query(query, params);

    if (!result.insertId) {
      console.error(TAG, 'Insert failed - no insertId returned');
      return res.status(500).json({ success: false, message: 'Failed to save message' });
    }

    console.log(TAG, 'Message saved with ID:', result.insertId);

    const newMessageId = result.insertId;
    const [insertedMsg] = await db.query('SELECT * FROM messages WHERE id = ?', [newMessageId]);
    const msgData = insertedMsg[0];

    const messageToEmit = {
      id: msgData.id,
      sender_id: msgData.sender_id,
      receiver_id: msgData.receiver_id,
      message: message, 
      timestamp: msgData.timestamp,
      status: 0,
      message_type: msgData.message_type,
      latitude: msgData.latitude,
      longitude: msgData.longitude,
      expires_at: msgData.expires_at,
      reply_to_id: msgData.reply_to_id || null,
      quoted_message: msgData.quoted_message || null,
      quoted_user_name: msgData.quoted_user_name || null
    };

    io.to(`chat_${receiver_id}`).emit('new_message_received', messageToEmit);
    io.to(`chat_${sender_id}`).emit('new_message_received', messageToEmit);

// --- REPLACE THIS BLOCK IN /sendMessage ---
try {
  const receiverIdStr = receiver_id.toString();

  // 1. Check if they are actively looking at THIS specific chat session
  const activeSession = activeChatSessions.get(receiverIdStr);
  const isLookingAtThisChat = activeSession === `user_${sender_id}`;

  // 2. Only send FCM if they aren't looking at the screen
  if (!isLookingAtThisChat) {
    const [userRows] = await db.query("SELECT fcm_token FROM users WHERE id = ?", [receiver_id]);
    const [senderRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name, profile_pic FROM users WHERE id = ?", [sender_id]);

    if (userRows.length > 0 && userRows[0].fcm_token) {
      const senderName = senderRows.length > 0 ? senderRows[0].name : "New Message";
      const senderPic = senderRows.length > 0 ? senderRows[0].profile_pic : "";
      const notificationBody = (type === 'location' || type === 'live_location') ? 'Shared a location' : message;

      // REPLACE the existing messagePayload block with this:
const messagePayload = {
  token: userRows[0].fcm_token,
  notification: { // Add this back for background reliability
    title: senderName,
    body: (type === 'location' || type === 'live_location') ? 'Shared a location' : message
  },
  data: {
    type: "chat",
    senderId: sender_id.toString(),
    senderName: senderName,
    senderProfilePic: senderPic || "",
    chatPartnerId: sender_id.toString(),
    // Fallbacks for your manual notification builder
    title: senderName,
    body: (type === 'location' || type === 'live_location') ? 'Shared a location' : message
  },
  android: {
    priority: "high",
    notification: {
      channelId: "channel_custom_sound_v3", // MATCHES YOUR MANIFEST
      priority: "high",
      sound: "custom_notification"
    }
  }
};
      await admin.messaging().send(messagePayload);
      console.log(`DATA-ONLY FCM Sent to ${receiverIdStr} (Partner was not in chat)`);
    }
  } else {
    console.log(`FCM Skipped: User ${receiverIdStr} is currently viewing this chat.`);
  }
} catch (fcmError) {
  console.error("CRITICAL FCM ERROR:", fcmError.message);
}
    res.json({ success: true, message: 'Message sent', messageId: newMessageId });

  } catch (error) {
    console.error(TAG, 'CRITICAL ERROR in /sendMessage:', error);
    console.error(TAG, 'Error stack:', error.stack);
    res.status(500).json({ success: false, message: 'Failed to send message', error: error.message });
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
        
        const friendsQuery = `
            SELECT DISTINCT
                CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
        `;
        const [friendRows] = await db.query(friendsQuery, [currentUserId, currentUserId, currentUserId]);
        const friendIds = new Set(friendRows.map(row => row.friend_id));
        
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
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.gender ELSE NULL END AS gender,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.profile_visibility ELSE NULL END AS profile_visibility,
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
            try { 
                lastMessage = row.last_message_content ? decrypt(row.last_message_content) : ""; 
            } catch (e) { 
                lastMessage = "[Encrypted Message]"; 
            }

            const isGroup = row.chat_type === 'group';
            const chatId = row.chat_id; 
            const chatName = isGroup ? row.group_name : row.username;
            
            let profilePicUrl = isGroup ? 'default_group_icon' : row.profile_pic;
            if (!isGroup) {
                profilePicUrl = getVisibleProfilePic(
                    { 
                        id: chatId, 
                        profile_pic: row.profile_pic, 
                        profile_visibility: row.profile_visibility,
                        gender: row.gender 
                    }, 
                    currentUserId, 
                    friendIds
                );
            }
            
            const unreadCount = isGroup ? row.group_unread_count : row.individual_unread_count;

            return {
                isGroup: isGroup,
                chatId: chatId,
                chatName: chatName,
                lastMessage: lastMessage,
                timestamp: row.last_timestamp, 
                unreadCount: unreadCount,
                profilePicUrl: profilePicUrl,
                gender: row.gender,
                lastSenderId: row.last_sender_id,
                lastSenderName: row.last_sender_name,
                lastMessageStatus: row.last_message_status 
            };
        });

        res.json({ success: true, chats: chatListItems });

    } catch (error) {
        console.error(TAG, 'Error fetching chat list:', error);
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

    const eventData = { blockerId: parseInt(blocker_id), blockedId: parseInt(blocked_id) };
    
    io.to(`chat_${blocked_id}`).emit('user_blocked', eventData);
    io.to(`chat_${blocker_id}`).emit('user_blocked', eventData);

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

    const eventData = { blockerId: parseInt(blocker_id), blockedId: parseInt(blocked_id) };

    io.to(`chat_${blocked_id}`).emit('user_unblocked', eventData);
    io.to(`chat_${blocker_id}`).emit('user_unblocked', eventData);

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
        // 1. Whitelist Map: Maps valid 'type' keys to their actual DB columns.
        // This ensures NO user-provided string ever enters the SQL query structure.
        const allowedSettings = {
            "trip_alerts": "trip_alerts_enabled"
            // You can easily add more features here later:
            // "chat_notifications": "chat_notif_enabled"
        };

        const targetColumn = allowedSettings[type];

        if (targetColumn) {
            // 2. Use a strictly hardcoded query structure. 
            // We use the whitelisted column name.
            const query = `UPDATE users SET ${targetColumn} = ? WHERE id = ?`;
            
            await db.query(query, [enabled, userId]);
            
            res.json({ success: true, message: 'Settings updated' });
        } else {
            // This handles cases where 'type' doesn't match our whitelist
            res.status(400).json({ success: false, message: 'No valid setting type found' });
        }
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/stopLiveLocation', async (req, res) => {
  const { messageId, userId } = req.body;
  try {
    // Set expires_at to current time so isExpired() will return true on reload
    const query = `UPDATE messages SET expires_at = UTC_TIMESTAMP() WHERE id = ? AND sender_id = ?`;
    const [result] = await db.execute(query, [messageId, userId]);
    
    res.json({ success: true, message: 'Live location ended in database' });
  } catch (error) {
    console.error('Error stopping live location in DB:', error);
    res.status(500).json({ success: false });
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
            WHERE tp.status = 'Trip Active'
            ORDER BY tp.time ASC
        `;
        const [rows] = await db.query(plansQuery);

        const usersGoing = rows.map(user => ({
            id: user.user_id,
            userId: user.user_id,
            name: user.name,
            fromPlace: user.fromPlace,
            toPlace: user.toPlace,
            time: user.time,
            gender: user.gender,
            profile_pic: getVisibleProfilePic(user, parseInt(currentUserId), friendIds)
        }));
        
        res.json({ success: true, users: usersGoing });
    } catch (err) {
        console.error("Error fetching users going:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

async function getAddressFromCoordinates(lat, lng) {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    
    if (!apiKey) {
      console.warn('Google Maps API key not configured');
      return null;
    }

    const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${apiKey}`;
    const response = await axios.get(url);

    if (response.data.status === 'OK' && response.data.results.length > 0) {
      const result = response.data.results[0];
      
      let city = '';
      let state = '';
      let country = '';
      
      result.address_components.forEach(component => {
        if (component.types.includes('locality')) {
          city = component.long_name;
        }
        if (component.types.includes('administrative_area_level_1')) {
          state = component.long_name;
        }
        if (component.types.includes('country')) {
          country = component.long_name;
        }
      });
      
      if (city && state && country) {
        return `${city}, ${state}, ${country}`;
      }
      
      return result.formatted_address;
    }
    
    return null;
  } catch (error) {
    console.error('Geocoding error:', error.message);
    return null;
  }
}

app.get("/travel-plans/destinations", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'Current user ID (userId) is required as a query parameter.' 
      });
    }
    
    const query = `
      SELECT
        ANY_VALUE(tp.to_place) as destination,
        COUNT(tp.user_id) as userCount,
        ANY_VALUE(g.group_id) as group_id,
        SUM(CASE WHEN tp.user_id = ? THEN 1 ELSE 0 END) > 0 AS isCurrentUserGoing,
        ANY_VALUE(tp.to_place_lat) as latitude,
        ANY_VALUE(tp.to_place_lng) as longitude
      FROM travel_plans tp
      JOIN \`group_table\` g ON tp.to_place = g.group_name
      WHERE
        tp.status = 'Trip Active'
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
    
    const destinationsWithAddress = await Promise.all(
      destinations.map(async (dest) => {
        const address = await getAddressFromCoordinates(dest.latitude, dest.longitude);
        return {
          ...dest,
          fullAddress: address || dest.destination 
        };
      })
    );
    
    res.json({ success: true, destinations: destinationsWithAddress || [] });
    
  } catch (err) {
    console.error("Error fetching travel plan destinations:", err);
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
                u.id, 
                CONCAT(u.first_name, ' ', u.last_name) as name, 
                u.work_category, 
                u.gender, 
                u.profile_pic, 
                u.profile_visibility,
                tp.from_place as fromPlace,
                tp.to_place as toPlace,
                DATE_FORMAT(tp.time, '%Y-%m-%dT%H:%i:%s.000Z') as time
            FROM travel_plans tp
            JOIN users u ON tp.user_id = u.id
            WHERE tp.to_place = ? AND tp.status = 'Trip Active'
            ORDER BY tp.time ASC
        `;
        const [users] = await db.query(plansQuery, [destination]);

        const filteredUsers = users.map(user => ({
            ...user,
            profile_pic: getVisibleProfilePic(user, parseInt(currentUserId), friendIds)
        }));
        
        res.json({ success: true, users: filteredUsers });
    } catch (error) {
        console.error('Error fetching users by destination:', error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});


function getVisibleProfilePic(user, viewerId, friendIds) {
    if (user.id === viewerId || user.user_id === viewerId) {
        return user.profile_pic;
    }

    const visibility = user.profile_visibility || 'everyone';
    
    if (visibility === 'none') {
        return user.gender === 'Female' ? 'default_female' : 'default_male';
    }
    
    if (visibility === 'friends') {
        const userId = user.id || user.user_id;
        if (friendIds && friendIds.has(userId)) {
            return user.profile_pic;
        }
        return user.gender === 'Female' ? 'default_female' : 'default_male';
    }
    
    return user.profile_pic;
}

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

    const uId = parseInt(userId);
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // Auto-update status for expired plans
    await db.query(`UPDATE travel_plans SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND time < NOW()`, [uId]);
    await db.query(`UPDATE travel_plans_cab SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND travel_datetime < NOW()`, [uId]);
    await db.query(`UPDATE travel_plans_own SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND travel_time < NOW()`, [uId]);

    const historyQuery = `
      SELECT * FROM (
        -- Rickshaw Plans
        SELECT 
            id, from_place, to_place, 
            DATE_FORMAT(time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Rickshaw' as commute_type
        FROM travel_plans WHERE user_id = ?

        UNION ALL

        -- Cab Plans (FIX: Selecting actual fare and added_fare from DB)
        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(travel_datetime, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Cab' as commute_type
        FROM travel_plans_cab WHERE user_id = ?

        UNION ALL

        -- Own Vehicle Plans (FIX: Selecting actual fare and added_fare from DB)
        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(travel_time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Own' as commute_type
        FROM travel_plans_own WHERE user_id = ?
      ) AS combined_history
      ORDER BY travel_time DESC
      LIMIT ? OFFSET ?
    `;

    const [trips] = await db.query(historyQuery, [uId, uId, uId, parseInt(limit), offset]);

    const processedTrips = trips.map(trip => ({
      id: trip.id,
      from_place: trip.from_place,
      to_place: trip.to_place,
      travel_time: trip.travel_time,
      fare: trip.fare ? parseFloat(trip.fare) : 0.00, // Ensuring fare is returned as a float
      status: trip.status,
      hasAddedFare: Boolean(trip.hasAddedFare), // Converting TINYINT to Boolean for Android
      commute_type: trip.commute_type 
    }));

    const [countResult] = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM travel_plans WHERE user_id = ?) +
        (SELECT COUNT(*) FROM travel_plans_cab WHERE user_id = ?) +
        (SELECT COUNT(*) FROM travel_plans_own WHERE user_id = ?) as total
    `, [uId, uId, uId]);

    const totalTrips = countResult[0].total;

    res.json({
      success: true,
      data: {
        trips: processedTrips,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalTrips / limit),
          totalTrips: totalTrips,
          hasMore: offset + processedTrips.length < totalTrips
        }
      }
    });
  } catch (error) {
    console.error(TAG, 'Error fetching unified trip history:', error);
    res.status(500).json({ success: false, message: 'Server Error', error: error.message });
  }
});

app.put('/trip/cancel/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }

    const tId = parseInt(tripId);

    // 1. Try to update in the Rickshaw table (travel_plans)
    const [rickshawRes] = await db.query('UPDATE travel_plans SET status = ? WHERE id = ?', ['Trip Cancelled', tId]);
    
    // 2. If not found, try to update in the Cab table (travel_plans_cab)
    let cabRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0) {
        [cabRes] = await db.query('UPDATE travel_plans_cab SET status = ? WHERE id = ?', ['Trip Cancelled', tId]);
    }

    // 3. If still not found, try to update in the Own Vehicle table (travel_plans_own)
    let ownRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0 && cabRes.affectedRows === 0) {
        [ownRes] = await db.query('UPDATE travel_plans_own SET status = ? WHERE id = ?', ['Trip Cancelled', tId]);
    }

    // Check if any of the three updates were successful
    if (rickshawRes.affectedRows > 0 || cabRes.affectedRows > 0 || ownRes.affectedRows > 0) {
      res.json({ success: true, message: 'Trip cancelled successfully' });
    } else {
      // If the ID wasn't found in any table
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

        const tId = parseInt(tripId);
        // This 'Done' must exist in your DB ENUM list
        const status = didGo === true ? 'Fare Added' : 'Trip Cancelled';
        const tripFare = didGo === true ? (parseFloat(fare) || 0.00) : 0.00;

        // 1. Try Rickshaw table (travel_plans)
        const [rickshawRes] = await db.query(
            'UPDATE travel_plans SET status = ?, fare = ?, added_fare = TRUE WHERE id = ?',
            [status, tripFare, tId]
        );

        // 2. If not found, try Cab table (travel_plans_cab)
        let cabRes = { affectedRows: 0 };
        if (rickshawRes.affectedRows === 0) {
            [cabRes] = await db.query(
                'UPDATE travel_plans_cab SET status = ?, fare = ?, added_fare = TRUE WHERE id = ?',
                [status, tripFare, tId]
            );
        }

        // 3. If still not found, try Own Vehicle table (travel_plans_own)
        let ownRes = { affectedRows: 0 };
        if (rickshawRes.affectedRows === 0 && cabRes.affectedRows === 0) {
            [ownRes] = await db.query(
                'UPDATE travel_plans_own SET status = ?, fare = ?, added_fare = TRUE WHERE id = ?',
                [status, tripFare, tId]
            );
        }

        // Check if any table was updated successfully
        if (rickshawRes.affectedRows > 0 || cabRes.affectedRows > 0 || ownRes.affectedRows > 0) {
            res.json({
                success: true,
                message: didGo ? 'Fare added successfully' : 'Trip marked as cancelled',
                newStatus: status
            });
        } else {
            // This occurs if the ID 210002 is not found in any table
            res.status(404).json({ success: false, message: 'Trip not found' });
        }

    } catch (error) {
        // This is where the 500 error is caught and logged
        console.error(TAG, 'Error completing trip:', error);
        res.status(500).json({ success: false, message: 'Error completing trip' });
    }
});

app.delete('/tripHistory/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }

    const tId = parseInt(tripId);

    // 1. Try to delete from the Rickshaw table (travel_plans)
    const [rickshawRes] = await db.query('DELETE FROM travel_plans WHERE id = ?', [tId]);
    
    // 2. If not found in Rickshaw, try the Cab table (travel_plans_cab)
    let cabRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0) {
        [cabRes] = await db.query('DELETE FROM travel_plans_cab WHERE id = ?', [tId]);
    }

    // 3. If still not found, try the Own Vehicle table (travel_plans_own)
    let ownRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0 && cabRes.affectedRows === 0) {
        [ownRes] = await db.query('DELETE FROM travel_plans_own WHERE id = ?', [tId]);
    }

    // Check if any of the three delete operations were successful
    if (rickshawRes.affectedRows > 0 || cabRes.affectedRows > 0 || ownRes.affectedRows > 0) {
      res.json({ success: true, message: 'Trip deleted successfully' });
    } else {
      // If the ID wasn't found in any of the three tables
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
      WHERE tp.user_id = ? AND tp.status = 'Trip Active' AND tp.time < NOW()
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
    // Update Rickshaw
    await db.query(`UPDATE travel_plans SET status = 'Trip Completed' WHERE status = 'Trip Active' AND time < NOW()`);
    // Update Cabs using new column
    await db.query(`UPDATE travel_plans_cab SET status = 'Trip Completed' WHERE status = 'Trip Active' AND travel_datetime < NOW()`);
    
    res.json({ success: true, message: "Trips updated" });
  } catch (error) {
    console.error('Error auto-updating trips:', error);
    res.status(500).json({ success: false });
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

        // 1. Basic Validation
        if (!phone || !country_code || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'Phone, country code, and new password are required'
            });
        }

        // 2. Strength Validation
        if (newPassword.length < 7 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 7 characters and include letters, numbers, and symbols." 
            });
        }

        // 3. Fetch User (Including current password hash)
        const [userRows] = await db.query(
            'SELECT id, password FROM users WHERE phone = ? AND country_code = ?',
            [phone, country_code]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const user = userRows[0];

        // 4. Check if new password is same as the old one
        // Note: user.password is the hashed string from DB
        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: "Your new password cannot be the same as your current password. Please choose a different one."
            });
        }

        // 5. Hash the new password and Update
        const userId = user.id;
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        
        await db.query(
            'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', 
            [newHashedPassword, userId]
        );

        res.json({ success: true, message: 'Password reset successfully' });

    } catch (error) {
        console.error(TAG, 'Error resetting password:', error);
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
            SELECT id, CONCAT(first_name, ' ', last_name) as name, work_category, phone, country_code, gender, dob, work_detail, profile_pic
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
        console.error(TAG, `Error searching for user:`, err);
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
    if (!userId) return res.status(400).json({ success: false, message: 'userId is required' });
    const currentUserId = parseInt(userId);
    try {
        const individualQuery = `SELECT COUNT(*) as totalUnreadCount FROM messages WHERE receiver_id = ? AND status < 2`;
        const [individualRows] = await db.execute(individualQuery, [currentUserId]);
        
        const groupQuery = `SELECT COUNT(*) as totalUnreadCount FROM group_messages gm WHERE gm.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?) AND gm.sender_id != ? AND NOT 
EXISTS (SELECT 1 FROM group_message_read_status gmrs WHERE gmrs.message_id = gm.message_id AND gmrs.user_id = ?)`;
        const [groupRows] = await db.execute(groupQuery, [currentUserId, currentUserId, currentUserId]);

        const requestQuery = `SELECT COUNT(*) as totalRequests FROM chat_requests WHERE receiver_id = ? AND status = 'pending'`;
        const [requestRows] = await db.execute(requestQuery, [currentUserId]);

        const total = individualRows[0].totalUnreadCount + groupRows[0].totalUnreadCount + requestRows[0].totalRequests;
        
        res.json({ success: true, unreadCount: total });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post("/hideChat", async (req, res) => {
    const TAG = "/hideChat"; 
    try {
        const { userId, otherUserId, isGroup } = req.body; 
        if (!userId || !otherUserId) return res.status(400).json({ success: false });

        if (isGroup) {
            // 1. Get all current messages in this group
            const [messages] = await db.query(`SELECT message_id FROM group_messages WHERE group_id = ?`, [otherUserId]);
            if (messages.length === 0) return res.json({ success: true });

            // 2. Mark these messages as hidden for THIS user
            const valuesToHide = messages.map(msg => [msg.message_id, userId, new Date()]);
            await db.query(`INSERT IGNORE INTO group_hidden_messages (message_id, user_id, hidden_at) VALUES ?`, [valuesToHide]);

            // 3. Collective Deletion Logic:
            // Check which messages have now been hidden by EVERYONE in the group
            const messageIds = messages.map(m => m.message_id);
            const [fullyHidden] = await db.query(`
                SELECT ghm.message_id 
                FROM group_hidden_messages ghm
                JOIN group_messages gm ON ghm.message_id = gm.message_id
                WHERE ghm.message_id IN (?)
                GROUP BY ghm.message_id
                HAVING COUNT(DISTINCT ghm.user_id) >= (SELECT COUNT(*) FROM group_members WHERE group_id = ?)
            `, [messageIds, otherUserId]);

            // 4. Permanently delete from DB if everyone hid it
            if (fullyHidden.length > 0) {
                const idsToDelete = fullyHidden.map(x => x.message_id);
                await db.query(`DELETE FROM group_messages WHERE message_id IN (?)`, [idsToDelete]);
                await db.query(`DELETE FROM group_hidden_messages WHERE message_id IN (?)`, [idsToDelete]);
                // Also clean up read status for these messages
                await db.query(`DELETE FROM group_message_read_status WHERE message_id IN (?)`, [idsToDelete]);
                console.log(TAG, `Permanently deleted ${idsToDelete.length} messages as all group members cleared history.`);
            }
        } else {
            // INDIVIDUAL CHAT LOGIC (Remains exactly as you had it)
            const [messages] = await db.query(`SELECT id FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)`, [userId, otherUserId, otherUserId, userId]);
            if (messages.length === 0) return res.json({ success: true });

            const valuesToHide = messages.map(msg => [msg.id, userId, new Date()]);
            await db.query(`INSERT IGNORE INTO hidden_messages (message_id, user_id, hidden_at) VALUES ?`, [valuesToHide]);
            
            const messageIds = messages.map(m => m.id);
            const [fullyHidden] = await db.query(`SELECT message_id FROM hidden_messages WHERE message_id IN (?) GROUP BY message_id HAVING COUNT(DISTINCT user_id) >= 2`, [messageIds]);
            if (fullyHidden.length > 0) {
                const idsToDelete = fullyHidden.map(x => x.message_id);
                await db.query(`DELETE FROM messages WHERE id IN (?)`, [idsToDelete]);
                await db.query(`DELETE FROM hidden_messages WHERE message_id IN (?)`, [idsToDelete]);
            }
        }
        res.json({ success: true });
    } catch (error) {
        console.error(TAG, error);
        res.status(500).json({ success: false });
    }
});

app.post("/cleanupDeletedMessages", async (req, res) => {
    const TAG = "/cleanupDeletedMessages";
    try {
        const [deletableMessages] = await db.query(`SELECT message_id FROM hidden_messages GROUP BY message_id HAVING COUNT(DISTINCT user_id) >= 2`);
        if (deletableMessages.length === 0) return res.status(200).json({ success: true });
        const messageIdsToDelete = deletableMessages.map(msg => msg.message_id);
        const connection = await db.getConnection();
        await connection.beginTransaction();
        try {
            await connection.query(`DELETE FROM messages WHERE id IN (?)`, [messageIdsToDelete]);
            await connection.query(`DELETE FROM hidden_messages WHERE message_id IN (?)`, [messageIdsToDelete]);
            await connection.commit();
            connection.release();
            res.status(200).json({ success: true });
        } catch (txError) {
            await connection.rollback();
            connection.release();
            throw txError; 
        }
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.delete('/deleteMessage/:messageId', async (req, res) => {
  const TAG = "DELETE /deleteMessage";
  try {
    const { messageId } = req.params;
    const { userId } = req.body;

    if (parseInt(userId) !== req.user.userId) {
        return res.status(403).json({ success: false, message: "Unauthorized action." });
    }

    if (!userId) return res.status(400).json({ success: false });
    const [messages] = await db.execute('SELECT * FROM messages WHERE id = ?', [messageId]);
    if (messages.length === 0) return res.status(404).json({ success: false });
    const msg = messages[0];
    
    if (msg.sender_id !== req.user.userId) {
        return res.status(403).json({ success: false, message: "You can only delete your own messages." });
    }

    if (msg.sender_id != userId) return res.status(403).json({ success: false });
    const [result] = await db.execute('DELETE FROM messages WHERE id = ?', [messageId]);
    if (result.affectedRows > 0) {
      io.to(`chat_${msg.receiver_id}`).emit('message_deleted', { messageId: parseInt(messageId) });
      io.to(`chat_${msg.sender_id}`).emit('message_deleted', { messageId: parseInt(messageId) });
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false });
    }
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/favorites/:userId', async (req, res) => {
    const { userId } = req.params;
    if (!userId) return res.status(400).json({ success: false });
    try {
        const [favorites] = await db.query(`SELECT id, user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng FROM favorites WHERE user_id = ? ORDER BY 
routeName ASC`, [userId]);
        res.json({ success: true, favorites: favorites });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/favorites', async (req, res) => {
    const { userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;
    if (!userId || !routeName || !fromPlace || !toPlace || fromPlaceLat === undefined) return res.status(400).json({ success: false });
    try {
        const query = `INSERT INTO favorites (user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        const [result] = await db.query(query, [userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng]);
        res.status(201).json({ success: true, favoriteId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.get("/user/:userId", async (req, res) => {
    const TAG = "/user/:userId"; 
    try {
        const { userId } = req.params; 
        const { viewerId } = req.query; 
        
        if (!userId || isNaN(userId)) return res.status(400).json({ success: false });

        const [friendRows] = await db.query(
            `SELECT DISTINCT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id 
             FROM messages WHERE sender_id = ? OR receiver_id = ?`, 
            [viewerId, viewerId, viewerId]
        );
        const friendIds = new Set(friendRows.map(row => row.friend_id));

        const query = `
            SELECT 
                id, 
                CONCAT(first_name, ' ', last_name) as name, 
                work_category, 
                gender, 
                dob, 
                work_detail, 
                profile_pic, 
                profile_visibility,
                COALESCE(bio, '') as bio,
                COALESCE(home_location, '') as home_location,
                EXISTS (
                    SELECT 1 FROM messages m 
                    WHERE (m.sender_id = ? AND m.receiver_id = users.id) 
                       OR (m.sender_id = users.id AND m.receiver_id = ?)
                ) as hasChat 
            FROM users WHERE id = ?`;

        const [rows] = await db.query(query, [viewerId, viewerId, parseInt(userId)]);
        
        if (rows.length === 0) return res.status(404).json({ success: false });
        
        const user = rows[0]; 
        user.hasChat = Boolean(user.hasChat);
        user.profile_pic = getVisibleProfilePic(user, parseInt(viewerId), friendIds);
        
        res.json({ success: true, user: user }); 
    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false });
    }
});

app.delete('/favorites/:userId/:favoriteId', async (req, res) => {
    const { userId, favoriteId } = req.params;
    try {
        const [result] = await db.query(`DELETE FROM favorites WHERE id = ? AND user_id = ?`, [favoriteId, userId]);
        res.json({ success: result.affectedRows > 0 });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.put('/settings/visibility', async (req, res) => {
    const { userId, visibility } = req.body;
    if (!userId || !visibility) return res.status(400).json({ success: false });
    try {
        await db.query('UPDATE users SET profile_visibility = ? WHERE id = ?', [visibility, userId]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        // 1. Validation check for password length
        if (!newPassword || newPassword.length < 7) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password doesn’t contain 7 characters' 
            });
        }

        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(404).json({ success: false });

        const isMatch = await bcrypt.compare(currentPassword, rows[0].password);
        if (!isMatch) {
            return res.status(400).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);
        
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false });
    }
});

app.get('/api/online-users', (req, res) => {
  res.json({ success: true, onlineUsers: Array.from(onlineUsers.entries()).map(([userId, data]) => ({ userId, isOnline: data.isOnline, lastSeen: data.lastSeen })) });
});

app.get('/api/user-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const onlineData = onlineUsers.get(userId);
    if (onlineData) return res.json({ success: true, userId, isOnline: true, lastSeen: onlineData.lastSeen });
    const [rows] = await db.query('SELECT is_online, last_seen FROM user_presence WHERE user_id = ?', [userId]);
    res.json({ success: true, userId, isOnline: false, lastSeen: rows[0]?.last_seen || null });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

app.get('/group-members/:groupId', async (req, res) => {
    const { groupId } = req.params;
    try {
        const [groupRows] = await db.execute('SELECT group_icon, group_name FROM group_table WHERE group_id = ?', [groupId]);
        const [members] = await db.execute(`SELECT u.id AS user_id, CONCAT(u.first_name, ' ', u.last_name) as name, u.phone, u.profile_pic FROM group_members gm JOIN users u ON gm.user_id = u.id 
WHERE gm.group_id = ? ORDER BY u.first_name ASC`, [groupId]);
        res.json({ success: true, group_icon: groupRows[0]?.group_icon, group_name: groupRows[0]?.group_name, members: members });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/leaveGroup', async (req, res) => {
    const { userId, groupId } = req.body;
    try {
        const [userRows] = await db.query(
            "SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", 
            [userId]
        );
        const userName = userRows.length > 0 ? userRows[0].name : "Someone";

        // 1. Remove from DB
        await db.query("DELETE FROM group_members WHERE user_id = ? AND group_id = ?", [userId, groupId]);
        
        // 2. Insert system message
        const systemMessage = `${userName} left the group`;
        const encrypted = encrypt(systemMessage);
        const [result] = await db.query(
            `INSERT INTO group_messages (group_id, sender_id, message_content, timestamp, message_type) 
             VALUES (?, ?, ?, NOW(), 'system')`,
            [groupId, userId, encrypted]
        );

        // 3. Notify remaining members via Socket
        io.to(`group_${groupId}`).emit('new_group_message', {
            id: result.insertId,
            group_id: groupId,
            sender_id: userId,
            sender_name: userName,
            message: systemMessage,
            message_type: 'system',
            timestamp: new Date().toISOString()
        });

        // 4. Force the specific user's socket to leave the room if they are online
        const userSocketId = onlineUsers.get(userId.toString())?.socketId;
        if (userSocketId) {
            const socket = io.sockets.sockets.get(userSocketId);
            if (socket) {
                socket.leave(`group_${groupId}`);
                console.log(`Forced Socket ${userSocketId} to leave group_${groupId}`);
            }
        }

        res.json({ success: true });
    } catch (e) {
        console.error("Leave group error:", e);
        res.status(500).json({ success: false });
    }
});

app.post('/update-group-icon', upload.single('group_icon'), async (req, res) => {
    const groupId = req.body.group_id;
    const cloudinaryUrl = req.file?.path;
    if (!groupId || !cloudinaryUrl) return res.status(400).json({ success: false });
    try {
        await db.execute('UPDATE group_table SET group_icon = ? WHERE group_id = ?', [cloudinaryUrl, groupId]);
        res.json({ success: true, group_icon: cloudinaryUrl });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/remove-group-icon', async (req, res) => {
    const { group_id } = req.body;
    try {
        await db.execute('UPDATE group_table SET group_icon = NULL WHERE group_id = ?', [group_id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.get('/group/:groupId/messages', async (req, res) => {
    const { groupId } = req.params;
    const { userId } = req.query;

    if (!userId) return res.status(400).json({ success: false, message: "User ID required" });

    try {
        
        const [memberCheck] = await db.query(
            `SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`,
            [groupId, userId]
        );
        
        if (memberCheck.length === 0) {
                if (memberCheck.length === 0) {
    // Auto-join the group instead of blocking
    await db.query(
        `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`,
        [groupId, userId]
    );
    // Optional: send a system message that user joined
    const [userRows] = await db.query(
        "SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", 
        [userId]
    );
    if (userRows.length > 0) {
        const { encrypt } = require('./cryptoHelper');
        const systemMsg = encrypt(`${userRows[0].name} joined the group`);
        await db.query(
            `INSERT INTO group_messages (group_id, sender_id, message_content, timestamp, message_type) 
             VALUES (?, ?, ?, NOW(), 'system')`,
            [groupId, userId, systemMsg]
        );
    }
}
        }
        const query = `
            SELECT
                gm.message_id as id,
                gm.sender_id,
                gm.message_content as message,
                gm.timestamp,
                gm.message_type, 
                gm.latitude,
                gm.longitude,
                gm.reply_to_id,
                gm.quoted_message, -- NEW
                gm.quoted_user_name, -- NEW
                DATE_FORMAT(gm.expires_at, '%Y-%m-%dT%H:%i:%s.000Z') as expires_at,
                gm.duration,
                CONCAT(u.first_name, ' ', u.last_name) as sender_name,
                u.profile_pic as sender_profile_pic,
                ((SELECT COUNT(DISTINCT user_id) FROM group_members WHERE group_id = ?) - 1) as totalParticipants,
                (SELECT COUNT(DISTINCT user_id)
                 FROM group_message_read_status
                 WHERE message_id = gm.message_id AND user_id != gm.sender_id) as readByCount,
                (SELECT GROUP_CONCAT(DISTINCT u2.first_name SEPARATOR ', ')
                 FROM group_message_read_status gmrs
                 JOIN users u2 ON gmrs.user_id = u2.id
                 WHERE gmrs.message_id = gm.message_id
                 AND gmrs.user_id != gm.sender_id) as readByNames
            FROM group_messages gm
            JOIN users u ON gm.sender_id = u.id
            WHERE gm.group_id = ?
              -- FILTER: Exclude messages hidden by this specific user
              AND NOT EXISTS (
                  SELECT 1 FROM group_hidden_messages ghm 
                  WHERE ghm.message_id = gm.message_id 
                  AND ghm.user_id = ?
              )
            ORDER BY gm.timestamp ASC
            LIMIT 300`;

        // Note: added userId to the parameter array to match the 3rd '?' in the query
        const [messages] = await db.execute(query, [groupId, groupId, userId]);

        const decrypted = messages.map(msg => ({
            ...msg,
            message: decrypt(msg.message)
        }));

        res.json({ success: true, messages: decrypted });
    } catch (error) { 
        console.error("Error fetching group messages:", error);
        res.status(500).json({ success: false });   
    }
});

app.get('/group/by-name', async (req, res) => {
    const TAG = "/group/by-name";
    try {
        const { groupName } = req.query;
        
        if (!groupName) {
            return res.status(400).json({ 
                success: false, 
                message: 'Group name is required' 
            });
        }

        const [groupRows] = await db.query(
            'SELECT group_id, group_name, group_icon FROM `group_table` WHERE group_name = ?', 
            [groupName]
        );

        if (groupRows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Group not found' 
            });
        }

        res.json({ 
            success: true, 
            groupId: groupRows[0].group_id,
            groupName: groupRows[0].group_name,
            groupIcon: groupRows[0].group_icon
        });

    } catch (error) {
        console.error(TAG, 'Error fetching group:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

app.post('/group/send', async (req, res) => {
    const TAG = "/group/send";
    const { 
        sender_id, 
        group_id, 
        message_content, 
        message_type, 
        latitude, 
        longitude, 
        reply_to_id, 
        quoted_sender_id,
        duration,
        quoted_message,
        quoted_user_name
    } = req.body;

    try {
        console.log(TAG, "Received request:", { sender_id, group_id, message_content, message_type, has_reply: !!reply_to_id });

        // 1. Validate group_id
        if (!group_id || group_id === 0) {
            return res.status(400).json({
                success: false,
                error: "Invalid group_id. Group ID must be a valid number."
            });
        }

        // 2. Fetch sender name
        const [userRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [sender_id]);

        if (userRows.length === 0) {
            return res.status(404).json({ success: false, error: "Sender user not found." });
        }
        const senderName = userRows[0].name;

        // 3. Check if group exists
        const [groupCheck] = await db.query('SELECT group_id, group_name, group_icon FROM `group_table` WHERE group_id = ?', [group_id]);

        if (groupCheck.length === 0) {
            console.log(TAG, "Group not found:", group_id);
            return res.status(404).json({
                success: false,
                error: "Group does not exist. Please create or join the group first."
            });
        }

        const groupName = groupCheck[0].group_name;

        // 4. Ensure user is a member
        const [memberCheck] = await db.query(
    `SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`,
    [group_id, sender_id]
);

if (memberCheck.length === 0) {
await db.query(
        `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`,
        [group_id, sender_id]
    );
}
        // 5. Encrypt message content
        const encrypted = encrypt(message_content);

        // 6. Calculate expiration for live location
        let expiresAt = null;
        if (message_type === 'live_location') {
            const durationInt = parseInt(duration);
            
            // FIX: Explicitly handle "Till I stop sharing" (-1)
            if (durationInt === -1) {
                expiresAt = '2099-12-31 23:59:59';
            } else {
                // Standard duration: use provided value or default to 60 if 0/NaN
                const finalDuration = (durationInt > 0) ? durationInt : 60;
                const expiryDate = new Date(Date.now() + finalDuration * 60000);
                expiresAt = expiryDate.toISOString().slice(0, 19).replace('T', ' ');
            }
            console.log(TAG, "Calculated Group Expiry:", expiresAt);
        }

        // 7. Prepare query with quoted message support
        const hasReplyData = reply_to_id && 
                             reply_to_id !== 0 && 
                             quoted_message && 
                             quoted_user_name;

        let query, params;

        if (hasReplyData) {
            query = `INSERT INTO group_messages
                (group_id, sender_id, message_content, timestamp, message_type, 
                 latitude, longitude, reply_to_id, quoted_sender_id, quoted_message, quoted_user_name, 
                 expires_at, duration)
                VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            
            params = [
                group_id,
                sender_id,
                encrypted,
                message_type || 'text',
                latitude || null,
                longitude || null,
                reply_to_id,
                quoted_sender_id || null,
                quoted_message,
                quoted_user_name,
                expiresAt,
                duration || 0
            ];
        } else {
            query = `INSERT INTO group_messages
                (group_id, sender_id, message_content, timestamp, message_type, 
                 latitude, longitude, reply_to_id, quoted_sender_id, quoted_message, quoted_user_name, 
                 expires_at, duration)
                VALUES (?, ?, ?, NOW(), ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)`;
            
            params = [
                group_id,
                sender_id,
                encrypted,
                message_type || 'text',
                latitude || null,
                longitude || null,
                expiresAt,
                duration || 0
            ];
        }

        const [result] = await db.execute(query, params);
        
        // 8. Socket emit with the same calculated expiresAt
        io.to(`group_${group_id}`).emit('new_group_message', {
            id: result.insertId,
            group_id: group_id,
            sender_id: sender_id,
            sender_name: senderName,
            message: message_content,
            message_type: message_type || 'text',
            latitude: latitude || null,
            longitude: longitude || null,
            reply_to_id: reply_to_id || null,
            quoted_sender_id: quoted_sender_id || null,
            quoted_message: quoted_message || null,
            quoted_user_name: quoted_user_name || null,
            expires_at: expiresAt,
            duration: duration || 0,
            timestamp: new Date().toISOString()
        });

        // 9. FCM Notifications
        try {
            const [members] = await db.query(`
                SELECT u.id, u.fcm_token 
                FROM group_members gm 
                JOIN users u ON gm.user_id = u.id 
                WHERE gm.group_id = ? AND gm.user_id != ? 
                  AND u.fcm_token IS NOT NULL AND u.fcm_token != ''
            `, [group_id, sender_id]);

            const tokensToNotify = members
                .filter(member => {
                    const activeSession = activeChatSessions.get(member.id.toString());
                    return activeSession !== `group_${group_id}`;
                })
                .map(m => m.fcm_token);

            if (tokensToNotify.length > 0) {
                const messagePayload = {
                    tokens: tokensToNotify,
                    notification: {
                        title: groupName,
                        body: `${senderName}: ${message_type === 'text' ? message_content : 'Shared a location'}`
                    },
                    android: {
                        priority: "high",
                        notification: {
                            channelId: "chat_channel_id",
                            sound: "default"
                        }
                    },
                    data: {
                        type: "group_chat",
                        groupId: String(group_id),
                        groupName: groupName,
                        senderId: String(sender_id)
                    }
                };
                await admin.messaging().sendEachForMulticast(messagePayload);
            }
        } catch (fcmError) {
            console.error(TAG, "FCM Error:", fcmError.message);
        }

        res.json({ success: true, messageId: result.insertId });

    } catch (error) {
        console.error(TAG, "ERROR:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 1. DELETE FOR ME (Group) - Just hides it for the caller
app.post("/group/deleteMessageForMe", async (req, res) => {
  try {
    const { messageId, userId } = req.body;
    if (!messageId || !userId) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    // We use a table called 'group_hidden_messages' to track who hid what
    // Ensure you have created this table in MySQL first!
    await db.query(
      `INSERT IGNORE INTO group_hidden_messages (message_id, user_id, hidden_at) VALUES (?, ?, NOW())`, 
      [messageId, userId]
    );

    res.json({ success: true, message: "Message hidden for you" });
  } catch (error) {
    console.error('Error in /group/deleteMessageForMe:', error);
    res.status(500).json({ success: false });
  }
});

// 2. DELETE FOR EVERYONE (Group) - Permanently removes from group_messages
app.delete('/group/deleteMessageForEveryone/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const { userId } = req.body;

    const [msgRows] = await db.execute('SELECT sender_id, group_id FROM group_messages WHERE message_id = ?', [messageId]);
    if (msgRows.length === 0) return res.status(404).json({ success: false });

    const msg = msgRows[0];
    if (msg.sender_id != userId) return res.status(403).json({ success: false, message: "Only sender can delete for everyone" });

    // Delete the actual message
    await db.execute('DELETE FROM group_messages WHERE message_id = ?', [messageId]);
    // Also clean up any 'hidden' entries for this message
    await db.execute('DELETE FROM group_hidden_messages WHERE message_id = ?', [messageId]);

    // Notify the group via socket
    io.to(`group_${msg.group_id}`).emit('message_deleted', { messageId: parseInt(messageId) });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});


app.get('/group/:groupId/members', async (req, res) => {
    const { groupId } = req.params;
    try {
        // Using a more robust query to ensure distinct user IDs
        const query = `
            SELECT 
                u.id, 
                u.id as userId, 
                CONCAT(u.first_name, ' ', u.last_name) as name, 
                u.profile_pic as profilePic 
            FROM users u 
            WHERE u.id IN (
                SELECT DISTINCT user_id 
                FROM group_members 
                WHERE group_id = ?
            )
            ORDER BY u.first_name ASC`;
            
        const [members] = await db.execute(query, [groupId]);
        res.json({ success: true, members: members });
    } catch (error) {
        console.error("Error fetching group members:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/group/read', async (req, res) => {
    const { user_id, group_id } = req.body;
    try {
        const query = `INSERT INTO group_message_read_status (message_id, user_id, group_id) 
                       SELECT gm.message_id, ?, gm.group_id 
                       FROM group_messages gm 
                       WHERE gm.group_id = ? 
                       AND NOT EXISTS (
                           SELECT 1 FROM group_message_read_status gmrs 
                           WHERE gmrs.message_id = gm.message_id AND gmrs.user_id = ?
                       )`;
        const [result] = await db.execute(query, [user_id, group_id, user_id]);
        res.json({ success: true, newReadCount: result.affectedRows });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});


app.post('/group/stop-location', async (req, res) => {
    const TAG = "/group/stop-location";
    const { userId, groupId } = req.body;

    if (!userId || !groupId) {
        return res.status(400).json({ success: false, message: "Missing userId or groupId" });
    }

    try {
        console.log(TAG, `Stopping live location for user ${userId} in group ${groupId}`);

        // Update the most recent live location message for this user in this group to EXPIRED
        const query = `
            UPDATE group_messages 
            SET expires_at = UTC_TIMESTAMP() 
            WHERE sender_id = ? 
              AND group_id = ? 
              AND message_type = 'live_location' 
            ORDER BY timestamp DESC 
            LIMIT 1
        `;

        const [result] = await db.execute(query, [userId, groupId]);

        if (result.affectedRows > 0) {
            res.json({ success: true, message: "Live location ended in database" });
        } else {
            res.json({ success: false, message: "No active session found" });
        }
    } catch (error) {
        console.error(TAG, "Error stopping group live location:", error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/searchUsers', async (req, res) => {
    const { query, currentUserId } = req.query;
    const searchTerm = query ? query.trim().toLowerCase() : "";
    if (!searchTerm) return res.json({ success: true, users: [] });
    try {
        const [friendRows] = await db.query(`SELECT DISTINCT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id FROM messages WHERE sender_id = ? OR receiver_id = ?`, 
[currentUserId, currentUserId, currentUserId]);
        const friendIds = new Set(friendRows.map(row => row.friend_id));
        const sql = `SELECT u.id, CONCAT(u.first_name, ' ', u.last_name) as name, u.work_category, u.profile_pic, u.gender, u.profile_visibility FROM users u WHERE LOWER(CONCAT(u.first_name, ' ', 
u.last_name)) LIKE ? AND u.id != ? LIMIT 50`;
        const [users] = await db.execute(sql, [`%${searchTerm}%`, currentUserId]);
        const response = users.map(u => ({ ...u, profile_pic: getVisibleProfilePic(u, parseInt(currentUserId), friendIds) }));
        res.json({ success: true, users: response });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post('/sendChatRequest', async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    try {
        await db.execute(`INSERT INTO chat_requests (sender_id, receiver_id, status, initial_message) VALUES (?, ?, 'pending', ?) ON DUPLICATE KEY UPDATE status = 'pending', initial_message = ?`, 
[senderId, receiverId, message, message]);
        io.to(`chat_${receiverId}`).emit('new_chat_request', { senderId, message });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post('/handleChatRequest', async (req, res) => {
    const { userId, otherUserId, action } = req.body;
    try {
        if (action === 'accept') {
            await db.execute(`UPDATE chat_requests SET status = 'accepted' WHERE sender_id = ? AND receiver_id = ?`, [otherUserId, userId]);
            const [request] = await db.execute(`SELECT initial_message FROM chat_requests WHERE sender_id = ? AND receiver_id = ?`, [otherUserId, userId]);
            if (request[0]?.initial_message) {
                const encrypted = encrypt(request[0].initial_message);
                await db.execute(`INSERT INTO messages (sender_id, receiver_id, message, timestamp, status) VALUES (?, ?, ?, UTC_TIMESTAMP(), 0)`, [otherUserId, userId, encrypted]);
            }
            res.json({ success: true });
        } else {
            await db.execute(`DELETE FROM chat_requests WHERE sender_id = ? AND receiver_id = ?`, [otherUserId, userId]);
            res.json({ success: true });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/chatRequests', async (req, res) => {
    const { userId } = req.query;
    try {
        const sql = `SELECT cr.id as requestId, cr.initial_message, u.id as userId, CONCAT(u.first_name, ' ', u.last_name) as name, u.profile_pic, u.gender, u.work_category FROM chat_requests cr 
JOIN users u ON cr.sender_id = u.id WHERE cr.receiver_id = ? AND cr.status = 'pending' ORDER BY cr.id DESC`;
        const [requests] = await db.execute(sql, [userId]);
        res.json({ success: true, requests: requests.map(r => ({ ...r, lastMessage: r.initial_message || "Sent a request" })) });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/chatRequests/count', async (req, res) => {
    const { userId } = req.query; // Add this line
    try {
        const [rows] = await db.execute(`SELECT COUNT(*) as count FROM chat_requests WHERE receiver_id = ? AND status = 'pending'`, [userId]);
        res.json({ success: true, count: rows[0].count });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.use(router);
const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
});
