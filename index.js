require("dotenv").config();
const activeChatSessions = new Map();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs'); 
const saltRounds = 10;
const admin = require("firebase-admin");
const axios = require('axios');
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const jwt = require('jsonwebtoken');
const authenticateToken = require('./authMiddleware');

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
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
app.set('trust proxy',1);
const server = http.createServer(app);

const allowedOrigins = [
  "https://reloaded-473118.web.app", // Your verified web app URL
  ...(process.env.NODE_ENV !== 'production' ? [
    "http://localhost:3000",           // For local development only
    "http://10.0.2.2:3000"             // For Android emulator testing only
  ] : [])
];

const corsOptions = {
  origin: function (origin, callback) {
    // SECURITY FIX: Only requests with NO Origin header (native mobile HTTP clients,
    // server-to-server calls) are trusted automatically. The literal strings "null" and
    // "localhost" are attacker-controllable (e.g. sandboxed iframes, some webviews send
    // Origin: null) and must NOT be auto-trusted, especially with credentials: true.
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Blocked by CORS policy"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

const rateLimit = require("express-rate-limit");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                  // 20 requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many attempts. Please try again later." }
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,                   // 5 OTP requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many OTP requests. Please try again later." }
});

// SECURITY FIX: /api/google-places-autocomplete proxies to a billed Google API using our own
// server-side key. Without auth + a rate limit, anyone can hammer it and run up our Google
// Maps bill / exhaust our quota. Require a logged-in user and cap requests per IP.
const placesAutocompleteLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 30,               // 30 requests per IP per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "Too many autocomplete requests. Please slow down." }
});

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket','polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000
});

// SECURITY FIX: 200mb was sized as if HD photos/videos flowed through this parser, but they
// don't — every upload route (profile_pic, group_icon, media_file) uses multer/Cloudinary
// storage, which streams multipart data directly and never touches express.json/urlencoded.
// This limit only applies to plain JSON/form bodies, so a large ceiling here just gives an
// attacker room to exhaust server memory with oversized request bodies. 5mb comfortably
// covers any legitimate JSON payload (e.g. base64 thumbnails, large trip/message payloads)
// without weakening HD media sharing at all.
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ limit: "5mb", extended: true }));

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
    transformation: [{ width: 1600, height: 1600, crop: 'limit', format: 'jpg' }] 
  }
});
const upload = multer({ storage: storage });

// SECURITY FIX: previously any mimetype was accepted — only the resource_type (image vs
// video) branched on it. That let someone upload arbitrary file types (executables, archives,
// scripts, etc.) into our Cloudinary account under the chat-media label. Restrict to real
// image/video formats. This intentionally still allows large, high-resolution photos and
// videos (HEIC/HEIF, RAW-adjacent formats, 4K-capable video containers) — it only blocks
// non-media file types, and the 100MB size cap below is unchanged.
const ALLOWED_SHARED_MEDIA_MIMETYPES = new Set([
  // Images
  'image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif',
  'image/heic', 'image/heif',
  // Videos
  'video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska',
  'video/3gpp', 'video/3gpp2', 'video/x-msvideo'
]);

function sharedMediaFileFilter(req, file, cb) {
  if (ALLOWED_SHARED_MEDIA_MIMETYPES.has(file.mimetype)) {
    return cb(null, true);
  }
  return cb(new Error('Unsupported file type. Only images and videos may be shared.'));
}

const sharedMediaStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    const isVideo = file.mimetype.startsWith('video');
    return {
      folder: 'automate_now_shared_media',
      resource_type: isVideo ? 'video' : 'image',
      timeout: 200000
    };
  }
});

const uploadSharedMedia = multer({ 
  storage: sharedMediaStorage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit rule allocation — unchanged, still supports HD photos/videos
  fileFilter: sharedMediaFileFilter
});

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

// Inside your index.js socket connections logic, update your properties:

// Locate these listeners in index.js and update them:

socket.on('i_delivered_messages', (data) => {
    const senderOfStatus = data.senderId || data.userId;
    socket.to(`chat_${data.partnerId}`).emit('partner_delivered_messages', {
        partnerId: parseInt(senderOfStatus),
        userId: parseInt(senderOfStatus)
    });
});

socket.on('i_read_messages', (data) => {
    const senderOfStatus = data.senderId || data.userId;
    socket.to(`chat_${data.partnerId}`).emit('partner_read_messages', {
        partnerId: parseInt(senderOfStatus),
        userId: parseInt(senderOfStatus)
    });
});

socket.on('join_group', (groupId) => {
    try {
        if (!groupId) return;
        const roomName = `group_${groupId}`; 
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

  socket.on('new_group_message', (data) => {
  socket.to(`group_${data.groupId}`).emit('new_group_message', data);
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
    if (!phone || !countryCode) {
        return { phone: phone || "", country_code: countryCode || "", isValid: false };
    }

    try {
        const dialCode = countryCode.startsWith('+') ? countryCode : `+${countryCode}`;
        const cleanPhone = phone.replace(/\D/g, '');
        const fullNumber = dialCode + cleanPhone;
        const phoneNumber = parsePhoneNumberFromString(fullNumber);

        if (phoneNumber && phoneNumber.isValid()) {
            return {
                phone: phoneNumber.nationalNumber, 
                country_code: `+${phoneNumber.countryCallingCode}`, 
                isValid: true
            };
        }
    } catch (e) {
        console.error("Normalization error:", e.message);
    }

    return {
        phone: phone.replace(/\D/g, ''),
        country_code: countryCode,
        isValid: false
    };
}

async function generateUniqueUserId(firstName) {
    const cleanName = firstName.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
    let isUnique = false;
    let finalUserId = "";

    while (!isUnique) {
        // Create a 4-character random alphanumeric suffix
        const randomSuffix = Math.random().toString(36).substring(2, 6);
        finalUserId = `${cleanName}_${randomSuffix}`;

        // Verify against DB to ensure zero collisions
        const [rows] = await db.query("SELECT id FROM users WHERE user_id = ?", [finalUserId]);
        if (rows.length === 0) {
            isUnique = true;
        }
    }
    return finalUserId;
}

async function executeMediaHardDeletionCleanup() {
    console.log("[Housekeeper] Commencing evaluation sequence for expired shared media components...");
    try {
        // Query rows where the current clock time has run past the assigned expires_at timestamp parameters
        const selectQuery = "SELECT id, cloudinary_public_id, media_type FROM shared_media WHERE expires_at <= NOW()";
        const [expiredRows] = await db.execute(selectQuery);

        if (expiredRows.length === 0) {
            console.log("[Housekeeper] Sanitization complete. Zero expired records detected.");
            return;
        }

        console.log(`[Housekeeper] Target matches locked. Purging ${expiredRows.length} elements from cloud storage clusters...`);

        // Iterate through array items to pull asset tracking properties
        for (let item of expiredRows) {
            const publicId = item.cloudinary_public_id;
            const resourceType = item.media_type === 'video' ? 'video' : 'image';

            // Explicitly delete asset from Cloudinary storage infrastructure completely
            await cloudinary.uploader.destroy(publicId, { resource_type: resourceType })
                .then(res => console.log(`[Cloudinary] Successfully shredded asset chunk: ${publicId} | Status:`, res.result))
                .catch(err => console.error(`[Cloudinary] Failed to shred asset: ${publicId}`, err.message));
        }

        // Execute hard removal delete from your TiDB shared_media table matching identical expired intervals
        const deleteQuery = "DELETE FROM shared_media WHERE expires_at <= NOW()";
        const [deleteResult] = await db.execute(deleteQuery);

        console.log(`[Housekeeper] Database sanitation execution wrapped up completely. Affected rows inside TiDB: ${deleteResult.affectedRows}`);

    } catch (error) {
        console.error("[Housekeeper Exception Error Handler] Routine failure:", error.message);
    }
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

// AFTER REFACTORING:
app.get("/debug/stores", (req, res) => {
  // SECURE FIX: Strict production enforcement environment verification check
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ success: false, message: "Not available in production" });
  }
  res.json({
    otpStore: "OTP is now stored in the database ('otp' table).",
    signupStore: "DB"
  });
});

app.get('/debug/routes', (req, res) => {
  // SECURE FIX: Completely block route structural mapping enumeration in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ success: false, message: "Not available in production" });
  }

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

app.get('/api/google-places-autocomplete', authenticateToken, placesAutocompleteLimiter, async (req, res) => {
    const { input } = req.query;
    const apiKey = process.env.GOOGLE_MAPS_API_KEY; // Ensure this is in your Cloud Run variables
    
    if (!input) return res.json({ predictions: [] });

    try {
        // Filter by 'school' and 'university' types to keep results relevant to Reloaded Automate
        const url = `https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${encodeURIComponent(input)}&types=school|university&key=${apiKey}`;
        const response = await axios.get(url);
        res.json(response.data);
    } catch (error) {
        console.error("Google Proxy Error:", error.message);
        res.status(500).json({ success: false });
    }
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

        const normalized = normalizePhoneData(phone, country_code);
        const finalPhone = normalized.phone;
        const finalCountryCode = normalized.country_code;

        console.log(TAG, `Attempting to create account for phone: ${finalCountryCode}${finalPhone}`);

        const [existingUser] = await db.query(
            `SELECT id, signup_status FROM users WHERE phone = ? AND country_code = ?`,
            [finalPhone, finalCountryCode]
        );

        if (existingUser.length > 0 && existingUser[0].signup_status === 'completed') {
            return res.status(409).json({ success: false, message: "A user with this phone number already exists." });
        }

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

        // FEATURE ENHANCEMENT: Generate a signed JWT token directly upon database insertion success
        const tokenPayload = { id: newUser.id, phone: newUser.phone };
        const authToken = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '30d' });

        // FIXED: Return BOTH the user object details AND the authenticating token string mapping parameter
        res.status(201).json({
            success: true,
            message: "Account created successfully. Please complete your profile.",
            token: authToken,
            user: newUser
        });

    } catch (err) {
        console.error(TAG, "Error in /create-account:", err);
        // SECURITY FIX: don't leak err.message (DB/driver internals) to the client
        res.status(500).json({ 
            success: false, 
            message: "Server error during account creation."
        });
    }
});

app.get("/check-phone-availability", authLimiter, async (req, res) => {
    const TAG = "/check-phone-availability";
    const { phone, country_code } = req.query;

    if (!phone || !country_code) {
        return res.status(400).json({ success: false, message: "Phone and country code required." });
    }

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

// SECURITY FIX: this route was a full account-enumeration oracle (any phone number ->
// full row data) with NO production gate, unlike its sibling /debug/* routes, and NO auth.
// It is now blocked in production and requires a valid session even in dev/staging.
app.get("/debug/check-user", authenticateToken, async (req, res) => {
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({ success: false, message: "Not available in production" });
    }
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

app.post("/login", authLimiter, async (req, res) => {
  const { phone, password, country_code } = req.body || {};

  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Missing phone or password` });
  }

  let finalPhone = phone.replace(/\D/g, '');
  let query = `SELECT * FROM users WHERE phone = ?`;
  let queryParams = [finalPhone];

  if (country_code) {
      const normalized = normalizePhoneData(phone, country_code);
      finalPhone = normalized.phone;
      query = `SELECT 
        id,
        user_id, 
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
        user_id, 
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

    const tokenPayload = {
    id: user.id,
    user_id: user.user_id
  };

  // Sign the token with an expiration timeframe (e.g., 7 days)
  const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });

  // Return both the user details and the token back to the client application
  res.json({ 
    success: true, 
    message: "Login successful", 
    token: token, // Client must save this token (e.g., in secure storage)
    user: user 
  });

  } catch (err) {
    console.error("/login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Replace your existing app.post("/updateProfile", ...) with this:
app.post("/updateProfile", authenticateToken, upload.single("profile_pic"), async (req, res) => {
  try {
    console.log("=== Update Profile Request (Stage 4 Complete) ===");
    const userId = req.user.id;
    const { 
      dob, 
      bio, 
      home_location, 
      home_lat, 
      home_lng 
    } = req.body || {};

    if (!userId) {
      return res.status(400).json({ success: false, message: "Missing userId" });
    }

    // --- NEW LOGIC: Generate user_id if they don't have one ---
    const [currentUser] = await db.query("SELECT first_name, user_id FROM users WHERE id = ?", [userId]);
    if (currentUser.length === 0) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const sets = [];
    const params = [];

    // Only generate a new id if it's currently missing or null
    if (!currentUser[0].user_id) {
      const generatedId = await generateUniqueUserId(currentUser[0].first_name);
      sets.push("user_id = ?");
      params.push(generatedId);
    }
    // ---------------------------------------------------------

    if (dob) {
      sets.push("dob = ?");
      params.push(dob);
    }
    if (bio) {
      sets.push("bio = ?");
      params.push(bio);
    }
    if (home_location) {
      sets.push("home_location = ?");
      params.push(home_location);
    }
    if (home_lat) {
      sets.push("home_lat = ?");
      params.push(home_lat);
    }
    if (home_lng) {
      sets.push("home_lng = ?");
      params.push(home_lng);
    }

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
      `SELECT
        id,
        user_id,
        CONCAT(first_name, ' ', last_name) as name,
        work_category,
        work_detail,
        phone,
        gender,
        dob,
        bio,
        home_location,
        home_lat,
        home_lng,
        profile_pic,
        signup_status
      FROM users WHERE id = ?`,
      [userId]
    );

    const updatedUser = rows[0];
    console.log("Profile Updated for User:", updatedUser.id, "Generated UserID:", updatedUser.user_id);

    res.json({
      success: true,
      message: "Profile updated and signup complete!",
      user: updatedUser
    });

  } catch (err) {
    console.error("=== /updateProfile ERROR ===");
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Internal Server Error",
      error: err.message
    });
  }
});

//==============================================ADD TRAVEL PLAN=========================================================

app.post("/addTravelPlan", authenticateToken, async (req, res) => {
    const TAG = "/addTravelPlan"; 
    let connection; 

    try {
        console.log(TAG, "Incoming payload details received:", req.body);

        // SECURE FIX: Force the identity to be the authenticated user from JWT
        const userId = req.user.id;

        // Destructure core required location tracking values safely
        const { 
            fromPlace, toPlace, time, 
            fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng, 
            landmark 
        } = req.body;

        // Resolution mapping for Android's serialized payload properties
        const ride_category    = req.body.rideCategory || req.body.ride_category || 'Planned';
        const service_provider = req.body.serviceProvider || req.body.service_provider || 'AutoMate';
        const vehicle_number   = req.body.vehicleNumber || req.body.vehicle_number || null;
        const mobile_number    = req.body.mobileNumber || req.body.mobile_number || null;
        
        // Handle precise parameter conversions safely
        const instant_fare = req.body.instantFare !== undefined ? req.body.instantFare : (req.body.instant_fare !== undefined ? req.body.instant_fare : null);
        const fare = req.body.fare || 0.00;

        if (!userId || !fromPlace || !toPlace || !time ||
            fromPlaceLat === undefined || fromPlaceLng === undefined ||
            toPlaceLat === undefined || toPlaceLng === undefined) {
            return res.status(400).json({
                success: false,
                message: "Required route coordination parameters are missing."
            });
        }

        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) throw new Error("Invalid format.");
        } catch (timeError) {
             return res.status(400).json({ success: false, message: "Invalid date format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        // 1. Locate the planQuery inside app.post("/addTravelPlan") and update columns/placeholders
        const planQuery = `
          INSERT INTO travel_plans 
            (user_id, from_place, to_place, time, status, 
             from_place_lat, from_place_lng, to_place_lat, to_place_lng, 
             landmark, meet_at, ride_category, service_provider, vehicle_number, instant_fare, mobile_number, fare, 
             created_at, updated_at) 
          VALUES (?, ?, ?, 
             CASE WHEN ? = 'Instant' THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL 6 MINUTE) ELSE ? END, 
             'Trip Active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP());
        `;

        // 2. Update the matching execution parameters array exactly like this:
        const [planResult] = await connection.query(planQuery, [
            userId, fromPlace, toPlace,
            ride_category, formattedTime,
            fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng,
            landmark || "Instant Booking",
            req.body.pickupAt || null, // <─── THIS GRABS THE FRONTEND FIELD AND SAVES IT TO MEET_AT
            ride_category,
            service_provider,
            vehicle_number,
            instant_fare,
            mobile_number,
            fare
        ]);
        
        const newPlanId = planResult.insertId;
        if (!newPlanId) {
             await connection.rollback();
             connection.release();
             throw new Error("Core travel plan row entry creation insertion failed.");
        }

        // 2. Manage destination group room allocation sequences
        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; 
        await connection.query(groupQuery, [toPlace]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [toPlace]);
        if (groupRows.length === 0) {
            await connection.rollback();
            connection.release();
            throw new Error(`Failed to establish destination chat group_id context allocation channel.`);
        }
        const groupId = groupRows[0].group_id;

        // 3. Connect active user to the target group channel
        const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
        await connection.query(memberQuery, [groupId, userId]);

        // 4. Fetch the user's name using the open transaction pool context *before* the commit completes
        const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
        const joinerName = userRows.length > 0 ? userRows[0].name : "Someone";

        // 5. Look for match criteria inside active table boundaries
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

        // 6. Complete transaction sequence updates atomically
        await connection.commit();

        // --- Asynchronous Notification Dispatches Execution ---
        if (matchingUsers.length > 0) {
            try {
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
                console.log(TAG, `Successfully broadcasted matching notifications to ${tokens.length} subscribers.`);
            } catch (notifyError) {
                console.error(TAG, "FCM notification dispatch failed to execute cleanly:", notifyError.message);
            }
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
        console.error(TAG, `Transaction rollback generated error:`, err);
        res.status(500).json({ success: false, message: "Server transaction execution failure." });
    } finally {
        if (connection) connection.release();
    }
});

app.post("/addCabTravelPlan", authenticateToken, async (req, res) => {
    const TAG = "/addCabTravelPlan";
    let connection;

    try {
        console.log(TAG, "Incoming payload details received:", req.body);

        // SECURE FIX: Force the identity to be the authenticated user from JWT
        const userId = req.user.id;
        
        // Safely extract properties by handling both backend-preferred and Android payload formats
        const fromPlace = req.body.fromPlace;
        const toPlace = req.body.toPlace;
        const landmark = req.body.landmark;
        
        // Map alternative time tokens
        const time = req.body.time || req.body.dateTime;

        // Map alternative coordinate layouts
        const fromPlaceLat = req.body.fromPlaceLat !== undefined ? req.body.fromPlaceLat : req.body.fromLat;
        const fromPlaceLng = req.body.fromPlaceLng !== undefined ? req.body.fromPlaceLng : req.body.fromLng;
        const toPlaceLat = req.body.toPlaceLat !== undefined ? req.body.toPlaceLat : req.body.toLat;
        const toPlaceLng = req.body.toPlaceLng !== undefined ? req.body.toPlaceLng : req.body.toLng;

        // Resolution mapping for Android's serialized payload properties
        const ride_category    = req.body.rideCategory    || req.body.ride_category    || 'Planned';
        const service_provider = req.body.serviceProvider || req.body.service_provider || 'AutoMate';
        const vehicle_number   = req.body.vehicleNumber   || req.body.vehicle_number   || null;
        const mobile_number    = req.body.mobileNumber    || req.body.mobile_number    || null;

        const instant_fare = req.body.instantFare !== undefined ? req.body.instantFare
                           : (req.body.instant_fare !== undefined ? req.body.instant_fare : null);
        const fare = req.body.fare || 0.00;

        // Validation Check
        if (!userId || !fromPlace || !toPlace || !time ||
            fromPlaceLat === undefined || fromPlaceLng === undefined ||
            toPlaceLat === undefined || toPlaceLng === undefined) {
            return res.status(400).json({
                success: false,
                message: "Required route coordination parameters are missing."
            });
        }

        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) throw new Error("Invalid format.");
        } catch (timeError) {
            return res.status(400).json({ success: false, message: "Invalid date format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        // 1. Update the INSERT query columns map and target values structure
        const planQuery = `
          INSERT INTO travel_plans_cab
            (user_id, pickup_location, destination, travel_datetime, status,
             from_place_lat, from_place_lng, to_place_lat, to_place_lng,
             landmark, meet_at, ride_category, service_provider, vehicle_number, instant_fare, mobile_number, fare,
             created_at, updated_at)
          VALUES (?, ?, ?, 
             CASE WHEN ? = 'Instant' THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL 6 MINUTE) ELSE ? END, 
             'Trip Active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP());
        `;

        // 2. Add req.body.pickupAt to the dynamic parameter array execution block
        const [planResult] = await connection.query(planQuery, [
            userId, fromPlace, toPlace,
            ride_category, formattedTime,
            fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng,
            landmark || "Instant Booking",
            req.body.pickupAt || null, // <─── SAVES THE MEET AT VALUE TO YOUR NEW DB COLUMN
            ride_category,
            service_provider,
            vehicle_number,
            instant_fare,
            mobile_number,
            fare
        ]);

        const newPlanId = planResult.insertId;
        if (!newPlanId) {
            await connection.rollback();
            connection.release();
            throw new Error("Core cab travel plan row entry creation insertion failed.");
        }

        // 2. Manage destination group room allocation sequences
        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`;
        await connection.query(groupQuery, [toPlace]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [toPlace]);
        if (groupRows.length === 0) {
            await connection.rollback();
            connection.release();
            throw new Error(`Failed to establish destination chat group_id context allocation channel.`);
        }
        const groupId = groupRows[0].group_id;

        // 3. Connect active user to the target group channel
        const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
        await connection.query(memberQuery, [groupId, userId]);

        // 4. Fetch the user's name
        const [userRows] = await connection.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [userId]);
        const joinerName = userRows.length > 0 ? userRows[0].name : "Someone";

        // 5. Look for match criteria inside active table boundaries
        const [matchingUsers] = await connection.query(`
            SELECT DISTINCT u.fcm_token
            FROM travel_plans_cab tp
            JOIN users u ON tp.user_id = u.id
            WHERE tp.destination = ?
              AND tp.status = 'Trip Active'
              AND tp.user_id != ?
              AND u.fcm_token IS NOT NULL
              AND u.trip_alerts_enabled = 1
        `, [toPlace, userId]);

        // 6. Complete transaction sequence updates atomically
        await connection.commit();

        // --- Asynchronous Notification Dispatches Execution ---
        if (matchingUsers.length > 0) {
            try {
                const tokens = matchingUsers.map(u => u.fcm_token).filter(t => t);
                const messagePayload = {
                    tokens: tokens,
                    notification: {
                        title: "New Cab Buddy!",
                        body: `${joinerName} is also taking a cab to ${toPlace}!`
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
                        groupId: String(groupId),
                        commuteType: "Cab"
                    }
                };
                await admin.messaging().sendEachForMulticast(messagePayload);
                console.log(TAG, `Successfully broadcasted matching cab notifications to ${tokens.length} subscribers.`);
            } catch (notifyError) {
                console.error(TAG, "FCM notification dispatch failed to execute cleanly:", notifyError.message);
            }
        }

        res.status(201).json({
            success: true,
            message: "Cab plan submitted successfully and group joined",
            id: newPlanId
        });

    } catch (err) {
        if (connection) {
            try { await connection.rollback(); } catch (e) {}
        }
        console.error(TAG, `Transaction rollback generated error:`, err);
        res.status(500).json({ success: false, message: "Server transaction execution failure." });
    } finally {
        if (connection) connection.release();
    }
});

app.post("/addOwnVehiclePlan", authenticateToken, async (req, res) => {
    const TAG = "/addOwnVehiclePlan";
    let connection;

    try {
        // SECURE FIX: Enforce the identity from the authenticated JWT token instead of req.body
        const userId = req.user.id;

        const { vehicleType, vehicleNumber, pickup, destination, time, landmark, estimatedFare, mobileNumber } = req.body;

        if (!userId || !destination || !time || !vehicleNumber || !vehicleType) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) throw new Error("Invalid date");
        } catch (e) {
            return res.status(400).json({ success: false, message: "Invalid time format." });
        }

        connection = await db.getConnection();
        await connection.beginTransaction();

        const query = `INSERT INTO travel_plans_own (user_id, vehicle_type, vehicle_number, pickup_location, destination, travel_time, landmark, estimated_fare, mobile_number, status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Trip Active')`;

        const [ownResult] = await connection.query(query, [
            userId, 
            vehicleType, 
            vehicleNumber, 
            pickup, 
            destination, 
            formattedTime, 
            landmark || null, 
            estimatedFare || 0.00,
            mobileNumber || null
        ]);

        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; 
        await connection.query(groupQuery, [destination]);

        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [destination]);
        const groupId = groupRows.length > 0 ? groupRows[0].group_id : null;

        if (groupId) {
            const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
            await connection.query(memberQuery, [groupId, userId]);
        }

        await connection.commit();

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

app.get("/travel-plans/destinations-by-type", authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { commuteType, rideCategory } = req.query;

    let tableName;
    let destinationCol;
    let statusFilter = "tp.status = 'Trip Active'";
    const queryParams = []; 

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        destinationCol = 'destination';
        
        if (rideCategory === 'Instant') {
            statusFilter += " AND tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)";
        } else if (rideCategory === 'Planned') {
            statusFilter += " AND tp.ride_category = 'Planned' AND CONVERT_TZ(tp.travel_datetime, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
        } else {
            statusFilter += ` AND ((tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)) OR 
(tp.ride_category = 'Planned' AND CONVERT_TZ(tp.travel_datetime, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')))`;
        }
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        destinationCol = 'destination';
        statusFilter += " AND CONVERT_TZ(tp.travel_time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
    } else {
        tableName = 'travel_plans';
        destinationCol = 'to_place'; 
        statusFilter += " AND (tp.commute_type = 'Rickshaw' OR tp.commute_type IS NULL)";

        if (rideCategory === 'Instant') {
            statusFilter += " AND tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)";
        } else if (rideCategory === 'Planned') {
            statusFilter += " AND tp.ride_category = 'Planned' AND CONVERT_TZ(tp.time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
        } else {
            statusFilter += ` AND ((tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)) OR 
(tp.ride_category = 'Planned' AND CONVERT_TZ(tp.time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')))`;
        }
    }

    try {
        let vehicleSelector = "NULL";
        let fareSelector = "NULL";
        let categorySelector = commuteType === 'Own' ? "'Planned'" : "MAX(tp.ride_category)";

        if (commuteType === 'Rickshaw' || commuteType === 'Cab' || commuteType === 'Own') {
            vehicleSelector = "tp.vehicle_number";
        }
        
        if (commuteType === 'Rickshaw' || commuteType === 'Cab') {
            fareSelector = "tp.instant_fare";
        } else if (commuteType === 'Own') {
            fareSelector = "tp.estimated_fare";
        }

        queryParams.unshift(userId);

        // For Rickshaw (travel_plans), group by destination name and date (cast to DATE to ignore hours/minutes)
        let dateGrouping = commuteType === 'Cab' ? "DATE(tp.travel_datetime)" : (commuteType === 'Own' ? "DATE(tp.travel_time)" : "DATE(tp.time)");


        const query = `
            SELECT 
                tp.${destinationCol} as destination, 
                COUNT(DISTINCT tp.user_id) as userCount, -- FIXED: Counts distinct people traveling
                SUM(CASE WHEN tp.user_id = ? THEN 1 ELSE 0 END) > 0 AS isCurrentUserGoing,
                g.group_id,
                MAX(${vehicleSelector}) AS vehicle_number,
                MAX(${fareSelector}) AS instant_fare,
                ${categorySelector} as ride_category
            FROM ${tableName} tp
            LEFT JOIN \`group_table\` g ON g.group_name = tp.${destinationCol}
            WHERE ${statusFilter}
            GROUP BY tp.${destinationCol}, g.group_id, ${categorySelector}
            ORDER BY userCount DESC
        `;

        const [destinations] = await db.query(query, queryParams);
        
        const formattedDestinations = destinations.map(d => ({
            groupId: d.group_id, 
            destination: d.destination,
            userCount: d.userCount,
            isCurrentUserGoing: d.isCurrentUserGoing,
            vehicleNumber: d.vehicle_number || null, 
            instantFare: d.instant_fare || null,
            ride_category: d.ride_category || rideCategory || 'Planned'
        }));

        res.json({ success: true, destinations: formattedDestinations });
    } catch (err) {
        console.error("Error fetching filtered destinations:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.get("/travel-plans/check-duplicate", authenticateToken, async (req, res) => {
    const { fromPlace, toPlace, date } = req.query;
    const userId = req.user.id;

    try {
        const query = `
            SELECT id FROM travel_plans 
            WHERE user_id = ? 
              AND from_place = ? 
              AND to_place = ? 
              AND DATE(time) = DATE(?) 
              AND status = 'Trip Active'
            LIMIT 1
        `;
        const [rows] = await db.query(query, [userId, fromPlace, toPlace, date]);

        if (rows.length > 0) {
            return res.json({ isDuplicate: true, existingTripId: rows[0].id });
        }
        res.json({ isDuplicate: false });
    } catch (err) {
        res.status(500).json({ isDuplicate: false });
    }
});

app.get("/users/destination", authenticateToken, async (req, res) => {
    const viewerId = req.user.id; 
    const { groupId, commuteType, destinationName, rideCategory } = req.query;

    let tableName = 'travel_plans';
    let fromCol = 'from_place';
    let toCol = 'to_place';
    let dbTimeField = 'time';
    let statusFilter = "tp.status = 'Trip Active'";
    
    const queryParams = [];

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        fromCol = 'pickup_location';
        toCol = 'destination';
        dbTimeField = 'travel_datetime';
        
        if (rideCategory === 'Instant') {
            statusFilter += " AND tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)";
        } else if (rideCategory === 'Planned') {
            statusFilter += " AND tp.ride_category = 'Planned' AND CONVERT_TZ(tp.travel_datetime, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
        } else {
            statusFilter += ` AND ((tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)) OR 
(tp.ride_category = 'Planned' AND CONVERT_TZ(tp.travel_datetime, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')))`;
        }
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        fromCol = 'pickup_location';
        toCol = 'destination';
        dbTimeField = 'travel_time';
        statusFilter += " AND CONVERT_TZ(tp.travel_time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
    } else {
        tableName = 'travel_plans';
        fromCol = 'from_place';
        toCol = 'to_place';
        dbTimeField = 'time';

        statusFilter += " AND (tp.commute_type = 'Rickshaw' OR tp.commute_type IS NULL)";

        if (rideCategory === 'Instant') {
            statusFilter += " AND tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)";
        } else if (rideCategory === 'Planned') {
            statusFilter += " AND tp.ride_category = 'Planned' AND CONVERT_TZ(tp.time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')";
        } else {
            statusFilter += ` AND ((tp.ride_category = 'Instant' AND CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') < DATE_ADD(CONVERT_TZ(tp.created_at, '+00:00', '+05:30'), INTERVAL 6 MINUTE)) OR 
(tp.ride_category = 'Planned' AND CONVERT_TZ(tp.time, '+00:00', '+05:30') > CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30')))`;
        }
    }

    try {
        let categorySelection, providerSelection, vehicleSelection, fareSelection, mobileSelection;

        if (commuteType === 'Cab') {
            categorySelection = "tp.ride_category";
            providerSelection = "tp.service_provider";
            vehicleSelection  = "tp.vehicle_number";
            fareSelection     = "tp.instant_fare";
            mobileSelection   = "tp.mobile_number";
        } else if (commuteType === 'Own') {
            categorySelection = "'Planned'";
            providerSelection = "'Own Vehicle'";
            vehicleSelection  = "tp.vehicle_number";
            fareSelection     = "tp.estimated_fare";
            mobileSelection   = "tp.mobile_number"; 
        } else {
            categorySelection = "tp.ride_category";
            providerSelection = "tp.service_provider";
            vehicleSelection  = "tp.vehicle_number";
            fareSelection     = "tp.instant_fare";
            mobileSelection   = "tp.mobile_number"; 
        }

        queryParams.push(destinationName, viewerId);

        const query = `
            SELECT
                u.id,           
                u.id as userId, 
                u.user_id as username_handle,
                CONCAT(u.first_name, ' ', u.last_name) as name,
                u.work_category,
                u.work_detail,
                u.gender,
                u.dob,
                u.profile_pic,
                u.profile_visibility,
                tp.${fromCol} as fromPlace,
                tp.${toCol} as toPlace,
                tp.meet_at,
                DATE_FORMAT(tp.${dbTimeField}, '%Y-%m-%dT%H:%i:%s.000Z') as time,
                tp.landmark,
                COALESCE(${categorySelection}, 'Planned') as ride_category,       
                COALESCE(${providerSelection}, 'AutoMate') as service_provider, 
                ${vehicleSelection} as vehicle_number,
                COALESCE(${fareSelection}, 0.00) as fare,
                ${mobileSelection} as mobile_number
            FROM ${tableName} tp
            JOIN users u ON tp.user_id = u.id
            WHERE ${statusFilter} AND tp.${toCol} = ? AND tp.user_id != ?
            ORDER BY tp.id DESC
        `;

        const [users] = await db.query(query, queryParams);

        const responseUsers = users.map(user => {
            const rawMobile = user.mobile_number; 

            return {
                id: user.id,
                userId: user.userId,
                user_id: user.username_handle,
                name: user.name,
                workCategory: user.work_category,
                workDetail: user.work_detail,
                gender: user.gender,
                fromPlace: user.fromPlace,
                toPlace: user.toPlace,
                meetAt: user.meet_at || null,
                time: user.time, 
                landmark: user.landmark || "",
                ride_category: user.ride_category,
                service_provider: user.service_provider,
                vehicle_number: user.vehicle_number || "",
                fare: String(user.fare),
                mobileNumber: rawMobile || null, 
                profilePic: getVisibleProfilePic(user, parseInt(viewerId), new Set())
            };
        });

        res.json({ success: true, users: responseUsers });

    } catch (err) {
        console.error("Error inside /users/destination route controller layer:", err);
        res.status(500).json({ success: false, message: "Server error fetching users" });
    }
});

app.post("/updateFcmToken", authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request body — otherwise
    // anyone could redirect another user's push notifications to their own device token.
    const userId = req.user.id;
    const { token } = req.body;
    try {
        await db.query("UPDATE users SET fcm_token = ? WHERE id = ?", [token, userId]);
        res.json({ success: true, message: "Token updated" });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/user/vehicles/:userId/:type', authenticateToken, async (req, res) => {
    const { userId, type } = req.params;
    // SECURITY FIX: only allow a user to read their own saved vehicles
    if (parseInt(userId) !== req.user.id) {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }
    try {
        const query = `SELECT * FROM user_vehicles WHERE userId = ? AND type = ?`;
        // Use await because 'db' is pool.promise()
        const [results] = await db.query(query, [userId, type]);
        
        res.status(200).json(results);
    } catch (err) {
        console.error("Error fetching vehicles:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.post('/user/save-vehicle', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request body
    const userId = req.user.id;
    const { type, state, district, series, number } = req.body;
    try {
        const query = `INSERT INTO user_vehicles (userId, type, state, district, series, number) 
                       VALUES (?, ?, ?, ?, ?, ?)`;
        
        const [result] = await db.query(query, [userId, type, state, district, series, number]);
        res.status(200).json({ message: "Vehicle saved successfully", vehicleId: result.insertId });
    } catch (err) {
        console.error("Error saving vehicle:", err);
        res.status(500).json({ message: "Database error" });
    }
});

app.get("/getUserTravelPlan/:userId", authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.userId);
    
    // SECURE FIX: Enforce that the user can only fetch their own travel plans
    if (!targetUserId || req.user.id !== targetUserId) {
      return res.status(403).json({ success: false, message: "Unauthorized data access request." });
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
      [targetUserId]
    );

    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error(`Error fetching travel plan:`, err);
    res.status(500).json({ success: false, message: "Database error", users: [] });
  }   
});

app.get('/getMessages', authenticateToken, async (req, res) => {
  try {
    const { receiver_id } = req.query;
    const sender_id = req.user.id;

    if (!receiver_id) {
      return res.status(400).json({ success: false, message: 'Required fields missing' });
    }

    const sql = `
      SELECT
        id, sender_id, receiver_id, message, timestamp, status, message_type,
        NULL AS media_url, expires_at,
        reply_to_id, quoted_message, quoted_user_name
      FROM messages
      WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
      UNION ALL
      SELECT
        id, sender_id, receiver_id,
        media_url AS message,
        send_at AS timestamp,
        IF(downloaded_at IS NOT NULL, 2, 1) AS status,
        media_type AS message_type,
        media_url, expires_at,
        NULL AS reply_to_id,
        NULL AS quoted_message, NULL AS quoted_user_name
      FROM shared_media
      WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        AND expires_at > NOW()
      ORDER BY timestamp ASC
    `;

    const [messages] = await db.query(sql, [
      parseInt(sender_id), parseInt(receiver_id), parseInt(receiver_id), parseInt(sender_id),
      parseInt(sender_id), parseInt(receiver_id), parseInt(receiver_id), parseInt(sender_id)
    ]);
    
    const hiddenSql = `SELECT message_id FROM hidden_messages WHERE user_id = ?`;
    const [hiddenMessages] = await db.query(hiddenSql, [parseInt(sender_id)]);
    const hiddenIds = hiddenMessages.map(h => h.message_id);
    
    const visibleMessages = messages.filter(msg => !hiddenIds.includes(msg.id));
    
    const decryptedMessages = visibleMessages.map(msg => {
      let processedContent = msg.message;
      if (!msg.message_type || msg.message_type === 'text' || msg.message_type === 'location' || msg.message_type === 'live_location') {
         try {
             const { decrypt } = require('./cryptoHelper');
             processedContent = decrypt(msg.message);
         } catch(e) {
             processedContent = msg.message;
         }
      }
      return { ...msg, message: processedContent };
    });

    res.json({ success: true, messages: decryptedMessages });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Database error' });
  }
});

app.post('/messages/delivered', authenticateToken, async (req, res) => {
  try {
    // SECURITY FIX: only the authenticated recipient can mark messages addressed to them
    // as delivered — identity comes from the token, not the body.
    const userId = req.user.id;
    const { otherUserId } = req.body;
    if (!otherUserId) {
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

app.post('/sendMessage', authenticateToken, async (req, res) => {
  const TAG = "/sendMessage";

  try {
    const { 
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

    // SECURE FIX: Force the sender_id to be the authenticated user from JWT
    const sender_id = req.user.id;

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

    if ((type === 'location' || type === 'live_location') && duration) {
        if (parseInt(duration) === -1) {
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

    try {
      const receiverIdStr = receiver_id.toString();

      const activeSession = activeChatSessions.get(receiverIdStr);
      const isLookingAtThisChat = activeSession === `user_${sender_id}`;

      if (!isLookingAtThisChat) {
        const [userRows] = await db.query("SELECT fcm_token FROM users WHERE id = ?", [receiver_id]);
        const [senderRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name, profile_pic FROM users WHERE id = ?", [sender_id]);

        if (userRows.length > 0 && userRows[0].fcm_token) {
          const senderName = senderRows.length > 0 ? senderRows[0].name : "New Message";
          const senderPic = senderRows.length > 0 ? senderRows[0].profile_pic : "";
          
          const messagePayload = {
            token: userRows[0].fcm_token,
            notification: { 
              title: senderName,
              body: (type === 'location' || type === 'live_location') ? 'Shared a location'
                  : (type === 'image') ? '📷 Photo'
                  : (type === 'video') ? '🎥 Video'
                  : message
            },
            data: {
              type: "chat",
              senderId: sender_id.toString(),
              senderName: senderName,
              senderProfilePic: senderPic || "",
              chatPartnerId: sender_id.toString(),
              title: senderName,
              body: (type === 'location' || type === 'live_location') ? 'Shared a location'
                  : (type === 'image') ? '📷 Photo'
                  : (type === 'video') ? '🎥 Video'
                  : message,
              groupKey: "com.swarajyadav.CHAT_GROUP_" + sender_id.toString()
            }, 
            android: {
              priority: "high",
              notification: {
                channelId: "channel_custom_sound_v3",
                priority: "high",
                sound: "custom_notification",
                tag: sender_id.toString()
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
    res.status(500).json({ success: false, message: 'Failed to send message', error: error.message });
  }
});

app.get('/getChatUsers', authenticateToken, async (req, res) => {
    const TAG = "/getChatUsers";
    try {
        // SECURE FIX: Override client query configuration with confirmed token identification
        const currentUserId = req.user.id;

        const friendsQuery = `
            SELECT DISTINCT
                CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id
            FROM messages
            WHERE sender_id = ? OR receiver_id = ?
        `;
        const [friendRows] = await db.query(friendsQuery, [currentUserId, currentUserId, currentUserId]);
        const friendIds = new Set(friendRows.map(row => row.friend_id));

        const combinedQuery = `
            WITH RawMergedChats AS (
                -- 1. Collect baseline text messages
                SELECT
                    'individual' AS chat_type,
                    CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS chat_id,
                    m.message AS last_message_content,
                    m.timestamp AS last_timestamp,
                    m.sender_id AS last_sender_id,
                    m.status AS last_message_status,
                    m.message_type AS last_message_type
                FROM messages m
                LEFT JOIN hidden_messages hm ON m.id = hm.message_id AND hm.user_id = ?
                WHERE
                    (m.sender_id = ? OR m.receiver_id = ?)
                    AND m.sender_id != m.receiver_id
                    AND hm.message_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM chat_requests cr 
                        WHERE cr.sender_id = m.sender_id 
                          AND cr.receiver_id = ? 
                          AND cr.status = 'pending'
                    )

                UNION ALL

                -- 2. Collect shared media entries (Optimized to stay persistent even after shared_media cleanup)
                SELECT
                    'individual' AS chat_type,
                    CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS chat_id,
                    m.message AS last_message_content,
                    m.timestamp AS last_timestamp,
                    m.sender_id AS last_sender_id,
                    m.status AS last_message_status,
                    m.message_type AS last_message_type
                FROM messages m
                WHERE
                    (m.sender_id = ? OR m.receiver_id = ?)
                    AND m.message_type IN ('image', 'video')
                    AND m.sender_id != m.receiver_id

                UNION ALL

                -- 3. Collect active group messages standard history rows
                SELECT
                    'group' AS chat_type,
                    gm.group_id AS chat_id,
                    gm.message_content AS last_message_content,
                    gm.timestamp AS last_timestamp,
                    gm.sender_id AS last_sender_id,
                    -1 AS last_message_status,
                    gm.message_type AS last_message_type
                FROM group_messages gm
                JOIN group_members gmem ON gm.group_id = gmem.group_id AND gmem.user_id = ?
                WHERE
                    gmem.user_id = ?
            ),
            LatestChats AS (
                SELECT 
                    rmc.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY rmc.chat_type, rmc.chat_id
                        ORDER BY rmc.last_timestamp DESC
                    ) as rn
                FROM RawMergedChats rmc
            )
            SELECT
                lc.chat_type,
                lc.chat_id,
                lc.last_message_content,
                lc.last_message_type,
                lc.last_timestamp,
                lc.last_sender_id,
                lc.last_message_status,
                CONCAT(u_sender.first_name, ' ', u_sender.last_name) AS last_sender_name,
                CASE WHEN lc.chat_type = 'individual' THEN CONCAT(u_partner.first_name, ' ', u_partner.last_name) ELSE NULL END AS username,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.user_id ELSE NULL END AS user_handle,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.profile_pic ELSE NULL END AS profile_pic,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.gender ELSE NULL END AS gender,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.profile_visibility ELSE NULL END AS profile_visibility,
                CASE WHEN lc.chat_type = 'group' THEN gt.group_name ELSE NULL END AS group_name,
                 (
                    (SELECT COUNT(*) FROM messages m_unread
                     WHERE lc.chat_type = 'individual'
                       AND m_unread.receiver_id = ?
                       AND m_unread.sender_id = lc.chat_id
                       AND m_unread.status < 2
                       AND m_unread.message_type NOT IN ('image', 'video'))
                    +
                    (SELECT COUNT(*) FROM shared_media sm_unread
                     WHERE lc.chat_type = 'individual'
                       AND sm_unread.receiver_id = ?
                       AND sm_unread.sender_id = CAST(lc.chat_id AS SIGNED)
                       AND sm_unread.expires_at > NOW()
                       AND sm_unread.downloaded_at IS NULL)
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
            LEFT JOIN users u_partner ON lc.chat_type = 'individual' AND CAST(lc.chat_id AS SIGNED) = u_partner.id
            LEFT JOIN \`group_table\` gt ON lc.chat_type = 'group' AND CAST(lc.chat_id AS SIGNED) = gt.group_id
            LEFT JOIN users u_sender ON lc.last_sender_id = u_sender.id
            WHERE lc.rn = 1 
              AND lc.chat_id != ?
            ORDER BY lc.last_timestamp DESC;
        `;

        // ─── REMAPPED CORRESPONDING QUERY BINDING PARAMETERS ARRAY ───
        const params = [
            currentUserId, currentUserId, currentUserId,   // CTE Section 1 text: chat_id, sender_id, hidden join
            currentUserId, currentUserId,                  // CTE Section 1 text: WHERE sender_id/receiver_id
            currentUserId,                                 // CTE Section 1 text: chat_requests check
            currentUserId, currentUserId, currentUserId,   // CTE Section 2 media: chat_id splits, WHERE params
            currentUserId, currentUserId,                  // CTE Section 3 group text/media message
            currentUserId,                                 // individual unread calculation: m_unread.receiver_id
            currentUserId,                                 // shared_media unread calculation: sm_unread.receiver_id
            currentUserId, currentUserId,                  // group unread counter properties configuration
            currentUserId                                  // global trailing layout filter: WHERE chat_id != currentUserId
        ];

        const [rows] = await db.query(combinedQuery, params);

        const chatListItems = rows.map(row => {
            let lastMessage = "";
            const msgType = (row.last_message_type || '').toLowerCase();
            
            if (msgType === 'image') {
                lastMessage = '📷 Photo';
            } else if (msgType === 'video') {
                lastMessage = '🎥 Video';
            } else {
                try { 
                    const { decrypt } = require('./cryptoHelper');
                    lastMessage = row.last_message_content ? decrypt(row.last_message_content) : "";
                } catch (e) { 
                    lastMessage = "[Encrypted Message]"; 
                }
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
                chatType: row.chat_type,
                chatId: chatId,
                chatName: chatName,
                lastMessage: lastMessage,
                timestamp: row.last_timestamp, 
                unreadCount: unreadCount,
                profilePicUrl: profilePicUrl,
                gender: row.gender,
                lastSenderId: row.last_sender_id,
                lastSenderName: isGroup ? row.last_sender_name : null,
                lastMessageStatus: row.last_message_status,
                user_id: isGroup ? null : row.user_handle 
            };
        });

        res.json({ success: true, chats: chatListItems });

    } catch (error) {
        console.error(TAG, 'Error fetching chat list:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch chat list' });
    }
});


// AFTER:
app.post("/deleteMessageForMe", authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.body;
    const userId = req.user.id; // SECURE FIX

    if (!messageId || !userId) {
      return res.status(400).json({ success: false, message: `messageId is required` });
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

// AFTER:
app.post('/block', authenticateToken, async (req, res) => {
  try {
    const { blocked_id } = req.body;
    const blocker_id = req.user.id; // SECURE FIX: Bind to token identity

    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocked ID is required.' });
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

app.post('/unblock', authenticateToken, async (req, res) => {
  try {
    const { blocked_id } = req.body;
    const blocker_id = req.user.id; // SECURE FIX: Bind to token identity

    if (!blocker_id || !blocked_id) {
      return res.status(400).json({ success: false, message: 'Blocked ID is required.' });
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

app.get('/checkBlockStatus', authenticateToken, async (req, res) => {
  try {
    const { user1_id, user2_id } = req.query;
    if (!user1_id || !user2_id) {
      return res.status(400).json({ success: false, message: 'Both user IDs are required.' });
    }
    // SECURITY FIX: only allow checking block status for a pair you're actually part of
    if (req.user.id !== parseInt(user1_id) && req.user.id !== parseInt(user2_id)) {
      return res.status(403).json({ success: false, message: 'Unauthorized.' });
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

// AFTER REFACTORING:
app.post('/updateNotificationSettings', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request body
    const userId = req.user.id;
    const { type, enabled } = req.body;
    if (!type) {
        return res.status(400).json({ success: false, message: 'Missing fields' });
    }
    try {
        // SECURE FIX: Avoid column string interpolation inside query execution entirely
        if (type === "trip_alerts") {
            await db.query(`UPDATE users SET trip_alerts_enabled = ? WHERE id = ?`, [enabled, userId]);
            return res.json({ success: true, message: 'Settings updated' });
        } 
        
        // Catch-all structural verification step for non-supported or missing criteria
        res.json({ success: true, message: 'No valid setting type found' });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/stopLiveLocation', authenticateToken, async (req, res) => {
  // SECURITY FIX: identity from the verified token, not the request body — otherwise
  // any user could stop another user's live-location share.
  const userId = req.user.id;
  const { messageId } = req.body;
  try {
    const query = `UPDATE messages SET expires_at = UTC_TIMESTAMP() WHERE id = ? AND sender_id = ?`;
    const [result] = await db.execute(query, [messageId, userId]);

    res.json({ success: true, message: 'Live location ended in database' });
  } catch (error) {
    console.error('Error stopping live location in DB:', error);
    res.status(500).json({ success: false });
  }
});

app.get("/getUsersGoing", authenticateToken, async (req, res) => {
    // SECURITY FIX: this ID gates profile-picture visibility (friends-only vs public), so it
    // must come from the verified token, not a client-supplied query param.
    const currentUserId = req.user.id;
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

        // Fix: Added u.work_detail to the SELECT clause
        const plansQuery = `
            SELECT
                tp.user_id,
                CONCAT(u.first_name, ' ', u.last_name) as name,
                u.profile_pic,
                u.gender,
                u.profile_visibility,
                u.work_category,
                u.work_detail,
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
            workCategory: user.work_category, // Pass to client
            workDetail: user.work_detail,     // Pass to client
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

app.get("/travel-plans/destinations", authenticateToken, async (req, res) => {
  try {
    // SECURITY FIX: identity from the verified token, not the request query
    const userId = req.user.id;

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


app.get('/travel-plans/by-destination', authenticateToken, async (req, res) => {
    // SECURITY FIX: this ID gates friend-only profile-picture visibility, so it must come
    // from the verified token, not a client-supplied query param.
    const currentUserId = req.user.id;
    const { destination } = req.query;
    if (!destination) {
        return res.status(400).json({ success: false, message: 'Destination is required.' });
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

app.delete("/user/profile/:userId", authenticateToken, async (req, res) => {
    const TAG = "/user/profile/:userId (DELETE)";
    try {
        const { userId } = req.params;
        if (!userId || isNaN(userId)) {
            return res.status(400).json({ success: false, message: "User ID required" });
        }
        // SECURITY FIX: only the account owner can remove their own profile picture
        if (parseInt(userId) !== req.user.id) {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        await db.query("UPDATE users SET profile_pic = NULL WHERE id = ?", [parseInt(userId)]);
        res.json({ success: true, message: "Profile picture removed", user: { profilePic: null } });
    } catch (err) {
        console.error(TAG, "Error removing profile pic:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get('/tripHistory/:userId', authenticateToken, async (req, res) => {
  const TAG = "GET /tripHistory/:userId";
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }
    // SECURITY FIX: only the account owner can view their own trip history
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized.' });
    }

    const uId = parseInt(userId);
    const offset = (parseInt(page) - 1) * parseInt(limit);

    // FIXED: Ensured execution checks hit valid time columns across individual layout architectures
    await db.query(`UPDATE travel_plans SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND time < NOW()`, [uId]);
    await db.query(`UPDATE travel_plans_cab SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND travel_datetime < NOW()`, [uId]);
    await db.query(`UPDATE travel_plans_own SET status = 'Trip Completed' WHERE user_id = ? AND status = 'Trip Active' AND travel_time < NOW()`, [uId]);

    const historyQuery = `
      SELECT * FROM (
        SELECT 
            id, from_place, to_place, 
            DATE_FORMAT(time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, NULL as hasAddedFare, 'Sharing Rickshaw' as commute_type,
            ride_category, service_provider, vehicle_number
        FROM travel_plans WHERE user_id = ?

        UNION ALL

        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(travel_datetime, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Reserved Cab' as commute_type,
            ride_category, service_provider, vehicle_number
        FROM travel_plans_cab WHERE user_id = ?

        UNION ALL

        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(travel_time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Personal Vehicle' as commute_type,
            NULL as ride_category, NULL as service_provider, NULL as vehicle_number
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
      fare: trip.fare ? parseFloat(trip.fare) : 0.00,
      status: trip.status,
      hasAddedFare: Boolean(trip.hasAddedFare),
      commute_type: trip.commute_type,
      ride_category: trip.ride_category || null,
      service_provider: trip.service_provider || null,
      vehicle_number: trip.vehicle_number || null
    }));

    const [countResult] = await db.query (`
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
    res.status(500).json({ success: false, message: 'Server Error' });
  }
});

app.put('/trip/cancel/:tripId', authenticateToken, async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }

    const tId = parseInt(tripId);
    // SECURITY FIX: identity from the verified token, and every UPDATE below is now scoped
    // to user_id = ? so only the trip's owner can cancel it.
    const uId = req.user.id;

    const [rickshawRes] = await db.query('UPDATE travel_plans SET status = ? WHERE id = ? AND user_id = ?', ['Trip Cancelled', tId, uId]);

    let cabRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0) {
        [cabRes] = await db.query('UPDATE travel_plans_cab SET status = ? WHERE id = ? AND user_id = ?', ['Trip Cancelled', tId, uId]);
    }

    let ownRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0 && cabRes.affectedRows === 0) {
        [ownRes] = await db.query('UPDATE travel_plans_own SET status = ? WHERE id = ? AND user_id = ?', ['Trip Cancelled', tId, uId]);
    }

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

app.get('/socket-status', authenticateToken, (req, res) => {
  // SECURITY FIX: this leaks internal socket IDs and the full online-user list; treat it
  // like the other /debug/* routes.
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ success: false, message: "Not available in production" });
  }
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

app.put('/trip/complete/:tripId', authenticateToken, async (req, res) => {
    const TAG = "PUT /trip/complete/:tripId";
    let connection;
    try {
        const { tripId } = req.params;
        const { 
            fare, 
            didGo, 
            commuteType, 
            durationMinutes, 
            companionSource, 
            companionUserId, 
            companionNameFallback 
        } = req.body;

        if (!tripId || isNaN(tripId) || didGo === undefined) {
            return res.status(400).json({ success: false, message: 'Invalid trip ID or missing didGo status' });
        }

        const tId = parseInt(tripId);
        // SECURITY FIX: identity from the verified token, used below to scope every UPDATE
        // to the caller's own trip so one user can't complete/set-fare on another's trip.
        const uId = req.user.id;
        const isExecuted = (didGo === true || didGo === 'true' || didGo === 1 || didGo === '1');
        const targetStatus = isExecuted ? 'Fare Added' : 'Trip Cancelled';
        const tripFare = isExecuted ? (parseFloat(fare) || 0.00) : 0.00;
        
        // Exact column ENUM matching alignment: 'Rickshaw', 'Cab', 'Own'
        let resolvedCommuteType = 'Rickshaw';
        if (commuteType && commuteType.toLowerCase().includes('cab')) resolvedCommuteType = 'Cab';
        if (commuteType && commuteType.toLowerCase().includes('own')) resolvedCommuteType = 'Own';
        if (commuteType && commuteType.toLowerCase().includes('personal')) resolvedCommuteType = 'Own';

        connection = await db.getConnection();
        await connection.beginTransaction();

        let affected = 0;
        
        // 1. Update primary tables gracefully
        try {
            const [rRes] = await connection.query(
                'UPDATE travel_plans SET status = ?, fare = ?, added_fare = TRUE WHERE id = ? AND user_id = ?',
                [targetStatus, tripFare, tId, uId]
            );
            affected += rRes.affectedRows;
        } catch (err) {
            console.warn(`${TAG} - travel_plans skip:`, err.message);
        }

        if (affected === 0) {
            try {
                const [cRes] = await connection.query(
                    'UPDATE travel_plans_cab SET status = ?, fare = ?, added_fare = TRUE WHERE id = ? AND user_id = ?',
                    [targetStatus, tripFare, tId, uId]
                );
                affected += cRes.affectedRows;
            } catch (err) {
                console.warn(`${TAG} - travel_plans_cab skip:`, err.message);
            }
        }

        if (affected === 0) {
            try {
                const [oRes] = await connection.query(
                    'UPDATE travel_plans_own SET status = ?, fare = ?, added_fare = TRUE WHERE id = ? AND user_id = ?',
                    [targetStatus, tripFare, tId, uId]
                );
                affected += oRes.affectedRows;
            } catch (err) {
                console.warn(`${TAG} - travel_plans_own skip:`, err.message);
            }
        }

        if (affected === 0) {
            await connection.rollback();
            return res.status(404).json({ success: false, message: 'Trip target reference not found' });
        }

        // Exact companion ENUM matching alignment: 'Random', 'App'
        let resolvedCompanionSource = 'Random';
        if (companionSource && companionSource.toLowerCase().includes('app')) {
            resolvedCompanionSource = 'App';
        }

        // 2. Insert metrics safely into trip_information or UPSERT cleanly if matching unique trip_id index key
        const insertInfoQuery = `
            INSERT INTO trip_information 
            (trip_id, commute_type, did_go, duration_minutes, total_fare, companion_source, companion_user_id, companion_name_fallback)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                commute_type = VALUES(commute_type),
                did_go = VALUES(did_go),
                duration_minutes = VALUES(duration_minutes),
                total_fare = VALUES(total_fare),
                companion_source = VALUES(companion_source),
                companion_user_id = VALUES(companion_user_id),
                companion_name_fallback = VALUES(companion_name_fallback),
                created_at = CURRENT_TIMESTAMP
        `;
        
        await connection.query(insertInfoQuery, [
            tId,
            resolvedCommuteType,
            isExecuted ? 1 : 0,
            durationMinutes ? parseInt(durationMinutes) : null,
            tripFare,
            resolvedCompanionSource,
            companionUserId ? String(companionUserId).trim() : null, // Safely handled as standard VARCHAR sequence
            companionNameFallback || null
        ]);

        await connection.commit();
        res.json({
            success: true,
            message: isExecuted ? 'Trip details and fare cataloged completely' : 'Trip logged as cancelled structural state',
            newStatus: targetStatus
        });

    } catch (error) {
        if (connection) await connection.rollback();
        console.error(TAG, 'Transaction Exception Fail:', error);
        res.status(500).json({ success: false, message: 'Error processing trip completion transactional workflow' });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/tripInformation/:tripId', authenticateToken, async (req, res) => {
    const TAG = "GET /tripInformation/:tripId";
    try {
        const { tripId } = req.params;
        const tIdNum = parseInt(tripId);

        // SECURITY FIX: verify the caller actually owns this trip in one of the three plan
        // tables before returning any information about it.
        const [ownsIt] = await db.query(
            `SELECT 1 FROM travel_plans WHERE id = ? AND user_id = ?
             UNION ALL SELECT 1 FROM travel_plans_cab WHERE id = ? AND user_id = ?
             UNION ALL SELECT 1 FROM travel_plans_own WHERE id = ? AND user_id = ?`,
            [tIdNum, req.user.id, tIdNum, req.user.id, tIdNum, req.user.id]
        );
        if (ownsIt.length === 0) {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        
        const infoQuery = `SELECT * FROM trip_information WHERE trip_id = ? ORDER BY id DESC LIMIT 1`;
        const [rows] = await db.query(infoQuery, [parseInt(tripId)]);
        
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: "No supplementary tracking data available" });
        }
        
        const tripInfo = rows[0];

        if (tripInfo.companion_source === 'App' && tripInfo.companion_user_id) {
            // Split clean incoming string collection parameters "2220001,1770001" safely
            const companionIds = String(tripInfo.companion_user_id)
                .split(',')
                .map(id => parseInt(id.trim()))
                .filter(id => !isNaN(id));
            
            if (companionIds.length > 0) {
                const [users] = await db.query(
                    `SELECT id, user_id, CONCAT(first_name, ' ', last_name) as name, work_category, profile_pic FROM users WHERE id IN (?)`,
                    [companionIds]
                );
                
                // CRITICAL FIXED FACTOR: Re-order database list rows to exactly preserve original app array sequences 
                const sortedUsers = companionIds.map(id => users.find(u => u.id === id)).filter(Boolean);
                
                tripInfo.companion_handle = sortedUsers.map(u => u.user_id || '').filter(Boolean).join(', ');
                tripInfo.companion_full_name = sortedUsers.map(u => u.name || '').filter(Boolean).join(', ');
                tripInfo.companion_work_category = sortedUsers.map(u => u.work_category || '').filter(Boolean).join(', ');
                tripInfo.companion_profile_pic = sortedUsers.length > 0 ? sortedUsers[0].profile_pic : null;
            } else {
                tripInfo.companion_full_name = tripInfo.companion_name_fallback || null;
            }
        } else {
            tripInfo.companion_handle = null;
            tripInfo.companion_full_name = tripInfo.companion_name_fallback || null;
            tripInfo.companion_work_category = null;
            tripInfo.companion_profile_pic = null;
        }

        res.json({ success: true, data: tripInfo });
    } catch (error) {
        console.error(TAG, error);
        res.status(500).json({ success: false, message: "Internal directory failure parsing structural mapping values" });
    }
});

app.delete('/tripHistory/:tripId', authenticateToken, async (req, res) => {
  try {
    const { tripId } = req.params;
    if (!tripId || isNaN(tripId)) {
      return res.status(400).json({ success: false, message: 'Invalid trip ID' });
    }

    const tId = parseInt(tripId);
    // SECURITY FIX: identity from the verified token, scoping every DELETE to the caller
    const uId = req.user.id;

    const [rickshawRes] = await db.query('DELETE FROM travel_plans WHERE id = ? AND user_id = ?', [tId, uId]);

    let cabRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0) {
        [cabRes] = await db.query('DELETE FROM travel_plans_cab WHERE id = ? AND user_id = ?', [tId, uId]);
    }

    let ownRes = { affectedRows: 0 };
    if (rickshawRes.affectedRows === 0 && cabRes.affectedRows === 0) {
        [ownRes] = await db.query('DELETE FROM travel_plans_own WHERE id = ? AND user_id = ?', [tId, uId]);
    }

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

app.get('/checkCompletedTrips/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }
    // SECURITY FIX: only the account owner can view their own completed-trips list
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized.' });
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

// SECURITY FIX: this is a system-wide maintenance job meant to be triggered by an internal
// scheduler (cron), not by end users, and should not be a freely-callable public endpoint.
// Gate it behind a shared internal secret, set INTERNAL_JOB_SECRET in your environment and
// have your scheduler send it as X-Internal-Job-Secret.
function requireInternalJobSecret(req, res, next) {
  const provided = req.get('X-Internal-Job-Secret');
  if (!process.env.INTERNAL_JOB_SECRET || provided !== process.env.INTERNAL_JOB_SECRET) {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }
  next();
}

app.post('/autoUpdateCompletedTrips', requireInternalJobSecret, async (req, res) => {
  try {
    await db.query(`UPDATE travel_plans SET status = 'Trip Completed' WHERE status = 'Trip Active' AND time < NOW()`);
    await db.query(`UPDATE travel_plans_cab SET status = 'Trip Completed' WHERE status = 'Trip Active' AND time < NOW()`);
    res.json({ success: true, message: "Trips updated" });
  } catch (error) {
    console.error('Error auto-updating trips:', error);
    res.status(500).json({ success: false });
  }
});

app.get('/tripStats/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }
    // SECURITY FIX: only the account owner can view their own trip statistics
    if (parseInt(userId) !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized.' });
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

// SECURITY FIX: /reset-password previously required NOTHING but a phone number to take
// over any account. It now requires a valid, freshly-verified OTP for that phone number.
// This uses Twilio Verify (the `twilio` client is already configured above) and requires
// a TWILIO_VERIFY_SERVICE_SID env var. If you already have your own OTP table/flow
// elsewhere in the codebase, wire that verification check in here instead — the important
// part is that SOME proof of phone ownership is checked before the UPDATE below runs.

app.post('/request-password-reset-otp', otpLimiter, async (req, res) => {
    const TAG = "/request-password-reset-otp";
    try {
        const { phone, country_code } = req.body;
        if (!phone || !country_code) {
            return res.status(400).json({ success: false, message: 'Phone and country code are required' });
        }

        const [userRows] = await db.query(
            'SELECT id FROM users WHERE phone = ? AND country_code = ?',
            [phone, country_code]
        );

        // Always respond with the same generic message whether or not the user exists,
        // so this endpoint can't be used to enumerate registered phone numbers.
        if (userRows.length > 0 && process.env.TWILIO_VERIFY_SERVICE_SID) {
            try {
                await client.verify.v2
                    .services(process.env.TWILIO_VERIFY_SERVICE_SID)
                    .verifications.create({ to: `${country_code}${phone}`, channel: 'sms' });
            } catch (twilioErr) {
                console.error(TAG, "Twilio send error:", twilioErr.message);
            }
        }

        res.json({ success: true, message: 'If this number is registered, a verification code has been sent.' });
    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/reset-password', authLimiter, async (req, res) => {
    const TAG = "/reset-password";
    try {
        const { phone, country_code, newPassword, otp } = req.body;

        if (!phone || !country_code || !newPassword || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Phone, country code, verification code, and new password are required'
            });
        }

        if (newPassword.length < 7 || !/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 7 characters and include letters, numbers, and symbols." 
            });
        }

        // SECURITY FIX: verify proof of phone ownership before allowing the reset.
        if (!process.env.TWILIO_VERIFY_SERVICE_SID) {
            console.error(TAG, "TWILIO_VERIFY_SERVICE_SID not configured; refusing reset for safety.");
            return res.status(500).json({ success: false, message: "Password reset is temporarily unavailable." });
        }
        try {
            const check = await client.verify.v2
                .services(process.env.TWILIO_VERIFY_SERVICE_SID)
                .verificationChecks.create({ to: `${country_code}${phone}`, code: otp });
            if (check.status !== 'approved') {
                return res.status(401).json({ success: false, message: 'Invalid or expired verification code.' });
            }
        } catch (twilioErr) {
            console.error(TAG, "Twilio verify error:", twilioErr.message);
            return res.status(401).json({ success: false, message: 'Invalid or expired verification code.' });
        }

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

        const isSamePassword = await bcrypt.compare(newPassword, user.password);

        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: "Your new password cannot be the same as your current password. Please choose a different one."
            });
        }

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

app.get("/getUserByPhone", authenticateToken, authLimiter, async (req, res) => {
    // SECURITY FIX: require auth + rate limit so this can't be used as an anonymous,
    // unlimited phone-number -> profile lookup/enumeration oracle.
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

// Locate app.post('/markMessagesRead'...) in your server code and replace it:
app.post('/markMessagesRead', authenticateToken, async (req, res) => {
  try {
    // SECURITY FIX: identity from the verified token, not the request body
    const userId = req.user.id;
    const { otherUserId } = req.body;
    if (!otherUserId) {
      return res.status(400).json({ success: false, message: 'otherUserId is required' });
    }

    // Explicitly parse IDs as base-10 integers to prevent type mismatches
    const targetUid = parseInt(userId, 10);
    const partnerUid = parseInt(otherUserId, 10);

    // 1. Clear text messages unread parameters safely
    const queryMessages = `
      UPDATE messages 
      SET status = 2 
      WHERE sender_id = ? AND receiver_id = ? AND status < 2
    `;
    const [result] = await db.execute(queryMessages, [partnerUid, targetUid]);  

    // 2. Clear ephemeral shared media unread parameters safely
    const queryMedia = `
      UPDATE shared_media
      SET downloaded_at = NOW()
      WHERE sender_id = ? AND receiver_id = ? AND downloaded_at IS NULL
    `;
    await db.execute(queryMedia, [partnerUid, targetUid]);

    res.json({ success: true, message: 'Messages marked as read', markedCount: result.affectedRows });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ success: false, message: 'Failed to mark messages as read' });
  }
});

app.get('/getUnreadCount', authenticateToken, async (req, res) => {
  try {
    // SECURITY FIX: identity from the verified token, not the request query
    const userId = req.user.id;
    const { otherUserId } = req.query;
    if (!otherUserId) {
      return res.status(400).json({ success: false, message: 'otherUserId is required' });
    }
    const query = `SELECT COUNT(*) as unreadCount FROM messages WHERE sender_id = ? AND receiver_id = ? AND status < 2`;
    const [rows] = await db.execute(query, [otherUserId, userId]);
    res.json({ success: true, unreadCount: rows[0].unreadCount });
  } catch (error) {
    console.error('Error getting unread count:', error);
    res.status(500).json({ success: false, message: 'Failed to get unread count' });
  }
});

app.get('/getTotalUnreadCount', authenticateToken, async (req, res) => {
    const TAG = "/getTotalUnreadCount"; 
    // SECURITY FIX: identity from the verified token, not the request query
    const currentUserId = req.user.id;
    try {
        // ─── OPTIMIZED: COUNTS TEXT MESSAGES AND LIVE SHARED MEDIA ASSETS SIMULTANEOUSLY ───
        const individualQuery = `
            SELECT 
                (SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND status < 2 AND message_type NOT IN ('image', 'video')) +
                (SELECT COUNT(*) FROM shared_media WHERE receiver_id = ? AND expires_at > NOW() AND downloaded_at IS NULL) 
            as totalUnreadCount`;
        
        const [individualRows] = await db.execute(individualQuery, [currentUserId, currentUserId]);

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

app.post("/hideChat", authenticateToken, async (req, res) => {
    const TAG = "/hideChat"; 
    try {
        // SECURITY FIX: identity from the verified token, not the request body — otherwise
        // any caller could hide/purge another user's chat history.
        const userId = req.user.id;
        const { otherUserId, isGroup } = req.body; 
        if (!otherUserId) return res.status(400).json({ success: false });

        if (isGroup) {
            const [messages] = await db.query(`SELECT message_id FROM group_messages WHERE group_id = ?`, [otherUserId]);
            if (messages.length === 0) return res.json({ success: true });

            const valuesToHide = messages.map(msg => [msg.message_id, userId, new Date()]);
            await db.query(`INSERT IGNORE INTO group_hidden_messages (message_id, user_id, hidden_at) VALUES ?`, [valuesToHide]);

            const messageIds = messages.map(m => m.message_id);
            const [fullyHidden] = await db.query(`
                SELECT ghm.message_id 
                FROM group_hidden_messages ghm
                JOIN group_messages gm ON ghm.message_id = gm.message_id
                WHERE ghm.message_id IN (?)
                GROUP BY ghm.message_id
                HAVING COUNT(DISTINCT ghm.user_id) >= (SELECT COUNT(*) FROM group_members WHERE group_id = ?)
            `, [messageIds, otherUserId]);

            if (fullyHidden.length > 0) {
                const idsToDelete = fullyHidden.map(x => x.message_id);
                await db.query(`DELETE FROM group_messages WHERE message_id IN (?)`, [idsToDelete]);
                await db.query(`DELETE FROM group_hidden_messages WHERE message_id IN (?)`, [idsToDelete]);
                await db.query(`DELETE FROM group_message_read_status WHERE message_id IN (?)`, [idsToDelete]);
                console.log(TAG, `Permanently deleted ${idsToDelete.length} messages as all group members cleared history.`);
            }
        } else {
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

// SECURITY FIX: system-wide maintenance job, not a per-user action — restrict to internal callers
app.post("/cleanupDeletedMessages", requireInternalJobSecret, async (req, res) => {
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

// BEFORE: app.delete('/deleteMessage/:messageId', async (req, res) => { ...
// AFTER:
app.delete('/deleteMessage/:messageId', authenticateToken, async (req, res) => {
  const TAG = "DELETE /deleteMessage";
  try {
    const { messageId } = req.params;
    // SECURE FIX: Enforce identity from JWT instead of body
    const userId = req.user.id; 
    
    if (!userId) return res.status(400).json({ success: false });
    
    const [messages] = await db.execute('SELECT * FROM messages WHERE id = ?', [messageId]);
    if (messages.length === 0) return res.status(404).json({ success: false });
    
    const msg = messages[0];
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

app.get('/favorites/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    
    if (!userId) {
        return res.status(400).json({ success: false, message: "Missing required parameter" });
    }

    try {
        const targetUserId = parseInt(userId);

        // SECURE FIX: Prevent a user from requesting someone else's pinned favorites list
        if (req.user.id !== targetUserId) {
            return res.status(403).json({ 
                success: false, 
                message: "Access Denied: You cannot view another user's favorite routes." 
            });
        }

        const [favorites] = await db.query(
            `SELECT id, user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng 
             FROM favorites 
             WHERE user_id = ? 
             ORDER BY routeName ASC`, 
            [targetUserId]
        );

        res.json({ success: true, favorites: favorites });
    } catch (error) {
        console.error("Error fetching favorites:", error);
        res.status(500).json({ success: false });
    }
});

app.post('/favorites', authenticateToken, async (req, res) => {
    const { routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;
    const userId = req.user.id; // SECURE FIX
    
    if (!userId || !routeName || !fromPlace || !toPlace || fromPlaceLat === undefined) return res.status(400).json({ success: false });
    try {
        const query = `INSERT INTO favorites (user_id, routeName, from_place, to_place, from_place_lat, from_place_lng, to_place_lat, to_place_lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        const [result] = await db.query(query, [userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng]);
        res.status(201).json({ success: true, favoriteId: result.insertId });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.get("/user/:userId", authenticateToken, async (req, res) => {
    const TAG = "/user/:userId"; 
    try {
        const { userId } = req.params; 
        // SECURITY FIX: viewerId gates friend-visibility logic below, so it must come from
        // the verified token, not a self-reported query param.
        const viewerId = req.user.id;

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
                user_id,
                CONCAT(first_name, ' ', last_name) as name, 
                work_category, 
                phone,
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

        // SECURITY FIX: phone number was previously returned to ANY viewer regardless of
        // visibility settings. Only return it when viewing your own profile. If your product
        // intentionally shares phone numbers with friends/chat partners, relax this to
        // `if (parseInt(userId) !== viewerId && !user.hasChat) delete user.phone;` instead.
        if (parseInt(userId) !== viewerId) {
            delete user.phone;
        }

        res.json({ success: true, user: user }); 
    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false });
    }
});

app.delete('/favorites/:userId/:favoriteId', authenticateToken, async (req, res) => {
    const { userId, favoriteId } = req.params;
    
    // SECURE FIX: Prevent modifying another user's choices
    if (parseInt(userId) !== req.user.id) {
        return res.status(403).json({ success: false, message: "Unauthorized action." });
    }
    
    try {
        const [result] = await db.query(`DELETE FROM favorites WHERE id = ? AND user_id = ?`, [favoriteId, userId]);
        res.json({ success: result.affectedRows > 0 });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.put('/settings/visibility', authenticateToken, async (req, res) => {
    const { visibility } = req.body;
    
    if (!visibility) {
        return res.status(400).json({ success: false, message: "Missing visibility parameter" });
    }

    try {
        // SECURE FIX: Enforce user identity directly from the verified token
        const authenticatedUserId = req.user.id;

        await db.query(
            'UPDATE users SET profile_visibility = ? WHERE id = ?', 
            [visibility, authenticatedUserId]
        );

        res.json({ success: true, message: "Visibility settings updated successfully." });
    } catch (error) {
        console.error("Error updating visibility settings:", error);
        res.status(500).json({ success: false });
    }
});

app.post('/change-password', authenticateToken, authLimiter, async (req, res) => {
    try {
        // SECURITY FIX: identity must come from the verified JWT, never from the request body
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        if (!newPassword || newPassword.length < 7) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password doesn’t contain 7 characters' 
            });
        }

        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(404).json({ success: false });

        const isMatch = await bcrypt.compare(currentPassword, rows[0].password);
        if (!isMatch) return res.status(400).json({ success: false, message: 'Current password is incorrect' });
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

app.get('/api/online-users', authenticateToken, (req, res) => {
  // SECURITY FIX: this dumped every user's online/last-seen status with no auth at all.
  res.json({ success: true, onlineUsers: Array.from(onlineUsers.entries()).map(([userId, data]) => ({ userId, isOnline: data.isOnline, lastSeen: data.lastSeen })) });
});

app.get('/api/user-status/:userId', authenticateToken, async (req, res) => {
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

app.get('/group-members/:groupId', authenticateToken, async (req, res) => {
    const { groupId } = req.params;
    
    if (!groupId || isNaN(groupId)) {
        return res.status(400).json({ success: false, message: "Valid Group ID is required" });
    }

    try {
        const targetGroupId = parseInt(groupId);
        const authenticatedUserId = req.user.id;

        // SECURE FIX: Verify that the requesting user is actually a member of this group
        const [membershipCheck] = await db.execute(
            'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
            [targetGroupId, authenticatedUserId]
        );

        if (membershipCheck.length === 0) {
            return res.status(403).json({ 
                success: false, 
                message: "Access Denied: You are not a member of this group channel." 
            });
        }

        // 1. Fetch group meta details safely
        const [groupRows] = await db.execute(
            'SELECT group_icon, group_name FROM group_table WHERE group_id = ?', 
            [targetGroupId]
        );

        // 2. Fetch members list (including u.gender as implemented for your default PFP feature logic)
        const [members] = await db.execute(
            `SELECT u.id AS user_id, CONCAT(u.first_name, ' ', u.last_name) as name, u.phone, u.profile_pic, u.gender 
             FROM group_members gm 
             JOIN users u ON gm.user_id = u.id 
             WHERE gm.group_id = ? 
             ORDER BY u.first_name ASC`, 
            [targetGroupId]
        );

        res.json({ 
            success: true, 
            group_icon: groupRows[0]?.group_icon || null, 
            group_name: groupRows[0]?.group_name || "Group", 
            members: members 
        });

    } catch (error) {
        console.error("Error inside secured /group-members route handler:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// AFTER:
app.post('/leaveGroup', authenticateToken, async (req, res) => {
    const { groupId } = req.body;
    const userId = req.user.id; // SECURE FIX
    
    try {
        const [userRows] = await db.query(
            "SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", 
            [userId]
        );
        const userName = userRows.length > 0 ? userRows[0].name : "Someone";

        await db.query("DELETE FROM group_members WHERE user_id = ? AND group_id = ?", [userId, groupId]);

        const systemMessage = `${userName} left the group`;
        const encrypted = encrypt(systemMessage);
        const [result] = await db.query(
            `INSERT INTO group_messages (group_id, sender_id, message_content, timestamp, message_type) 
             VALUES (?, ?, ?, NOW(), 'system')`,
            [groupId, userId, encrypted]
        );

        io.to(`group_${groupId}`).emit('new_group_message', {
            id: result.insertId,
            group_id: groupId,
            sender_id: userId,
            sender_name: userName,
            message: systemMessage,
            message_type: 'system',
            timestamp: new Date().toISOString()
        });

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

app.post('/update-group-icon', authenticateToken, upload.single('group_icon'), async (req, res) => {
    const groupId = req.body.group_id;
    const cloudinaryUrl = req.file?.path;
    if (!groupId || !cloudinaryUrl) return res.status(400).json({ success: false });
    try {
        // SECURITY FIX: only an existing member of the group can change its icon
        const [membership] = await db.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, req.user.id]);
        if (membership.length === 0) {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        await db.execute('UPDATE group_table SET group_icon = ? WHERE group_id = ?', [cloudinaryUrl, groupId]);
        res.json({ success: true, group_icon: cloudinaryUrl });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post('/remove-group-icon', authenticateToken, async (req, res) => {
    const { group_id } = req.body;
    try {
        // SECURITY FIX: only an existing member of the group can remove its icon
        const [membership] = await db.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [group_id, req.user.id]);
        if (membership.length === 0) {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        await db.execute('UPDATE group_table SET group_icon = NULL WHERE group_id = ?', [group_id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.get('/group/:groupId/messages', authenticateToken, async (req, res) => {
    const { groupId } = req.params;
    
    // SECURE FIX: Grab verified identity from payload token context
    const userId = req.user.id;

    try {
        const [memberCheck] = await db.query(
            `SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?`,
            [groupId, userId]
        );

        if (memberCheck.length === 0) {
            await db.query(
                `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`,
                [groupId, userId]
            );
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
                gm.quoted_message,
                gm.quoted_user_name,
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
              AND NOT EXISTS (
                  SELECT 1 FROM group_hidden_messages ghm 
                  WHERE ghm.message_id = gm.message_id 
                  AND ghm.user_id = ?
              )
            ORDER BY gm.timestamp ASC
            LIMIT 300`;

        const [messages] = await db.execute(query, [groupId, groupId, userId]);

        const decrypted = messages.map(msg => {
            const msgType = (msg.message_type || '').toLowerCase();
            // image/video messages store the raw Cloudinary URL — do not decrypt them
            if (msgType === 'image' || msgType === 'video') {
                return { ...msg, media_url: msg.message };
            }
            try {
                return { ...msg, message: decrypt(msg.message) };
            } catch (e) {
                return { ...msg, message: msg.message };
            }
        });

        res.json({ success: true, messages: decrypted });
    } catch (error) { 
        console.error("Error fetching group messages:", error);
        res.status(500).json({ success: false });   
    }
});

app.get('/group/by-name', authenticateToken, async (req, res) => {
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

app.post('/group/send', authenticateToken, async (req, res) => {
    const TAG = "/group/send";
    const { 
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

    // SECURE FIX: Bind the message execution directly to the verified sender_id token variable
    const sender_id = req.user.id;

    try {
        console.log(TAG, "Received request:", { sender_id, group_id, message_content, message_type, has_reply: !!reply_to_id });

        if (!group_id || group_id === 0) {
            return res.status(400).json({
                success: false,
                error: "Invalid group_id. Group ID must be a valid number."
            });
        }

        const [userRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [sender_id]);

        if (userRows.length === 0) {
            return res.status(404).json({ success: false, error: "Sender user not found." });
        }
        const senderName = userRows[0].name;

        const [groupCheck] = await db.query('SELECT group_id, group_name, group_icon FROM `group_table` WHERE group_id = ?', [group_id]);

        if (groupCheck.length === 0) {
            console.log(TAG, "Group not found:", group_id);
            return res.status(404).json({
                success: false,
                error: "Group does not exist. Please create or join the group first."
            });
        }

        const groupName = groupCheck[0].group_name;

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
        
        const encrypted = encrypt(message_content);

        let expiresAt = null;
        if (message_type === 'live_location') {
            const durationInt = parseInt(duration);

            if (durationInt === -1) {
                expiresAt = '2099-12-31 23:59:59';
            } else {
                const finalDuration = (durationInt > 0) ? durationInt : 60;
                const expiryDate = new Date(Date.now() + finalDuration * 60000);
                expiresAt = expiryDate.toISOString().slice(0, 19).replace('T', ' ');
            }
            console.log(TAG, "Calculated Group Expiry:", expiresAt);
        }

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

app.post("/group/deleteMessageForMe", authenticateToken, async (req, res) => {
  try {
    // SECURITY FIX: identity from the verified token, not the request body
    const userId = req.user.id;
    const { messageId } = req.body;
    if (!messageId) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

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

app.delete('/group/deleteMessageForEveryone/:messageId', authenticateToken, async (req, res) => {
  try {
    const { messageId } = req.params;
    // SECURITY FIX: identity from the verified token, not the request body — this is what
    // the "only sender can delete" check below relies on, so it must not be spoofable.
    const userId = req.user.id;

    const [msgRows] = await db.execute('SELECT sender_id, group_id FROM group_messages WHERE message_id = ?', [messageId]);
    if (msgRows.length === 0) return res.status(404).json({ success: false });

    const msg = msgRows[0];
    if (msg.sender_id != userId) return res.status(403).json({ success: false, message: "Only sender can delete for everyone" });

    await db.execute('DELETE FROM group_messages WHERE message_id = ?', [messageId]);
    await db.execute('DELETE FROM group_hidden_messages WHERE message_id = ?', [messageId]);

    io.to(`group_${msg.group_id}`).emit('message_deleted', { messageId: parseInt(messageId) });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});


app.get('/group/:groupId/members', authenticateToken, async (req, res) => {
    const { groupId } = req.params;
    try {
        // SECURITY FIX: only existing members can list who else is in the group
        const [membership] = await db.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, req.user.id]);
        if (membership.length === 0) {
            return res.status(403).json({ success: false, message: "Unauthorized." });
        }
        const query = `
            SELECT 
                u.id, 
                u.id as userId, 
                CONCAT(u.first_name, ' ', u.last_name) as name, 
                u.profile_pic as profilePic,
                u.gender 
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
        res.status(500).json({ success: false });
    }
});

// AFTER:
app.post('/group/read', authenticateToken, async (req, res) => {
    const { group_id } = req.body;
    const user_id = req.user.id; // SECURE FIX: Bind strictly to verified token identity

    if (!group_id) {
        return res.status(400).json({ success: false, message: "Group ID is required" });
    }

    try {
        // Optional Security Check: Verify the user is actually a member of this group before updating status
        const [membershipCheck] = await db.execute(
            'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
            [group_id, user_id]
        );

        if (membershipCheck.length === 0) {
            return res.status(403).json({ success: false, message: "Unauthorized: You are not a member of this group." });
        }

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
        console.error("Error in group/read:", error);
        res.status(500).json({ success: false });
    }
});

app.post('/group/stop-location', authenticateToken, async (req, res) => {
    const TAG = "/group/stop-location";
    // SECURITY FIX: identity from the verified token, not the request body
    const userId = req.user.id;
    const { groupId } = req.body;

    if (!groupId) {
        return res.status(400).json({ success: false, message: "Missing groupId" });
    }

    try {
        console.log(TAG, `Stopping live location for user ${userId} in group ${groupId}`);

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
        res.status(500).json({ success: false });
    }
});

app.get('/searchUsers', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request query — it gates
    // friend-visibility logic and excludes the caller from their own results.
    const currentUserId = req.user.id;
    const { query } = req.query;
    const searchTerm = query ? query.trim().toLowerCase() : "";
    
    if (!searchTerm) return res.json({ success: true, users: [] });

    try {
        const [friendRows] = await db.query(
            `SELECT DISTINCT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id 
             FROM messages WHERE sender_id = ? OR receiver_id = ?`, 
            [currentUserId, currentUserId, currentUserId]
        );
        const friendIds = new Set(friendRows.map(row => row.friend_id));

        // Locate app.get('/searchUsers'...) and update the sql text block to include u.user_id:
const sql = `
    SELECT u.id, u.user_id, u.first_name, u.last_name, 
           CONCAT(u.first_name, ' ', u.last_name) as name, 
           u.work_category, u.work_detail, u.profile_pic, u.gender, u.profile_visibility,
           EXISTS (
                SELECT 1 FROM messages m 
                WHERE (m.sender_id = ? AND m.receiver_id = u.id) 
                   OR (m.sender_id = u.id AND m.receiver_id = ?)
            ) as hasChat,
           CASE 
                WHEN LOWER(u.user_id) LIKE ? THEN 0   -- Highest priority if matching unique user_id
                WHEN LOWER(u.first_name) LIKE ? THEN 1
                WHEN LOWER(u.last_name) LIKE ? THEN 2
                ELSE 3
           END as search_priority
    FROM users u 
    WHERE (LOWER(u.first_name) LIKE ? OR LOWER(u.last_name) LIKE ? OR LOWER(CONCAT(u.first_name, ' ', u.last_name)) LIKE ? OR LOWER(u.user_id) LIKE ?)
      AND u.id != ? 
    ORDER BY search_priority ASC, u.first_name ASC 
    LIMIT 100`;

const searchLike = `%${searchTerm}%`;
const startLike = `${searchTerm}%`;

const [users] = await db.execute(sql, [
    currentUserId, currentUserId, 
    startLike, // user_id priority match
    startLike, 
    startLike, 
    searchLike, searchLike, searchLike, searchLike, // user_id context match
    currentUserId 
]);

        const response = users.map(u => ({ 
            ...u, 
            hasChat: Boolean(u.hasChat),
            profile_pic: getVisibleProfilePic(u, parseInt(currentUserId), friendIds) 
        }));

        res.json({ success: true, users: response });
    } catch (err) {
        console.error("Search Error:", err);
        res.status(500).json({ success: false });
    }
});

app.post('/sendChatRequest', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request body
    const senderId = req.user.id;
    const { receiverId, message } = req.body;

    if (!receiverId || !message) {
        return res.status(400).json({ success: false, message: "Missing data" });
    }

    try {
        // Force the timezone to IST regardless of where the server is hosted
        const now = new Date();
        const timestamp = now.toLocaleString('en-IN', { 
            timeZone: 'Asia/Kolkata',
            month: 'short', 
            day: '2-digit', 
            hour: '2-digit', 
            minute: '2-digit', 
            hour12: false // Set to true if you want 11:43 PM format
        });

        // The ──────────────── line break helps with the "separate lines" requirement
        const formattedEntry = `[${timestamp}]\n${message}\n────────────────`;

        const sql = `
            INSERT INTO chat_requests (sender_id, receiver_id, status, initial_message) 
            VALUES (?, ?, 'pending', ?) 
            ON DUPLICATE KEY UPDATE 
                initial_message = CONCAT(initial_message, '\n\n', VALUES(initial_message)),
                status = 'pending'
        `;
        
        await db.execute(sql, [senderId, receiverId, formattedEntry]);

        io.to(`chat_${receiverId}`).emit('new_chat_request', { 
            senderId, 
            message: formattedEntry 
        });

        res.json({ success: true });
    } catch (err) {
        console.error("SQL Error:", err);
        res.status(500).json({ success: false });
    }
});

app.post('/handleChatRequest', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request body — this is the
    // receiver deciding to accept/reject, so it must be the authenticated caller.
    const userId = req.user.id; // userId = Receiver
    const { otherUserId, action } = req.body;
    try {
        if (action === 'accept') {
            const [request] = await db.execute(
                `SELECT initial_message, sender_id, receiver_id 
                 FROM chat_requests 
                 WHERE sender_id = ? AND receiver_id = ?`, 
                [otherUserId, userId]
            );

            if (request.length > 0) {
                const originalSender = request[0].sender_id;
                const originalReceiver = request[0].receiver_id;
                let rawMessage = request[0].initial_message;

                // --- CLEANING LOGIC ---
                // 1. Remove the timestamps like [Apr 01, 17:05]
                // 2. Remove the separator lines ────────────────
                // 3. Trim extra newlines
                let cleanMessage = rawMessage
                    .replace(/\[.*?\d{2}:\d{2}\]/g, '') // Removes [Date, Time]
                    .replace(/────────────────/g, '')    // Removes the lines
                    .replace(/\n\s*\n/g, '\n')          // Collapses multiple newlines into one
                    .trim();

                const { encrypt } = require('./cryptoHelper');
                const encrypted = encrypt(cleanMessage);

                // Insert into main messages table
                await db.execute(
                    `INSERT INTO messages (sender_id, receiver_id, message, timestamp, status) 
                     VALUES (?, ?, ?, UTC_TIMESTAMP(), 0)`, 
                    [originalSender, originalReceiver, encrypted]
                );

                // Mark request as accepted
                await db.execute(
                    `UPDATE chat_requests SET status = 'accepted' 
                     WHERE sender_id = ? AND receiver_id = ?`, 
                    [originalSender, originalReceiver]
                );
            }
            res.json({ success: true });
        } else {
            // Reject logic remains the same (Soft delete/status update)
            await db.execute(
                `UPDATE chat_requests SET status = 'rejected' 
                 WHERE sender_id = ? AND receiver_id = ?`, 
                [otherUserId, userId]
            );
            res.json({ success: true });
        }
    } catch (err) {
        console.error("Handle Request Error:", err);
        res.status(500).json({ success: false });
    }
});

app.get('/checkChatRequest', authenticateToken, async (req, res) => {
    // SECURITY FIX: the caller must be the sender being checked; identity from the token
    const senderId = req.user.id;
    const { receiverId } = req.query;
    try {
        const [rows] = await db.execute(
            `SELECT initial_message FROM chat_requests 
             WHERE sender_id = ? AND receiver_id = ? AND status 
IN ('pending','rejected')`,
            [senderId, receiverId]
        );
        
        if (rows.length > 0) {
            res.json({ success: true, exists: true, message: rows[0].initial_message });
        } else {
            res.json({ success: true, exists: false });
        }
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.post('/deleteChatRequest', authenticateToken, async (req, res) => {
    // SECURITY FIX: only the original sender can cancel their own pending request
    const senderId = req.user.id;
    const { receiverId } = req.body;
    try {
        await db.execute(
            `DELETE FROM chat_requests 
             WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'`,
            [senderId, receiverId]
        );
        
        // Optional: Emit socket event so Hitesh's list updates in real-time
        io.to(`chat_${receiverId}`).emit('chat_request_cancelled', { senderId });
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/chatRequests', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request query
    const userId = req.user.id;
    try {
        const sql = `SELECT cr.id as requestId, cr.initial_message, u.id as userId, CONCAT(u.first_name, ' ', u.last_name) as name, u.profile_pic, u.gender, u.work_category FROM chat_requests cr 
JOIN users u ON cr.sender_id = u.id WHERE cr.receiver_id = ? AND cr.status = 'pending' ORDER BY cr.id DESC`;
        const [requests] = await db.execute(sql, [userId]);
        res.json({ success: true, requests: requests.map(r => ({ ...r, lastMessage: r.initial_message || "Sent a request" })) });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

app.get('/chatRequests/count', authenticateToken, async (req, res) => {
    // SECURITY FIX: identity from the verified token, not the request query
    const userId = req.user.id;
    try {
        const [rows] = await db.execute(`SELECT COUNT(*) as count FROM chat_requests WHERE receiver_id = ? AND status = 'pending'`, [userId]);
        res.json({ success: true, count: rows[0].count });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ================= SHARABLE EPHEMERAL MEDIA ROUTES =================

app.post("/api/media/send", authenticateToken, uploadSharedMedia.single("media_file"), async (req, res) => {
    const TAG = "/api/media/send";
    try {
        const { receiver_id, media_type } = req.body;
        const sender_id = req.user.id;

        if (!sender_id || !receiver_id || !media_type || !req.file) {
            return res.status(400).json({ success: false, message: "Required parameter variables are missing." });
        }

        const mediaUrl = req.file.path;
        const cloudinaryPublicId = req.file.filename || req.file.public_id || "raw_id";

        // 1. Insert into core messages table first to get a permanent message history ID
        const [msgResult] = await db.execute(
            `INSERT INTO messages (sender_id, receiver_id, message, timestamp, status, message_type) 
             VALUES (?, ?, ?, NOW(), 1, ?)`,
            [sender_id.toString(), parseInt(receiver_id), mediaUrl, media_type]
        );
        const permanentMessageId = msgResult.insertId;

        // 2. TiDB execution saves the baseline entry inside shared_media table using the same shared ID
        const insertQuery = `
            INSERT INTO shared_media 
            (id, sender_id, receiver_id, media_type, media_url, cloudinary_public_id, send_at, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 3 HOUR))
        `;
        await db.execute(insertQuery, [
            permanentMessageId,
            sender_id.toString(),
            parseInt(receiver_id),
            media_type,
            mediaUrl,
            cloudinaryPublicId
        ]);

        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 3);

        const payloadToEmit = {
            id: permanentMessageId,
            sender_id: parseInt(sender_id),
            receiver_id: parseInt(receiver_id),
            message_type: media_type, // "image" or "video"
            message: mediaUrl,        
            media_url: mediaUrl,
            timestamp: new Date().toISOString(),
            expires_at: expiryDate.toISOString(),
            status: 1, 
            group_id: 0
        };

        // Broadcast out to listeners
        io.to(`chat_${receiver_id}`).emit('new_media_received', payloadToEmit);
        io.to(`user_${receiver_id}`).emit('new_media_received', payloadToEmit);
        io.to(`chat_${sender_id}`).emit('new_media_received', payloadToEmit);

        try {
            const receiverIdStr = receiver_id.toString();
            const activeSession = activeChatSessions.get(receiverIdStr);
            const isLookingAtThisChat = activeSession === `user_${sender_id}`;

            if (!isLookingAtThisChat) {
                const [rcvRows] = await db.query("SELECT fcm_token FROM users WHERE id = ?", [receiver_id]);
                const [sndRows] = await db.query("SELECT CONCAT(first_name,' ',last_name) as name, profile_pic FROM users WHERE id = ?", [sender_id]);

                if (rcvRows.length > 0 && rcvRows[0].fcm_token) {
                    const sndName = sndRows.length > 0 ? sndRows[0].name : "New Message";
                    const rPic  = sndRows.length > 0 ? sndRows[0].profile_pic : "";
                    const notifBody = media_type === 'video' ? '🎥 Video' : '📷 Photo';
                    await admin.messaging().send({
                        token: rcvRows[0].fcm_token,
                        notification: { title: sndName, body: notifBody },
                        data: {
                            type: "chat",
                            senderId: sender_id.toString(),
                            senderName: sndName,
                            senderProfilePic: rPic || "",
                            chatPartnerId: sender_id.toString(),
                            title: sndName,
                            body: notifBody,
                            groupKey: "com.swarajyadav.CHAT_GROUP_" + sender_id.toString()
                        },
                        android: {
                            priority: "high",
                            notification: { channelId: "channel_custom_sound_v3", sound: "custom_notification", tag: sender_id.toString() }
                        }
                    });
                }
            }
        } catch (fcmErr) {
            console.error("/api/media/send-media FCM error:", fcmErr.message);
        }

        res.status(201).json({
            success: true,
            message: "Media transmitted and entries logged successfully.",
            data: payloadToEmit
        });

    } catch (err) {
        console.error(TAG, "Transaction exception loop error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/media/mark-read', authenticateToken, async (req, res) => {
    const TAG = '/api/media/mark-read';
    try {
        // receiver calls this; sender_id = the person who sent media TO the receiver
        const { sender_id, receiver_id } = req.body;
        const callerId = req.user.id;          // the authenticated user (receiver)
 
        // Safety: only the actual receiver may mark their own media as read
        if (parseInt(receiver_id) !== callerId) {
            return res.status(403).json({ success: false, message: 'Forbidden' });
        }
 
        await db.execute(
            `UPDATE shared_media
                SET downloaded_at = NOW()
              WHERE sender_id = ?
                AND receiver_id = ?
                AND downloaded_at IS NULL`,
            [parseInt(sender_id), callerId]
        );
 
        res.json({ success: true });
    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/media/send-group", authenticateToken, uploadSharedMedia.single("media_file"), async (req, res) => {
    const TAG = "/api/media/send-group";
    try {
        const { group_id, media_type } = req.body;
        const sender_id = req.user.id;

        if (!sender_id || !group_id || !media_type || !req.file) {
            return res.status(400).json({ success: false, message: "Required fields missing." });
        }

        // Verify membership
        const [memberCheck] = await db.query(
            "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
            [parseInt(group_id), sender_id]
        );
        if (memberCheck.length === 0) {
            return res.status(403).json({ success: false, message: "Not a group member." });
        }

        const mediaUrl        = req.file.path;
        const cloudinaryPubId = req.file.filename || req.file.public_id || "raw_id";

        // 1. Fetch sender name and group name for socket payload + FCM
        const [userRows] = await db.query(
            "SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?",
            [sender_id]
        );
        const senderName = userRows.length > 0 ? userRows[0].name : "Member";

        const [groupRows] = await db.query(
            "SELECT group_name FROM `group_table` WHERE group_id = ?",
            [parseInt(group_id)]
        );
        const groupName = groupRows.length > 0 ? groupRows[0].group_name : "Group";

        // 2. Persist to shared_media for Cloudinary download-complete tracking ledger
        const [smResult] = await db.execute(
            `INSERT INTO shared_media
             (sender_id, receiver_id, group_id, media_type, media_url, cloudinary_public_id, send_at, expires_at)
             VALUES (?, NULL, ?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 72 HOUR))`,
            [sender_id, parseInt(group_id), media_type, mediaUrl, cloudinaryPubId]
        );
        const sharedMediaId = smResult.insertId;


        const [gmResult] = await db.execute(
            `INSERT INTO group_messages
             (group_id, sender_id, message_content, timestamp, message_type,
              latitude, longitude, reply_to_id, quoted_sender_id, quoted_message,
              quoted_user_name, expires_at, duration)
             VALUES (?, ?, ?, NOW(), ?, NULL, NULL, NULL, NULL, NULL, NULL,
                     DATE_ADD(NOW(), INTERVAL 72 HOUR), 0)`,
            [parseInt(group_id), sender_id, mediaUrl, media_type]
        );
        const newMessageId = gmResult.insertId;

        // 4. Build socket payload
        const payloadToEmit = {
            id:           newMessageId,
            group_id:     parseInt(group_id),
            sender_id:    sender_id,
            sender_name:  senderName,
            message_type: media_type,
            message:      mediaUrl,
            media_url:    mediaUrl,
            timestamp:    new Date().toISOString(),
            status:       1
        };

        // 5. Broadcast to all group members in the socket room
        io.to(`group_${group_id}`).emit("new_group_message", payloadToEmit);

        // 6. FCM push notification to offline members
        try {
            const [members] = await db.query(`
                SELECT u.id, u.fcm_token
                FROM group_members gm
                JOIN users u ON gm.user_id = u.id
                WHERE gm.group_id = ? AND gm.user_id != ?
                  AND u.fcm_token IS NOT NULL AND u.fcm_token != ''
            `, [parseInt(group_id), sender_id]);

            const tokensToNotify = members
                .filter(m => activeChatSessions.get(m.id.toString()) !== `group_${group_id}`)
                .map(m => m.fcm_token);

            if (tokensToNotify.length > 0) {
                const notifBody = media_type === 'video'
                    ? `${senderName}: 🎥 Video`
                    : `${senderName}: 📷 Photo`;
                await admin.messaging().sendEachForMulticast({
                    tokens: tokensToNotify,
                    notification: { title: groupName, body: notifBody },
                    android: {
                        priority: "high",
                        notification: { channelId: "chat_channel_id", sound: "default" }
                    },
                    data: {
                        type: "group_chat",
                        groupId: String(group_id),
                        groupName: groupName,
                        senderId: String(sender_id)
                    }
                });
            }
        } catch (fcmError) {
            console.error(TAG, "FCM Error for group media:", fcmError.message);
        }

        res.status(201).json({
            success:   true,
            messageId: newMessageId,
            data:      payloadToEmit
        });

    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false });
    }
});

app.get("/api/media/fetch/:userId", authenticateToken, async (req, res) => {
    const { userId } = req.params;
    // SECURITY FIX: previously anyone could fetch any user's private shared-media URLs by
    // just changing the :userId in the URL — this is now locked to the account owner.
    if (parseInt(userId) !== req.user.id) {
        return res.status(403).json({ success: false, message: "Unauthorized." });
    }
    try {
        // Enforce strict expiration boundaries matching baseline current timestamp boundaries
        const query = `
            SELECT id, sender_id, media_type, media_url, send_at, expires_at 
            FROM shared_media 
            WHERE receiver_id = ? AND expires_at > NOW() 
            ORDER BY send_at ASC
        `;
        const [rows] = await db.execute(query, [parseInt(userId)]);
        res.json({ success: true, media: rows });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ================= FIXED GROUP/INDIVIDUAL PURGE HANDLER =================

app.post("/api/media/download-complete", authenticateToken, async (req, res) => {
    const TAG = "/api/media/download-complete";
    try {
        const { message_id, group_id } = req.body;
        const current_user_id = req.user.id;

        if (!message_id) {
            return res.status(400).json({ success: false, message: "Missing message_id param." });
        }

        // ─── NEW GROUP MEDIA TRACK-AND-PURGE LOGIC ───
        if (group_id && parseInt(group_id) > 0) {
            const parsedGroupId = parseInt(group_id);
            const parsedMsgId = parseInt(message_id);

            // 1. Log that this user has successfully downloaded/read this message
            await db.execute(
                `INSERT IGNORE INTO group_message_read_status (message_id, user_id, group_id) 
                 VALUES (?, ?, ?)`,
                [parsedMsgId, current_user_id, parsedGroupId]
            );

            // 2. Fetch the current download/read count vs total group size

            // 2. Fetch the current download/read count vs total group size (excluding the sender)
const [countRows] = await db.execute(
    `SELECT 
        (SELECT COUNT(DISTINCT gmrs.user_id) 
         FROM group_message_read_status gmrs
         JOIN group_messages gm ON gmrs.message_id = gm.message_id
         WHERE gmrs.message_id = ? AND gmrs.user_id != gm.sender_id) as downloadedCount,
        
        (SELECT COUNT(*) 
         FROM group_members gmem
         JOIN group_messages gm ON gmem.group_id = gm.group_id
         WHERE gm.message_id = ? AND gmem.user_id != gm.sender_id) as totalReceivers`,
    [parsedMsgId, parsedMsgId]
);

if (countRows.length > 0) {
    const { downloadedCount, totalReceivers } = countRows[0];
    console.log(TAG, `Group Media ${parsedMsgId}: Downloaded by ${downloadedCount}/${totalReceivers} target receivers.`);

    // 3. Purge if everyone except the sender has downloaded it
    if (downloadedCount >= totalReceivers && totalReceivers > 0) {
        // Look up Cloudinary public ID from shared_media or group_messages reference map
        const [mediaRows] = await db.execute(
            "SELECT cloudinary_public_id, media_type FROM shared_media WHERE group_id = ? AND media_url = (SELECT message_content FROM group_messages WHERE message_id = ?)",
            [parsedGroupId, parsedMsgId]
        );

        if (mediaRows.length > 0) {
            const asset = mediaRows[0];
            const resourceType = asset.media_type === 'video' ? 'video' : 'image';
            
            // Wipe from Cloudinary storage
            await cloudinary.uploader.destroy(asset.cloudinary_public_id, { resource_type: resourceType });
            
            // Clean records from tables
            await db.execute("DELETE FROM shared_media WHERE group_id = ? AND media_url = (SELECT message_content FROM group_messages WHERE message_id = ?)", [parsedGroupId, parsedMsgId]);
            console.log(TAG, `Permanently purged group asset ${parsedMsgId} from Cloudinary—all recipients downloaded it.`);
        }
    }
}
            return res.json({ success: true, message: "Group download tracked successfully." });
        } 
        else {
            // Existing individual chat media purge logic remains unchanged
            const [rows] = await db.execute("SELECT cloudinary_public_id, media_type, sender_id, receiver_id FROM shared_media WHERE id = ?", [parseInt(message_id)]);
            if (rows.length === 0) return res.status(404).json({ success: false, message: "Asset records non-existent." });

            const asset = rows[0];
            if (String(asset.receiver_id) !== current_user_id.toString()) {
                return res.status(403).json({ success: false, message: "Unauthorized request." });
            }

            io.to(`chat_${asset.sender_id}`).emit('partner_read_messages', {
                partnerId: parseInt(current_user_id),
                userId: parseInt(current_user_id)
            });

            const resourceType = asset.media_type === 'video' ? 'video' : 'image';
            await cloudinary.uploader.destroy(asset.cloudinary_public_id, { resource_type: resourceType });
            await db.execute("DELETE FROM shared_media WHERE id = ?", [parseInt(message_id)]);
            
            return res.json({ success: true, message: "Individual media purged permanently." });
        }
    } catch (err) {
        console.error(TAG, err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// SECURITY FIX: system-wide maintenance job, not a per-user action — restrict to internal callers
app.post("/api/media/housekeeper-cleanup", requireInternalJobSecret, async (req, res) => {
    const TAG = "/api/media/housekeeper-cleanup";
    try {
        // Identify files that passed expiration threshold validation checkpoints
        const [expiredItems] = await db.execute(
            "SELECT cloudinary_public_id, media_type FROM shared_media WHERE expires_at <= NOW()"
        );

        if (expiredItems.length === 0) {
            return res.json({ success: true, message: "Storage baseline sanitized. Zero targets detected." });
        }

        // Loop array values to strip file chunks from Cloudinary cloud structures
        for (let item of expiredItems) {
            const resourceType = item.media_type === 'video' ? 'video' : 'image';
            await cloudinary.uploader.destroy(item.cloudinary_public_id, { resource_type: resourceType });
        }

        // Wipe historical schema references inside TiDB database atomically
        await db.execute("DELETE FROM shared_media WHERE expires_at <= NOW()");
        
        console.log(TAG, `Sanitization successfully executed for ${expiredItems.length} elements.`);
        res.json({ success: true, wipedCount: expiredItems.length });
    } catch (err) {
        console.error(TAG, "Cleanup processing loop failures:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ================= DELETE MEDIA FOR SENDER (CHAT) =================
app.post("/api/media/delete", authenticateToken, async (req, res) => {
    const TAG = "/api/media/delete";
    try {
        const { messageId, actionType } = req.body;
        const current_user_id = parseInt(req.user.id, 10); // Enforce reliable integer comparisons

        if (!messageId || !actionType) {
            return res.status(400).json({ success: false, message: "Missing required fields." });
        }

        const msgId = parseInt(messageId, 10);

        // Fetch message details from the database
        const [msgRows] = await db.query("SELECT sender_id, receiver_id, message_type, message FROM messages WHERE id = ?", [msgId]);
        if (msgRows.length === 0) {
            return res.status(404).json({ success: false, message: "Message reference not found." });
        }

        const message = msgRows[0];
        const msgSenderId = parseInt(message.sender_id, 10);
        const msgReceiverId = parseInt(message.receiver_id, 10);

        // ================= ACTION: DELETE FOR EVERYONE =================
        if (actionType === "everyone") {
            // Security Check: Only the original sender can delete a message for everyone
            if (msgSenderId !== current_user_id) {
                return res.status(403).json({ success: false, message: "Unauthorized action. You can only delete your own sent media for everyone." });
            }

            // Fetch asset parameters from shared_media to shred from cloud storage
            const [mediaRows] = await db.query("SELECT cloudinary_public_id, media_type FROM shared_media WHERE id = ?", [msgId]);
            
            if (mediaRows.length > 0) {
                const asset = mediaRows[0];
                const resourceType = asset.media_type === 'video' ? 'video' : 'image';
                
                // Shred physical file binaries out of Cloudinary buckets entirely
                await cloudinary.uploader.destroy(asset.cloudinary_public_id, { resource_type: resourceType })
                    .catch(err => console.error(`[Cloudinary Shred Failure] ${asset.cloudinary_public_id}:`, err.message));
            }

            // Atomic drop sweep across all primary context tables
            await db.query("DELETE FROM messages WHERE id = ?", [msgId]);
            await db.query("DELETE FROM shared_media WHERE id = ?", [msgId]);
            await db.query("DELETE FROM hidden_messages WHERE message_id = ?", [msgId]);

            // Broadcast socket notifications immediately to shred display cells on active screens
            io.to(`chat_${msgReceiverId}`).emit('message_deleted', { messageId: msgId });
            io.to(`chat_${msgSenderId}`).emit('message_deleted', { messageId: msgId });

            return res.json({ success: true, message: "Media purged globally from cloud structural nodes." });
        } 

        // ================= ACTION: DELETE FOR ME =================
        else if (actionType === "me") {
            // Security Check: Ensure the applicant is a valid conversational participant
            if (current_user_id !== msgSenderId && current_user_id !== msgReceiverId) {
                return res.status(403).json({ success: false, message: "Unauthorized conversation modification." });
            }

            // Insert tracking placeholder to hide this layout context for the specific caller
            await db.query(`INSERT IGNORE INTO hidden_messages (message_id, user_id, hidden_at) VALUES (?, ?, NOW())`, [msgId, current_user_id]);
            
            // Garbage Collection Cascade: If both participants have hidden it, drop the file completely
            const [fullyHidden] = await db.query(`SELECT message_id FROM hidden_messages WHERE message_id = ? GROUP BY message_id HAVING COUNT(DISTINCT user_id) >= 2`, [msgId]);
            if (fullyHidden.length > 0) {
                const [mediaRows] = await db.query("SELECT cloudinary_public_id, media_type FROM shared_media WHERE id = ?", [msgId]);
                if (mediaRows.length > 0) {
                    const asset = mediaRows[0];
                    const resourceType = asset.media_type === 'video' ? 'video' : 'image';
                    await cloudinary.uploader.destroy(asset.cloudinary_public_id, { resource_type: resourceType }).catch(() => {});
                }
                await db.query(`DELETE FROM messages WHERE id = ?`, [msgId]);
                await db.query(`DELETE FROM hidden_messages WHERE message_id = ?`, [msgId]);
                await db.query(`DELETE FROM shared_media WHERE id = ?`, [msgId]);
            }

            return res.json({ success: true, message: "Media hidden successfully for this user." });
        }

        res.status(400).json({ success: false, message: "Invalid delete configuration operation." });
    } catch (error) {
        console.error(TAG, error);
        res.status(500).json({ success: false, message: "Server transaction execution failure." });
    }
});

// ================= DELETE MEDIA FOR SENDER/RECEIVER (GROUP CHAT) =================

app.post("/api/group-media/delete", authenticateToken, async (req, res) => {
    const current_user_id = req.user.id;
    const { actionType, groupId: clientGroupId } = req.body;

    try {
        // Look up target message rows based on active membership constraints
        const [rows] = await db.query(
            "SELECT sender_id, group_id, message_content, timestamp FROM group_messages WHERE sender_id = ? AND group_id = ? ORDER BY timestamp DESC LIMIT 10",
            [current_user_id, clientGroupId]
        );

        if (rows.length === 0) {
            return res.json({ success: true, message: "Synchronization cleanup complete." });
        }

        const targetRow = rows[0]; 
        const { sender_id, group_id: targetGroupId, message_content: mediaUrlStr, timestamp } = targetRow;

        if (actionType === "everyone") {
            if (sender_id !== current_user_id) {
                return res.status(403).json({ success: false, message: "Global content purge unauthorized." });
            }

            if (mediaUrlStr && mediaUrlStr.includes("cloudinary.com")) {
                try {
                    const urlSegments = mediaUrlStr.split('/');
                    const fileWithExtension = urlSegments[urlSegments.length - 1];
                    const publicId = fileWithExtension.split('.')[0];
                    const folderName = urlSegments[urlSegments.length - 2];
                    const fullPublicId = `${folderName}/${publicId}`;

                    await cloudinary.uploader.destroy(fullPublicId);
                    console.log("Cloudinary group asset destroyed successfully:", fullPublicId);
                } catch (cloudinaryErr) {
                    console.error("Cloudinary bypass warning:", cloudinaryErr);
                }
            }

            // Execute delete query by matching layout schema parameters accurately
            await db.query(
                "DELETE FROM group_messages WHERE group_id = ? AND sender_id = ? AND message_content = ? AND timestamp = ?",
                [targetGroupId, sender_id, mediaUrlStr, timestamp]
            );

            // Emit structured parameters back to room pipes cleanly for real-time removal
            io.to(`group_${targetGroupId}`).emit('message_deleted', { 
                senderId: sender_id,
                timestamp: timestamp
            });

            return res.json({ success: true, message: "Group message purged globally successfully." });
        }

        res.status(400).json({ success: false, message: "Unsupported operation parameters." });
    } catch (error) {
        console.error("/api/group-media/delete Error:", error);
        res.status(500).json({ success: false, message: "Server transaction execution failure." });
    }
});

// SECURITY FIX / UX FIX: without this, a multer fileFilter rejection (unsupported file type)
// or a file exceeding the 100MB shared-media limit would surface as an unhandled error /
// generic 500 instead of a clean response. Centralize that handling here.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ success: false, message: "File is too large. Maximum size is 100MB." });
    }
    return res.status(400).json({ success: false, message: err.message });
  }
  if (err && err.message === 'Unsupported file type. Only images and videos may be shared.') {
    return res.status(400).json({ success: false, message: err.message });
  }
  next(err);
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on port ${PORT}`);
});

server.timeout = 300000;
