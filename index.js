require("dotenv").config();
const activeChatSessions = new Map();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs'); 
const admin = require("firebase-admin");
const axios = require('axios');

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

  socket.on('update_live_location', (data) => {
  const { senderId, receiverId, lat, lng, type } = data;
  
  // Relay the update (location OR stop signal) to the receiver
  socket.to(`chat_${receiverId}`).emit('update_live_location', {
    senderId,
    lat,
    lng,
    type: type // This will now correctly relay 'stop_sharing'
  });

  if (type === 'stop_sharing') {
      console.log(`User ${senderId} stopped sharing with ${receiverId}`);
  }
});

  socket.on('update_group_live_location', (data) => {
    const { senderId, groupId, lat, lng } = data;
    socket.to(`group_${groupId}`).emit('group_live_location_update', {
      senderId,
      lat,
      lng
    });
    if (type === 'stop_sharing') {
        console.log(`User ${senderId} stopped sharing with ${receiverId}`);
    }
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

app.post("/create-account", async (req, res) => {
    const TAG = "/create-account";
    try {
        const { first_name, last_name, work_category, work_detail, gender, phone, country_code, password } = req.body;

        if (!first_name || !last_name || !work_category || !work_detail || !gender || !phone || !country_code || !password) {
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
        
        await db.query(query, [first_name, last_name, work_category, work_detail, gender, phone, country_code, hashedPassword]);
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

    console.log(TAG, `Checking: phone=${phone}, country_code=${country_code}`);

    if (!phone || !country_code) {
        return res.status(400).json({ success: false, message: "Phone and country code required." });
    }

    try {
        const [rows] = await db.query(
            `SELECT id, phone, country_code, signup_status FROM users WHERE phone = ? AND country_code = ? AND signup_status = 'completed'`,
            [phone, country_code]
        );

        console.log(TAG, `Query result: found ${rows.length} rows`);
        if (rows.length > 0) {
            console.log(TAG, `User exists:`, rows[0]);
        }

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

app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
  if (!phone || !password) {
    return res.status(400).json({ success: false, message: `Missing phone or password` });
  }
  try {
    const [rows] = await db.query(
      `SELECT 
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
       FROM users WHERE phone = ?`,
      [phone]
    );

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
    
    res.json({ success: true, message: "Login successful", user: user });

  } catch (err) {
    console.error("/login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    console.log("=== Update Profile Request ===");
    const { 
      userId, 
      dob, 
      bio, 
      home_location, 
      home_lat, 
      home_lng 
    } = req.body || {};

    if (!userId) {
      return res.status(400).json({ success: false, message: "Missing userId" });
    }

    const sets = [];
    const params = [];

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
    console.log("Profile Updated for User:", updatedUser.id);

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

//==========================================================================CAB TRAVEL PLAN==========================================================================================
app.post("/addCabTravelPlan", async (req, res) => {
    const { userId, companyName, date, time, pickup, destination, landmark } = req.body;
    try {
        const query = `INSERT INTO travel_plans_cab (user_id, company_name, travel_date, travel_time, pickup_location, destination, landmark) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)`;
        await db.query(query, [userId, companyName, date, time, pickup, destination, landmark]);
        res.status(201).json({ success: true, message: "Cab plan saved successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

//==========================================================================OWN VEHICLE PLAN=========================================================================================
app.post("/addOwnVehiclePlan", async (req, res) => {
    const { userId, vehicleType, vehicleNumber, pickup, destination, time } = req.body;
    try {
        const query = `INSERT INTO travel_plans_own (user_id, vehicle_type, vehicle_number, pickup_location, destination, travel_time) 
                       VALUES (?, ?, ?, ?, ?, ?)`;
        await db.query(query, [userId, vehicleType, vehicleNumber, pickup, destination, time]);
        res.status(201).json({ success: true, message: "Vehicle plan saved successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/travel-plans/destinations-by-type", async (req, res) => {
    const { userId, commuteType } = req.query;

    let tableName;
    let destinationCol;
    let statusFilter = "status = 'Active'";

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        destinationCol = 'destination';
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        destinationCol = 'destination';
    } else {
        tableName = 'travel_plans';
        destinationCol = 'to_place'; 
    }

    try {
        const query = `
            SELECT 
                ${destinationCol} as destination, 
                COUNT(*) as userCount,
                SUM(CASE WHEN user_id = ? THEN 1 ELSE 0 END) > 0 AS isCurrentUserGoing
            FROM ${tableName}
            WHERE ${statusFilter}
            GROUP BY ${destinationCol}
            ORDER BY userCount DESC
        `;

        const [destinations] = await db.query(query, [userId]);
        const formattedDestinations = destinations.map((d, index) => ({
            groupId: index + 100, 
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
    let timeCol = 'time';

    if (commuteType === 'Cab') {
        tableName = 'travel_plans_cab';
        fromCol = 'pickup_location';
        toCol = 'destination';
        timeCol = 'travel_time';
    } else if (commuteType === 'Own') {
        tableName = 'travel_plans_own';
        fromCol = 'pickup_location';
        toCol = 'destination';
        timeCol = 'travel_time';
    }

    try {
        const [friendRows] = await db.query(
            `SELECT DISTINCT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END as friend_id 
             FROM messages WHERE sender_id = ? OR receiver_id = ?`, 
            [currentUserId, currentUserId, currentUserId]
        );
        const friendIds = new Set(friendRows.map(row => row.friend_id));

        let finalDestName = destinationName;
        if (!finalDestName && groupId) {
            const [groupRows] = await db.query("SELECT group_name FROM \`group_table\` WHERE group_id = ?", [groupId]);
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
                u.profile_pic AS profilePic,
                u.gender,
                u.profile_visibility,
                tp.${timeCol} as time,        
                tp.${fromCol} AS fromPlace, 
                tp.${toCol} AS toPlace     
            FROM ${tableName} tp
            JOIN users u ON tp.user_id = u.id
            WHERE
                tp.${toCol} = ?
                AND tp.status = 'Active' 
                AND tp.user_id != ?   
            ORDER BY
                tp.${timeCol} ASC; 
        `;
        
        const [users] = await db.execute(query, [finalDestName, currentUserId]);

        const responseUsers = users.map(user => ({
            ...user,
            profilePic: getVisibleProfilePic(
                { ...user, profile_pic: user.profilePic, user_id: user.id }, 
                currentUserId, 
                friendIds
            )
        }));

        res.json({ success: true, users: responseUsers }); 

    } catch (error) {
        console.error(TAG, `Error fetching users:`, error);
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
    if ((type === 'location' || type === 'live_location') && duration && duration > 0) {
        const date = new Date();
        date.setMinutes(date.getMinutes() + duration);
        expiresAt = date.toISOString().slice(0, 19).replace('T', ' ');
        console.log(TAG, 'Set expires_at to:', expiresAt);
    }

    // CRITICAL FIX: Handle reply fields more carefully
    // Only include them if ALL three exist AND are valid
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
            notification: { 
              title: senderName, 
              body: type === 'location' || type === 'live_location' ? 'Shared a location' : message 
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
      console.error(TAG, " Error sending FCM:", fcmError.message);
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
            WHERE tp.status = 'Active'
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
            WHERE tp.to_place = ? AND tp.status = 'Active'
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

    await db.query(`UPDATE travel_plans SET status = 'Completed' WHERE user_id = ? AND status = 'Active' AND time < NOW()`, [uId]);
    await db.query(`UPDATE travel_plans_cab SET status = 'Completed' WHERE user_id = ? AND status = 'Active' AND travel_date < CURDATE()`, [uId]);
    await db.query(`UPDATE travel_plans_own SET status = 'Completed' WHERE user_id = ? AND status = 'Active' AND travel_time < NOW()`, [uId]);

    const historyQuery = `
      SELECT * FROM (
        -- Rickshaw Plans
        SELECT 
            id, from_place, to_place, 
            DATE_FORMAT(time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            fare, status, added_fare as hasAddedFare, 'Rickshaw' as commute_type
        FROM travel_plans WHERE user_id = ?

        UNION ALL

        -- Cab Plans
        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(CONCAT(travel_date, ' ', travel_time), '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            0 as fare, status, 0 as hasAddedFare, 'Cab' as commute_type
        FROM travel_plans_cab WHERE user_id = ?

        UNION ALL

        -- Own Vehicle Plans
        SELECT 
            id, pickup_location as from_place, destination as to_place,
            DATE_FORMAT(travel_time, '%Y-%m-%dT%H:%i:%s.000Z') as travel_time,
            0 as fare, status, 0 as hasAddedFare, 'Own' as commute_type
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
      fare: trip.fare ? parseFloat(trip.fare) : null,
      status: trip.status,
      hasAddedFare: Boolean(trip.hasAddedFare),
      commute_type: trip.commute_type // Added this field for your Android UI
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
        res.json({ success: true, unreadCount: individualRows[0].totalUnreadCount + groupRows[0].totalUnreadCount });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

app.post("/hideChat", async (req, res) => {
    const TAG = "/hideChat"; 
    try {
        const { userId, otherUserId } = req.body;
        if (!userId || !otherUserId) return res.status(400).json({ success: false });
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
        res.json({ success: true });
    } catch (error) {
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
        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(404).json({ success: false });
        const isMatch = await bcrypt.compare(currentPassword, rows[0].password);
        if (!isMatch) return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);
        res.json({ success: true });
    } catch (error) {
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
        await db.query("DELETE FROM group_members WHERE user_id = ? AND group_id = ?", [userId, groupId]);
        io.to(`group_${groupId}`).emit('group_notification', { message: `A user has left the group` });
        res.json({ success: true });
    } catch (e) {
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
        // Ensure user is a member
        await db.query(`INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`, [groupId, userId]);
         
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
                CONCAT(u.first_name, ' ', u.last_name) as sender_name,
                u.profile_pic as sender_profile_pic,
                -- Fix: Count unique members except the sender
                ((SELECT COUNT(DISTINCT user_id) FROM group_members WHERE group_id = ?) - 1) as totalParticipants,
                -- Fix: Count unique readers except the sender
                (SELECT COUNT(DISTINCT user_id) FROM group_message_read_status WHERE message_id = gm.message_id AND user_id != gm.sender_id) as readByCount,
                -- Fix: List unique reader names except the sender
                (SELECT GROUP_CONCAT(DISTINCT u2.first_name SEPARATOR ', ')
                 FROM group_message_read_status gmrs
                 JOIN users u2 ON gmrs.user_id = u2.id
                 WHERE gmrs.message_id = gm.message_id AND gmrs.user_id != gm.sender_id) as readByNames
            FROM group_messages gm 
            JOIN users u ON gm.sender_id = u.id
            WHERE gm.group_id = ?
            ORDER BY gm.timestamp ASC
            LIMIT 300`;

        const [messages] = await db.execute(query, [groupId, groupId]);

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
    const { sender_id, group_id, message_content, message_type, latitude, longitude, reply_to_id } = req.body;

    try {
        console.log(TAG, "Received request:", { sender_id, group_id, message_content, message_type });

        // 1. Validate group_id
        if (!group_id || group_id === 0) {
            return res.status(400).json({ 
                success: false, 
                error: "Invalid group_id. Group ID must be a valid number." 
            });
        }

        // 2. Fetch sender name FIRST so it is defined for the socket emit and parsing
        const [userRows] = await db.query("SELECT CONCAT(first_name, ' ', last_name) as name FROM users WHERE id = ?", [sender_id]);
        
        if (userRows.length === 0) {
            return res.status(404).json({ success: false, error: "Sender user not found." });
        }
        const senderName = userRows[0].name;

        // 3. Check if group exists
        const [groupCheck] = await db.query('SELECT group_id, group_name FROM `group_table` WHERE group_id = ?', [group_id]);
        
        if (groupCheck.length === 0) {
            console.log(TAG, "Group not found:", group_id);
            return res.status(404).json({ 
                success: false, 
                error: "Group does not exist. Please create or join the group first." 
            });
        }

        // 4. Ensure user is a member of this group
        await db.execute(`INSERT IGNORE INTO group_members (user_id, group_id) VALUES (?, ?)`, [sender_id, group_id]);

        // 5. Encrypt message content
        const encrypted = encrypt(message_content);

        // 6. Insert message into database
        const query = `INSERT INTO group_messages 
            (group_id, sender_id, message_content, timestamp, message_type, latitude, longitude, reply_to_id) 
            VALUES (?, ?, ?, NOW(), ?, ?, ?, ?)`;

        const [result] = await db.execute(query, [
            group_id, 
            sender_id, 
            encrypted, 
            message_type || 'text', 
            latitude || null, 
            longitude || null, 
            reply_to_id || null
        ]);

        console.log(TAG, "Message inserted successfully:", result.insertId);

        // 7. Socket emit - Now senderName is guaranteed to be defined
        io.to(`group_${group_id}`).emit('new_group_message', { 
            id: result.insertId, 
            sender_id: sender_id, 
            sender_name: senderName, 
            message: message_content, 
            message_type: message_type || 'text',
            latitude: latitude || null,
            longitude: longitude || null,
            reply_to_id: reply_to_id || null,
            timestamp: new Date() 
        });

        // 8. Return success response to the app
        res.json({ success: true, messageId: result.insertId });

    } catch (error) {
        console.error(TAG, "DATABASE ERROR:", error.message); 
        res.status(500).json({ success: false, error: error.message });
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
    try {
        const [rows] = await db.execute(`SELECT COUNT(*) as count FROM chat_requests WHERE receiver_id = ? AND status = 'pending'`, [req.query.userId]);
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
