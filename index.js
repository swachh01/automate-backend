require("dotenv").config();
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const bcrypt = require('bcryptjs'); 

const twilio = require("twilio");
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);
const signupStore = {};

const express = require("express");
const cors = require("cors");
const path = require("path");
const { encrypt, decrypt } = require('./cryptoHelper');
const fs = require("fs");
const multer = require("multer");
const mysql = require("mysql2");

const http = require('http');
// --- RENAMED to 'Server' to follow Socket.IO v4 convention ---
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
// --- Use 'new Server()' ---
const io = new Server(server, {
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


// --- REPLACE YOUR ENTIRE io.on('connection', ...) BLOCK WITH THIS ---

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  // --- 1. YOUR EXISTING PRESENCE LOGIC (MERGED) ---
  socket.on('user_online', async (userId) => {
    try {
      onlineUsers.set(userId.toString(), {
        socketId: socket.id,
        lastSeen: new Date(),
        isOnline: true
      });
      await updateUserPresence(userId, true);
      socket.broadcast.emit('user_status_changed', {
        userId: userId.toString(),
        isOnline: true,
        lastSeen: new Date()
      });
      console.log(` User ${userId} is now online`);

      // --- CRITICAL FIX: JOIN THE PRIVATE CHAT ROOM ---
      socket.join(`chat_${userId}`);
      console.log(`User ${userId} joined private chat room: chat_${userId}`);

    } catch (error) {
      console.error(' Error handling user_online:', error);
    }
  });

  socket.on('user_offline', async (userId) => {
    // (This code is fine, no changes needed)
    try {
      onlineUsers.delete(userId.toString());
      await updateUserPresence(userId, false);
      socket.broadcast.emit('user_status_changed', {
        userId: userId.toString(),
        isOnline: false,
        lastSeen: new Date()
      });
      console.log(`User ${userId} manually went offline`);
    } catch (error) {
      console.error(' Error handling user_offline:', error);
    }
  });

  socket.on('disconnect', async () => {
    // (This code is fine, no changes needed)
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
        console.log(` User ${disconnectedUserId} disconnected`);
      }
    } catch (error) {
      console.error('❌ Error handling disconnect:', error);
    }
  });


  // --- 2. YOUR TYPING LOGIC (USING YOUR EVENT NAMES) ---
  socket.on('typing_start', (data) => {
    // data = { userId: 12 (sender), chatWithUserId: 45 (receiver) }
    // We send this *only* to the receiver's private room
    console.log(`User ${data.userId} is typing to ${data.chatWithUserId}`);
    socket.to(`chat_${data.chatWithUserId}`).emit('user_typing', {
      userId: data.userId,
      isTyping: true
    });
  });

  socket.on('typing_stop', (data) => {
    // data = { userId: 12 (sender), chatWithUserId: 45 (receiver) }
    console.log(`User ${data.userId} stopped typing to ${data.chatWithUserId}`);
    socket.to(`chat_${data.chatWithUserId}`).emit('user_typing', {
      userId: data.userId,
      isTyping: false
    });
  });

  // --- 3. NEW MESSAGE LOGIC (THE INSTANT FIX) ---
  socket.on('new_message_sent', (data) => {
    // data = { receiverId: 45, messageObject: {...} }
    // This event is sent by the sender.
    // We relay (emit) it to the receiver's private room.
    console.log(`Relaying message to room: chat_${data.receiverId}`);
    socket.to(`chat_${data.receiverId}`).emit('new_message_received', data.messageObject);
  });

  // In index.js, update these handlers:

socket.on('i_delivered_messages', (data) => {
    // data = { partnerId: 45 }
    console.log(`Relaying 'delivered' status to room: chat_${data.partnerId}`);
    socket.to(`chat_${data.partnerId}`).emit('partner_delivered_messages', {
        userId: data.partnerId // Include the user ID for context
    });
  });

socket.on('i_read_messages', (data) => {
    // data = { partnerId: 45 }
    console.log(`Relaying 'read' status to room: chat_${data.partnerId}`);
    socket.to(`chat_${data.partnerId}`).emit('partner_read_messages', {
        userId: data.partnerId // Include the user ID for context
    });
});  

  socket.on('join_group', (groupId) => {
    socket.join(`group_${groupId}`);
    console.log(`Socket ${socket.id} joined group room: group_${groupId}`);
  });

  socket.on('new_group_message_sent', (data) => {
    // data = { groupId: 5, messageObject: {...} }
    console.log(`Relaying group message to room: group_${data.groupId}`);
    socket.to(`group_${data.groupId}`).emit('new_group_message', data.messageObject);
});

// Add these handlers inside your io.on('connection', (socket) => { ... }) block
// Place them after the existing socket handlers

// --- GROUP TYPING INDICATORS ---

socket.on('group_typing_start', async (data) => {
  // data = { userId: 12, groupId: 5, isTyping: true }
  try {
    const { userId, groupId } = data;
    
    // Get the user's name from the database
    const [userRows] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);
    
    if (userRows.length > 0) {
      const userName = userRows[0].name;
      
      // Broadcast to all other members in the group room
      socket.to(`group_${groupId}`).emit('group_user_typing', {
        userId: userId,
        userName: userName,
        groupId: groupId,
        isTyping: true
      });
      
      console.log(`User ${userName} (${userId}) started typing in group ${groupId}`);
    }
  } catch (error) {
    console.error('Error handling group_typing_start:', error);
  }
});

socket.on('group_typing_stop', async (data) => {
  // data = { userId: 12, groupId: 5, isTyping: false }
  try {
    const { userId, groupId } = data;
    
    // Get the user's name from the database
    const [userRows] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);
    
    if (userRows.length > 0) {
      const userName = userRows[0].name;
      
      // Broadcast to all other members in the group room
      socket.to(`group_${groupId}`).emit('group_user_typing', {
        userId: userId,
        userName: userName,
        groupId: groupId,
        isTyping: false
      });
      
      console.log(`User ${userName} (${userId}) stopped typing in group ${groupId}`);
    }
  } catch (error) {
    console.error('Error handling group_typing_stop:', error);
  }
});

// --- END GROUP TYPING INDICATORS ---


// Also make sure you have the join_group handler:
socket.on('join_group', (groupId) => {
  socket.join(`group_${groupId}`);
  console.log(`Socket ${socket.id} joined group room: group_${groupId}`);
});

// When someone reads group messages, notify all group members
socket.on('group_read', (data) => {
    // data = { userId: 12, groupId: 5 }
    console.log(`User ${data.userId} read messages in group ${data.groupId}`);
    socket.to(`group_${data.groupId}`).emit('group_messages_read', {
        userId: data.userId,
        groupId: data.groupId
    });
});

}); 

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
  // --- FIXED: otpStore is not defined in this file ---
  // You moved to DB-based OTPs, so this route is mostly for signupStore
  res.json({
    // otpStore: Object.keys(otpStore).map(phone => ({
    //   phone,
    //   hasOtp: !!otpStore[phone].otp,
    //   expires: new Date(otpStore[phone].expires)
    // })),
    otpStore: "OTP is now stored in the database ('otp' table).",
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

    const [existingUser] = await db.query(`SELECT id, signup_status FROM users WHERE phone = ?`, [phone]);
    
    if (existingUser.length > 0 && existingUser[0].signup_status === 'completed') {
      return res.status(400).json({ success: false, message: `A user with this phone number already has a completed account.` });
    }

    const signupData = { name: name.trim(), college: college.trim(), gender };
    signupStore[phone] = signupData;
    
    return res.json({ success: true, message: `Signup data received. Please verify OTP.` });
  } catch (err) {
    console.error(" /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// Remove the global otpStore object: const otpStore = {};

app.post("/sendOtp", async (req, res) => { // Make it async
    const TAG = "/sendOtp"; // Define TAG for logging context
    const { phone } = req.body;

    if (!phone) {
        console.warn(TAG, "Request missing phone number."); // Use console.warn
        return res.status(400).json({ success: false, message: `Phone number required` });
    }

    // Basic phone number format validation (adjust if needed)
    if (phone.length !== 10 || !/^\d+$/.test(phone)) {
        console.warn(TAG, `Invalid phone number format received: ${phone}`);
        return res.status(400).json({ success: false, message: "Please enter a valid 10-digit phone number." });
    }


    const otp = Math.floor(1000 + Math.random() * 9000).toString(); // Generate 4-digit OTP
    const otpValiditySeconds = 60; // OTP valid for 60 seconds (1 minute)
    console.log(TAG, `Generated OTP ${otp} for phone ${phone}`); // Log generated OTP

    try {
        // Store/Update OTP and expiry time in the database
        const query = `
            INSERT INTO otp (phone, otp_code, expiry_time)
            VALUES (?, ?, UTC_TIMESTAMP() + INTERVAL ? SECOND)
            ON DUPLICATE KEY UPDATE
                otp_code = VALUES(otp_code),
                expiry_time = VALUES(expiry_time),
                created_at = CURRENT_TIMESTAMP; -- Also update created_at on resend
        `;
        // Execute the database query
        await db.query(query, [phone, otp, otpValiditySeconds]);
        console.log(TAG, `Stored/Updated OTP in DB for phone ${phone}, valid for ${otpValiditySeconds}s.`);

        // Proceed to send OTP via Twilio ONLY after successful DB storage
        console.log(TAG, `Attempting to send OTP SMS via Twilio to +91${phone}`);
        client.messages
            .create({
                body: `Your Automate verification code is ${otp}`, // Consider mentioning your app name
                from: process.env.TWILIO_PHONE_NUMBER,
                // Ensure phone number format matches Twilio requirements (e.g., +91)
                to: `+91${phone}` // Assuming Indian numbers, adjust if needed
            })
            .then(message => {
                console.log(TAG, `OTP SMS sent successfully via Twilio to ${phone}, SID: ${message.sid}`);
                // Send success response back to the app
                res.json({
                    success: true,
                    message: "OTP sent successfully",
                    // IMPORTANT: Only include OTP in response during development/debugging
                    ...(process.env.NODE_ENV !== 'production' && { otp }) // Show OTP if NOT in production
                });
            })
            .catch(err => {
                // Log Twilio error details
                console.error(TAG, `❌ Twilio SMS Error for phone ${phone}: Code=${err.code}, Message=${err.message}`, err);
                // Inform the app that SMS sending failed
                // Consider the user experience: Should the DB entry be deleted? For now, we leave it, user can retry.
                res.status(500).json({ success: false, message: "Failed to send OTP SMS. Please check the number and try again." });
            });

    } catch (dbError) {
        // Handle errors during database interaction
        console.error(TAG, `❌ Database error storing OTP for phone ${phone}:`, dbError);
        res.status(500).json({ success: false, message: "Server error saving OTP information. Please try again later." });
    }
});


app.post("/verifyOtp", async (req, res) => {
    const TAG = "/verifyOtp"; // Define TAG for logging context
    let phoneToCheck = null; // Variable to hold phone for cleanup in catch block

    try {
        const { phone, otp } = req.body;
        phoneToCheck = phone; // Store for potential cleanup

        if (!phone || !otp) {
            console.warn(TAG, `Request missing phone or OTP.`);
            return res.status(400).json({ success: false, message: `Phone and OTP required` });
        }

        // Basic validation for OTP format
        if (otp.length !== 4 || !/^\d+$/.test(otp)) {
             console.warn(TAG, `Invalid OTP format received for phone ${phone}: ${otp}`);
             return res.status(400).json({ success: false, message: `Invalid OTP format.` });
        }

        // 1. Fetch OTP details from the database
        console.log(TAG, `Fetching OTP details from DB for phone: ${phone}`);
        const [otpRows] = await db.query(
            'SELECT otp_code, expiry_time FROM otp WHERE phone = ?',
            [phone]
        );

        // 2. Check if OTP record exists
        if (otpRows.length === 0) {
            console.warn(TAG, `No OTP record found in DB for phone: ${phone}`);
            return res.status(400).json({ success: false, message: `Invalid or expired OTP.` }); // Generic message for security
        }

        const storedOtp = otpRows[0].otp_code;
        const expiryTime = new Date(otpRows[0].expiry_time); // Convert DB timestamp to Date object

        // Get current UTC time directly from the database for accurate comparison
        const [currentTimeRows] = await db.query('SELECT UTC_TIMESTAMP() as now');
        const currentTime = new Date(currentTimeRows[0].now);
        console.log(TAG, `Current DB UTC Time: ${currentTime.toISOString()}, OTP Expiry Time: ${expiryTime.toISOString()}`);

        // 3. Check if OTP has expired
        if (currentTime > expiryTime) {
            console.warn(TAG, `OTP expired for phone: ${phone}.`);
            // Optionally delete the expired OTP from DB here for cleanup
            try {
                 await db.query('DELETE FROM otp WHERE phone = ?', [phone]);
                 console.log(TAG, `Deleted expired OTP from DB for phone: ${phone}`);
            } catch (deleteError) {
                 console.error(TAG, `Error deleting expired OTP for ${phone}:`, deleteError);
            }
            return res.status(400).json({ success: false, message: `OTP expired.` });
        }

        // 4. Check if the submitted OTP matches the stored OTP
        if (storedOtp !== otp.toString()) {
            console.warn(TAG, `Invalid OTP entered for phone: ${phone}. Entered: ${otp}, Expected: ${storedOtp}`);
            // Do NOT delete the OTP here, allow user to retry if within expiry time
            return res.status(400).json({ success: false, message: `Invalid OTP.` });
        }

        // --- OTP IS VALID ---
        console.log(TAG, `Valid OTP received for phone: ${phone}`);

        // 5. (CRITICAL) Delete the used OTP from the database IMMEDIATELY to prevent reuse
        try {
            await db.query('DELETE FROM otp WHERE phone = ?', [phone]);
            console.log(TAG, `Deleted used OTP from DB for phone: ${phone}`);
        } catch (deleteError) {
            console.error(TAG, `CRITICAL: Error deleting used OTP for phone ${phone} after successful validation:`, deleteError);
            // Decide how to handle this - potentially return an error as verification isn't fully complete?
            // For now, log critically and continue, but this needs monitoring.
            // return res.status(500).json({ success: false, message: "Server error completing verification." });
        }

        // 6. Check for temporary signup data (same logic as before, using signupStore)
        const signupData = signupStore[phone]; // Still use in-memory signupStore for stage 1 data

        if (signupData) {
            // --- A. SIGNUP FLOW ---
            console.log(TAG, `Processing SIGNUP flow for phone: ${phone}`);
            delete signupStore[phone]; // Clear temporary signup data
            console.log(TAG, `Cleared signup data from store for phone: ${phone}`);

            const signupQuery = `
              INSERT INTO users (name, college, phone, gender, password, created_at, signup_status)
              VALUES (?, ?, ?, ?, '', NOW(), 'pending')
              ON DUPLICATE KEY UPDATE
                name = VALUES(name),
                college = VALUES(college),
                gender = VALUES(gender),
                signup_status = IF(signup_status = 'completed', 'completed', 'pending');
            `;
            await db.query(signupQuery, [signupData.name, signupData.college, phone, signupData.gender]);
            console.log(TAG, `Executed INSERT/UPDATE for signup user, phone: ${phone}`);

            const [userRows] = await db.query('SELECT id FROM users WHERE phone = ?', [phone]);
            if (userRows.length === 0) {
                 console.error(TAG, `User ID not found after signup DB operation, phone: ${phone}`);
                 throw new Error("User ID not found after database operation in signup flow.");
            }
            const userId = userRows[0].id;
            console.log(TAG, `Found userId ${userId} for signup flow, phone: ${phone}`);

            return res.json({
              success: true, message: "OTP verified successfully for signup.", userId: userId,
              user: { id: userId, name: signupData.name, college: signupData.college, phone: phone, gender: signupData.gender }
            });

        } else {
            // --- B. PASSWORD RESET (or other non-signup) FLOW ---
            console.log(TAG, `Processing NON-SIGNUP flow, phone: ${phone}`);

            const [userRows] = await db.query('SELECT id FROM users WHERE phone = ?', [phone]);
            if (userRows.length === 0) {
                 console.warn(TAG, `Password reset flow failed: User not found for phone: ${phone}`);
                 return res.status(404).json({ success: false, message: `User with this phone number not found.` });
            }
            const userId = userRows[0].id;
            console.log(TAG, `Found existing userId ${userId} for non-signup flow, phone: ${phone}`);

            return res.json({ success: true, message: "OTP verified successfully.", userId: userId });
        }
    } catch (err) {
        // Log detailed error on the server
        console.error(TAG, "❌ Error during OTP verification process:", err);

        // Attempt to clean up signup store if relevant on error
        if (phoneToCheck && signupStore[phoneToCheck]) {
            try { delete signupStore[phoneToCheck]; } catch (cleanupErr) { console.error(TAG, "Error cleaning up signupStore during catch block:", cleanupErr); }
        }
        // Do NOT clean up OTP table here in catch block, as the OTP might still be valid for another try if the error wasn't related to OTP check itself

        // Send a generic server error response to the client
        return res.status(500).json({ success: false, message: `Server error during OTP verification.` });
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

    if (user.password.startsWith('$2') && user.password.length > 50) {
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
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

    delete user.password;
    res.json({ success: true, message: "Login successful", user: { ...user, year: user.year || 0 } });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    console.log("=== Update Profile Request ===");
    console.log("Body:", req.body);
    console.log("File:", req.file);
    
    const { userId, dob, degree, year } = req.body || {};
    
    if (!userId) {
      console.log("ERROR: Missing userId");
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
      console.log("ERROR: Nothing to update");
      return res.status(400).json({ success: false, message: "Nothing to update" });
    }
    
    const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
    params.push(userId);
    
    console.log("SQL:", sql);
    console.log("Params:", params);
    
    const [result] = await db.query(sql, params);
    
    console.log("Update result:", result);
    
    if (result.affectedRows === 0) {
      console.log("ERROR: User not found");
      return res.status(404).json({ success: false, message: "User not found" });
    }
      
    await db.query("UPDATE users SET signup_status = 'completed' WHERE id = ?", [userId]);
    
    const [rows] = await db.query("SELECT id, name, college, phone, gender, dob, degree, year, profile_pic FROM users WHERE id = ?", [userId]);
    
    console.log("Updated user:", rows[0]);
    
    res.json({ success: true, message: "Profile updated and signup complete!", user: rows[0] });
  } catch (err) {
    console.error("=== /updateProfile ERROR ===");
    console.error("Error message:", err.message);
    console.error("Error stack:", err.stack);
    
    // Send proper JSON error response
    res.status(500).json({ 
      success: false, 
      message: "Internal Server Error",
      error: err.message
    });
  } 
});

app.post("/addTravelPlan", async (req, res) => {
    const TAG = "/addTravelPlan"; // Logging tag
    let connection; // Define connection variable for potential transaction

    try {
        const { userId, fromPlace, toPlace, time, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;

        // --- Validation (Keep your existing validation) ---
        if (!userId || !fromPlace || !toPlace || !time ||
            fromPlaceLat === undefined || fromPlaceLng === undefined ||
            toPlaceLat === undefined || toPlaceLng === undefined) {
             console.warn(TAG, `Request missing required fields for userId: ${userId || 'UNKNOWN'}`);
            return res.status(400).json({
                success: false,
                message: "Missing required fields: userId, fromPlace, toPlace, time, and all coordinates (from/to)."
            });
        }
        let formattedTime;
        try {
            formattedTime = new Date(time);
            if (isNaN(formattedTime.getTime())) { throw new Error("Invalid date format received from client."); }
        } catch (timeError) {
             console.warn(TAG, `Invalid time format received for userId ${userId}: ${time}`, timeError);
             return res.status(400).json({ success: false, message: "Invalid time format provided. Please use ISO 8601 format (e.g., YYYY-MM-DDTHH:mm:ss.sssZ)." });
        }
        // --- End Validation ---

        console.log(TAG, `Attempting to add travel plan for userId: ${userId} to destination: ${toPlace}`);

        // --- Start Transaction ---
        connection = await db.getConnection();
        await connection.beginTransaction();
        // ------------------------

        // --- Step 1: Insert the travel plan ---
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
             throw new Error("Travel plan insert failed unexpectedly.");
        }
        console.log(TAG, `Successfully added travel plan ID: ${newPlanId}`);

        // --- Step 2: Add/Ensure Group Exists (Using new table name) ---
        console.log(TAG, `Ensuring group exists for destination: ${toPlace}`);
        const groupQuery = `INSERT IGNORE INTO \`group_table\` (group_name) VALUES (?)`; // Changed table name
        await connection.query(groupQuery, [toPlace]);

        // --- Step 3: Get the group_id (Using new table name) ---
        const [groupRows] = await connection.query('SELECT group_id FROM \`group_table\` WHERE group_name = ?', [toPlace]); // Changed table name
        if (groupRows.length === 0) {
            await connection.rollback();
            connection.release();
            throw new Error(`Failed to find or create group_id for destination: ${toPlace}`);
        }
        const groupId = groupRows[0].group_id;
        console.log(TAG, `Found/Created groupId: ${groupId} for destination: ${toPlace}`);

        // --- Step 4: Add User to the Group ---
        console.log(TAG, `Adding user ${userId} to group ${groupId}`);
        const memberQuery = `INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)`;
        await connection.query(memberQuery, [groupId, userId]);

        // --- Commit Transaction ---
        await connection.commit();
        // --------------------------

        console.log(TAG, `Successfully added plan and added user ${userId} to group ${groupId}`);

        // Send success response
        res.status(201).json({
            success: true,
            message: "Plan submitted successfully and group joined",
            id: newPlanId
        });

    } catch (err) {
        // --- Rollback Transaction on Error ---
        if (connection) {
            try {
                await connection.rollback();
                 console.log(TAG, "Transaction rolled back due to error.");
            } catch (rollbackError) {
                console.error(TAG, "❌ Failed to rollback transaction:", rollbackError);
            }
        }
        // -----------------------------------
        console.error(TAG, `❌ Error saving travel plan or updating group:`, err);
        res.status(500).json({ success: false, message: "Server error occurred while saving the travel plan or joining the group." });
    } finally {
        // --- Release Connection ---
        if (connection) {
            connection.release();
             console.log(TAG, "Database connection released.");
        }
        // --------------------------
    }
});

// In index.js

// In index.js

app.get('/users/destination', async (req, res) => {
    const TAG = "/users/destination"; // Logging tag
    const { groupId, userId } = req.query; // Current viewer's ID

    if (!groupId || !userId) {
        console.warn(TAG, "Missing groupId or userId query parameter.");
        return res.status(400).json({ success: false, message: 'Missing groupId or userId' });
    }

    const currentGroupId = parseInt(groupId);
    const currentUserId = parseInt(userId);

    try {
        console.log(TAG, `Fetching active users for groupId: ${currentGroupId}, excluding userId: ${currentUserId}`);

        // --- QUERY MODIFIED ---
        // This query now ensures users are in the group AND have an ACTIVE plan for THIS destination.
        const query = `
            SELECT
                u.id,           -- User's ID (matches GoingUser 'id')
                u.id as userId, -- Include userId field explicitly if needed by GoingUserAdapter/Activity
                u.name,
                u.college,
                u.profile_pic AS profilePic,
                u.gender,
                tp.time,        -- Time from the ACTIVE travel plan
                tp.from_place AS fromPlace, -- From place from the ACTIVE travel plan
                tp.to_place AS toPlace     -- To place from the ACTIVE travel plan
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            -- Use INNER JOIN to require a matching ACTIVE travel plan
            INNER JOIN travel_plans tp ON u.id = tp.user_id
                AND tp.status = 'Active' -- Only include users with an ACTIVE plan
                -- Ensure the plan matches the destination name of the current group
                AND tp.to_place = (SELECT group_name FROM \`group_table\` WHERE group_id = ?)
            WHERE
                gm.group_id = ?       -- Make sure they are a member of the requested group
                AND gm.user_id != ?   -- Exclude the current user viewing the list
            ORDER BY
                tp.time ASC; -- Optional: Order by travel time
        `;
        // --- END QUERY MODIFICATION ---

        // Parameters: [groupId for subquery, groupId for WHERE, userId for exclusion]
        const [users] = await db.execute(query, [currentGroupId, currentGroupId, currentUserId]);

        console.log(TAG, `Found ${users.length} active users for groupId: ${currentGroupId}`);

        // Ensure response structure matches what GoingUserAdapter expects
        // Renaming 'id' to 'userId' or ensuring both are present might be needed
        // depending on your GoingUser.java class.
        const responseUsers = users.map(user => ({
            ...user,
            id: user.id, // Ensure 'id' field is present if needed
            userId: user.id // Ensure 'userId' field is present if needed
        }));


        res.json({ success: true, users: responseUsers }); // Return the filtered list

    } catch (error) {
        console.error(TAG, `Error fetching active users for destination groupId ${currentGroupId}:`, error);
        res.status(500).json({ success: false, message: 'Server error fetching users' });
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
      WHERE tp.user_id = ? 
        AND tp.time > UTC_TIMESTAMP() 
        AND tp.status = 'Active'
      ORDER BY tp.time ASC`,
      [userId]
    );
      
    res.json({ success: true, users: results || [] });
  } catch (err) {
    console.error(`Error fetching travel plan for user ${userId}:`, err);
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

    // 'SELECT *' will now also get the 'status' column
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
    console.error('❌ Error fetching messages:', error);
    res.status(500).json({ success: false, message: 'Database error' });
  } 
});

app.post('/messages/delivered', async (req, res) => {
  try {
    // We use the same 'userId' and 'otherUserId' as your markMessagesRead route
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }

    // This query updates the status from 0 (Sent) to 1 (Received)
    // for all messages sent from 'otherUserId' to 'userId'
    const query = `
      UPDATE messages
      SET status = 1
      WHERE sender_id = ? AND receiver_id = ? AND status = 0
    `;
    
    // Note the order: [otherUserId, userId]
    const [result] = await db.execute(query, [otherUserId, userId]);

    res.json({ success: true, message: 'Messages marked as delivered', updatedCount: result.affectedRows });
  } catch (error) {
    console.error('Error marking messages as delivered:', error);
    res.status(500).json({ success: false, message: 'Failed to mark messages as delivered' });
  }
});

// REPLACE your existing /sendMessage route with this fixed version

app.post('/sendMessage', async (req, res) => {
  const TAG = "/sendMessage"; // Add logging tag
  try {
    const { sender_id, receiver_id, message } = req.body;
    
    // Validation
    if (!sender_id || !receiver_id || !message) {
      console.warn(TAG, 'Missing required fields');
      return res.status(400).json({ 
        success: false, 
        message: 'sender_id, receiver_id, and message are required' 
      });
    }
    
    console.log(TAG, `User ${sender_id} sending message to ${receiver_id}`);
      
    // Check if either user has blocked the other
    const blockCheckQuery = `
      SELECT * FROM blocked_users
      WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)
    `;
    const [blockedRows] = await db.query(blockCheckQuery, [sender_id, receiver_id, receiver_id, sender_id]);
    
    if (blockedRows.length > 0) {
      console.warn(TAG, `Blocked: User ${sender_id} cannot message ${receiver_id}`);
      return res.status(403).json({ 
        success: false, 
        message: 'This user cannot be messaged.' 
      });
    }
    
    // Encrypt the message
    const encryptedMessage = encrypt(message);
    console.log(TAG, 'Message encrypted successfully');
        
    // Insert the message with UTC_TIMESTAMP() for consistency
    const query = `
      INSERT INTO messages (sender_id, receiver_id, message, timestamp, status)
      VALUES (?, ?, ?, UTC_TIMESTAMP(), 0)
    `;  
    const [result] = await db.query(query, [sender_id, receiver_id, encryptedMessage]);
    
    if (!result.insertId) {
      console.error(TAG, 'Failed to insert message - no insertId returned');
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to save message to database' 
      });
    }
    
    const newMessageId = result.insertId;
    console.log(TAG, `Message saved with ID: ${newMessageId}`);
    
    // Get the actual timestamp that was inserted
    const [insertedMsg] = await db.query(
      'SELECT timestamp FROM messages WHERE id = ?', 
      [newMessageId]
    );
    
    if (!insertedMsg || insertedMsg.length === 0) {
      console.error(TAG, 'Could not retrieve inserted message timestamp');
      // Still return success since message was saved
      return res.json({ 
        success: true, 
        message: 'Message sent successfully', 
        messageId: newMessageId 
      });
    }
    
    // Create the complete message object for Socket.IO
    const messageToEmit = {
      id: newMessageId,
      sender_id: sender_id,
      receiver_id: receiver_id,
      message: message, // Send DECRYPTED for real-time display
      timestamp: insertedMsg[0].timestamp,
      status: 0 // Sent
    };
    
    // Emit to the RECEIVER's room
    try {
      io.to(`chat_${receiver_id}`).emit('new_message_received', messageToEmit);
      console.log(TAG, `Emitted 'new_message_received' (ID: ${newMessageId}) to chat_${receiver_id}`);
    } catch (socketError) {
      console.error(TAG, 'Error emitting socket event:', socketError);
      // Don't fail the request if socket emit fails
    }
    
    // Send success response
    res.json({ 
      success: true, 
      message: 'Message sent successfully', 
      messageId: newMessageId 
    });
    
  } catch (error) {
    console.error(TAG, '❌ Error in /sendMessage:', error);
    console.error(TAG, 'Error stack:', error.stack);
    
    // Send proper error response
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send message',
      error: error.message 
    });
  }
});

app.get('/getChatUsers', async (req, res) => {
    const TAG = "/getChatUsers";
    try {
        const { userId } = req.query;
        if (!userId) {
            console.warn(TAG, "Request missing userId query parameter.");
            return res.status(400).json({ success: false, message: 'userId is required as a query parameter.' });
        }
        const currentUserId = parseInt(userId);
        
        console.log(TAG, `Fetching combined chat list for userId: ${currentUserId}`);
        
        const combinedQuery = `
            WITH LatestChats AS (
                -- Part 1: Individual Chats
                SELECT
                    'individual' AS chat_type,
                    CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END AS chat_id,
                    m.message AS last_message_content,
                    m.timestamp AS last_timestamp,
                    m.sender_id AS last_sender_id,
                    m.status AS last_message_status, -- *** ADD STATUS ***
                    ROW_NUMBER() OVER (
                        PARTITION BY CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
                        ORDER BY m.timestamp DESC
                    ) as rn
                FROM messages m
                LEFT JOIN hidden_messages hm ON m.id = hm.message_id AND hm.user_id = ?
                WHERE
                    (m.sender_id = ? OR m.receiver_id = ?)
                    AND hm.message_id IS NULL

                UNION ALL

                -- Part 2: Group Chats
                SELECT
                    'group' AS chat_type,
                    gm.group_id AS chat_id,
                    gm.message_content AS last_message_content,
                    gm.timestamp AS last_timestamp,
                    gm.sender_id AS last_sender_id,
                    -1 AS last_message_status, -- *** No status for groups ***
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
                lc.last_message_status, -- *** INCLUDE STATUS ***
                u_sender.name AS last_sender_name,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.name ELSE NULL END AS username,
                CASE WHEN lc.chat_type = 'individual' THEN u_partner.profile_pic ELSE NULL END AS profile_pic,
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
            currentUserId, currentUserId, currentUserId, currentUserId, currentUserId,
            currentUserId, currentUserId,
            currentUserId, currentUserId, currentUserId
        ];

        console.log(TAG, `Executing combined chat query for userId: ${currentUserId}`);
        const [rows] = await db.execute(combinedQuery, params);
        console.log(TAG, `Query returned ${rows.length} chat list items.`);

        const chatListItems = rows.map(row => {
            let lastMessage = "";
            try {
                lastMessage = row.last_message_content ? decrypt(row.last_message_content) : "";
            } catch (e) {
                console.error(TAG, `Failed to decrypt message content for chat_id ${row.chat_id}, type ${row.chat_type}:`, e.message);
                lastMessage = "[Encrypted Message]";
            }

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
                lastSenderId: row.last_sender_id,
                lastSenderName: row.last_sender_name,
                lastMessageStatus: row.last_message_status // *** ADD STATUS ***
            };
        });

        console.log(TAG, `Successfully processed ${chatListItems.length} chat items.`);
        res.json({ success: true, chats: chatListItems });

    } catch (error) {
        console.error(TAG, '❌ Error fetching combined chat list:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch chat list',
            error: error.sqlMessage || error.message
        });
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
    console.error(" Error blocking user:", err);
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
            WHERE tp.status = 'Active'
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
        console.error(" Error fetching users going:", err);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

app.get("/travel-plans/destinations", async (req, res) => {
  try {
    // --- Get currentUserId from query parameter ---
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'Current user ID (userId) is required as a query parameter.' });
    }
    const currentUserId = parseInt(userId); // Ensure it's a number
    // ---------------------------------------------

    // --- QUERY MODIFIED ---
    const query = `
      SELECT
        ANY_VALUE(tp.to_place) as destination,
        COUNT(tp.user_id) as userCount,
        ANY_VALUE(g.group_id) as group_id,
        -- This expression checks if the current user is among those going
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
    // --- END MODIFICATION ---

    // Pass currentUserId as the first parameter to the query
    const [destinations] = await db.query(query, [currentUserId]);

    // The response now includes `isCurrentUserGoing` (will be 1 for true, 0 for false)
    res.json({ success: true, destinations: destinations || [] });

  } catch (err) {
    console.error(" Error fetching travel plan destinations:", err);
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
            WHERE tp.to_place = ? AND tp.status = 'Active'
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
        console.error(' Error fetching users by destination:', error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// ADD THIS NEW ROUTE for removing profile pic
router.delete("/user/profile/:userId", async (req, res) => {
    const TAG = "/user/profile/:userId (DELETE)";
    try {
        const { userId } = req.params;

        if (!userId || isNaN(userId)) {
            console.warn(TAG, `Invalid userId: ${userId}`);
            return res.status(400).json({ success: false, message: "User ID required" });
        }

        // Update the user's profile_pic column to NULL
        await db.query("UPDATE users SET profile_pic = NULL WHERE id = ?", [parseInt(userId)]);

        console.log(TAG, `Removed profile pic for user ID: ${userId}`);
        
        // Return a response that includes the updated user (or null pic)
        // This helps updateLocalUserData in the app
        res.json({ 
            success: true, 
            message: "Profile picture removed",
            user: { profilePic: null } // Send back an object indicating the pic is null
        });

    } catch (err) {
        console.error(TAG, "Error removing profile pic:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Make sure this is registered with app.use(router);


router.get('/tripHistory/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 20 } = req.query;
    if (!userId || isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const updateStatusQuery = `
      UPDATE travel_plans SET status = 'Completed' 
      WHERE user_id = ? AND status = 'Active' AND time < NOW()`;
    await db.query(updateStatusQuery, [parseInt(userId)]);

    const offset = (page - 1) * limit;
    
    const historyQuery = `
      SELECT
        tp.id, 
        tp.from_place, 
        tp.to_place,
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

// In index.js (replace the existing /getUserByPhone route)

app.get("/getUserByPhone", async (req, res) => {
    const TAG = "/getUserByPhone"; // Logging tag
    // Expecting 'phone' (e.g., "8850260443") and 'country_code' (e.g., "+91") as query parameters
    const phone = req.query.phone;
    const country_code = req.query.country_code; // Get country code from query parameters

    // --- Validation ---
    if (!phone || !country_code) { // Check if both parameters are provided
        console.warn(TAG, "Request missing 'phone' or 'country_code' query parameter.");
        // Send a clear error message back to the app
        return res.status(400).json({ success: false, message: "Missing required phone number or country code." });
    }

    // Optional but recommended: Validate formats
    // Check if country_code starts with '+' followed by 1 to 4 digits
    if (!/^\+\d{1,4}$/.test(country_code)) {
         console.warn(TAG, `Invalid country code format received: ${country_code}`);
         return res.status(400).json({ success: false, message: "Invalid country code format (e.g., +91)." });
    }
     // Check if phone is exactly 10 digits (adjust regex if other lengths are valid)
     if (!/^\d{10}$/.test(phone)) {
         console.warn(TAG, `Invalid phone number format received: ${phone}`);
         return res.status(400).json({ success: false, message: "Invalid phone number format (should be 10 digits)." });
    }
    // --- End Validation ---


    try {
        console.log(TAG, `Searching for user with phone: ${country_code}${phone}`);
        // --- UPDATED QUERY: Select user WHERE both phone and country_code match ---
        const query = `
            SELECT id, name, college, phone, country_code, gender, dob, degree, year, profile_pic
            FROM users
            WHERE phone = ? AND country_code = ?;
        `;
        // Execute the query, passing both parameters safely
        const [results] = await db.query(query, [phone, country_code]);
        // --- END UPDATED QUERY ---

        // Check if any user was found
        if (results.length === 0) {
            console.log(TAG, `User not found for ${country_code}${phone}.`);
            // Return a 404 Not Found status code, indicating no user exists with this combination
            return res.status(404).json({ success: false, message: "User not registered with this phone number and country code." });
        }

        // User found
        const user = results[0];
        console.log(TAG, `User found for ${country_code}${phone}. User ID: ${user.id}`);

        // IMPORTANT: Ensure password hash is never sent back, even if selected with '*' previously
        delete user.password;

        // Send success response with user data
        res.json({ success: true, userId: user.id, user: user });

    } catch (err) {
        // Handle unexpected database or server errors
        console.error(TAG, `❌ Error searching for user ${country_code}${phone}:`, err);
        res.status(500).json({ success: false, message: "Server error while checking user information." });
    }
});

app.post('/markMessagesRead', async (req, res) => {
  try {
    const { userId, otherUserId } = req.body;
    if (!userId || !otherUserId) {
      return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
    }

    // --- UPDATED QUERY ---
    // This now sets the status to 2 (Read) for any message
    // from 'otherUserId' to 'userId' that is not already read (status < 2).
    const query = `
      UPDATE messages 
      SET status = 2 
      WHERE sender_id = ? AND receiver_id = ? AND status < 2
    `;
    
    // Note the order: [otherUserId, userId]
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


/**
 * GET TOTAL UNREAD COUNT
 *
 * This route calculates the total number of unread messages for a user
 * from BOTH individual and group chats, and returns a single count.
 * This is used for the notification badge on the HomeActivity.
 */
app.get('/getTotalUnreadCount', async (req, res) => {
    const TAG = "/getTotalUnreadCount"; // Add logging tag
    const { userId } = req.query;
    
    if (!userId) {
        console.warn(TAG, "Missing userId query parameter");
        return res.status(400).json({ success: false, message: 'userId is required' });
    }
    
    const currentUserId = parseInt(userId);
    console.log(TAG, `Calculating total unread count for userId: ${currentUserId}`);

    try {
        // 1. Count unread INDIVIDUAL messages
        const individualQuery = `
            SELECT COUNT(*) as totalUnreadCount 
            FROM messages 
            WHERE receiver_id = ? AND status < 2
        `;
        const [individualRows] = await db.execute(individualQuery, [currentUserId]);
        const individualCount = individualRows[0].totalUnreadCount;

        // 2. Count unread GROUP messages
        const groupQuery = `
            SELECT COUNT(*) as totalUnreadCount
            FROM group_messages gm
            WHERE 
                -- The user must be a member of the group
                gm.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)
                -- The message must NOT be from the user
                AND gm.sender_id != ?
                -- And there must NOT be a "read" receipt for this user and this message
                AND NOT EXISTS (
                    SELECT 1
                    FROM group_message_read_status gmrs
                    WHERE gmrs.message_id = gm.message_id
                      AND gmrs.user_id = ?
                );
        `;
        const [groupRows] = await db.execute(groupQuery, [currentUserId, currentUserId, currentUserId]);
        const groupCount = groupRows[0].totalUnreadCount;

        // 3. Add them together
        const totalUnreadCount = individualCount + groupCount;
        
        console.log(TAG, `Unread count for user ${currentUserId}: Individual=${individualCount}, Group=${groupCount}, Total=${totalUnreadCount}`);
        
        // *** FIX: Return 'unreadCount' to match UnreadCountResponse.java ***
        res.json({ 
            success: true, 
            unreadCount: totalUnreadCount  // Changed from 'totalUnreadCount'
        });

    } catch (error) {
        console.error(TAG, '❌ Error getting total unread count:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error', 
            error: error.sqlMessage || error.message 
        });
    }
});

app.post("/hideChat", async (req, res) => {
    const TAG = "/hideChat"; // Define TAG for logging context
    try {
        const { userId, otherUserId } = req.body;

        // Validation
        if (!userId || !otherUserId) {
            console.warn(TAG, `Request missing userId (${userId}) or otherUserId (${otherUserId})`);
            return res.status(400).json({ success: false, message: 'userId and otherUserId are required' });
        }

        if (userId === otherUserId) {
             console.warn(TAG, `User ${userId} tried to hide chat with themselves.`);
             return res.status(400).json({ success: false, message: 'Cannot hide chat with yourself' });
        }
        
        console.log(TAG, `User ${userId} requested to hide chat with ${otherUserId}`);

        // Step 1: Find all *existing* message IDs between these two users.
        const [messages] = await db.query(
            `SELECT id FROM messages 
             WHERE (sender_id = ? AND receiver_id = ?) 
                OR (sender_id = ? AND receiver_id = ?)`,
            [userId, otherUserId, otherUserId, userId]
        );

        // If there are no messages, there's nothing to hide.
        if (messages.length === 0) {
            console.log(TAG, `No messages found between ${userId} and ${otherUserId}. Nothing to hide.`);
            return res.json({ success: true, message: 'Chat hidden successfully (no messages).' });
        }

        // Step 2: Prepare to bulk-insert these message IDs into hidden_messages
        // The values format is an array of arrays: [ [messageId, userId, hidden_at_date], ... ]
        
        // --- THIS IS THE FIX ---
        const valuesToHide = messages.map(msg => [msg.id, userId, new Date()]);
        // --- END FIX ---

        // Step 3: Execute the bulk INSERT IGNORE query.
        const hideQuery = `
            INSERT IGNORE INTO hidden_messages (message_id, user_id, hidden_at)
            VALUES ?
        `; // The '?' will be replaced by the 'valuesToHide' array

        const [result] = await db.query(hideQuery, [valuesToHide]);

        console.log(TAG, `Successfully marked ${result.affectedRows} new messages as hidden for user ${userId} (chat with ${otherUserId}).`);

        // Send success response to the app
        res.json({ 
            success: true, 
            message: 'Chat history hidden successfully. New messages will appear here.' 
        });

    } catch (error) {
        console.error(TAG, "❌ Error in /hideChat:", error);
        res.status(500).json({ success: false, message: 'Failed to hide chat due to a server error.' });
    }
});

app.post("/cleanupDeletedMessages", async (req, res) => {
    const TAG = "/cleanupDeletedMessages";
    
    // Optional: Add a simple secret/key check to prevent unauthorized calls
    // const adminKey = req.headers['x-admin-key'];
    // if (adminKey !== process.env.YOUR_ADMIN_CRON_KEY) {
    //     console.warn(TAG, "Unauthorized cleanup attempt.");
    //     return res.status(403).json({ success: false, message: "Unauthorized" });
    // }

    try {
        console.log(TAG, "Starting scheduled cleanup task for mutually hidden messages...");

        // Step 1: Find all message IDs that appear 2 or more times in hidden_messages
        // (meaning at least two users have hidden them).
        const [deletableMessages] = await db.query(`
            SELECT message_id
            FROM hidden_messages
            GROUP BY message_id
            HAVING COUNT(DISTINCT user_id) >= 2
        `);

        if (deletableMessages.length === 0) {
            console.log(TAG, "Cleanup complete. No messages found for mutual deletion.");
            return res.status(200).json({ success: true, message: "No messages to clean up." });
        }

        // Collect all message IDs to be deleted
        const messageIdsToDelete = deletableMessages.map(msg => msg.message_id);
        console.log(TAG, `Found ${messageIdsToDelete.length} messages for permanent deletion.`);

        // Step 2: Use a transaction to delete from both tables safely
        const connection = await db.getConnection();
        await connection.beginTransaction();

        try {
            // Delete from the main 'messages' table first
            const [msgDeleteResult] = await connection.query(
                `DELETE FROM messages WHERE id IN (?)`,
                [messageIdsToDelete]
            );

            // Then, delete the corresponding entries from 'hidden_messages'
            const [hiddenDeleteResult] = await connection.query(
                `DELETE FROM hidden_messages WHERE message_id IN (?)`,
                [messageIdsToDelete]
            );

            // If both succeed, commit the changes
            await connection.commit();
            connection.release();

            const totalDeleted = msgDeleteResult.affectedRows;
            console.log(TAG, `Cleanup successful. Permanently deleted ${totalDeleted} messages.`);
            res.status(200).json({ success: true, message: `Cleaned up ${totalDeleted} messages.` });

        } catch (txError) {
            // If anything fails, roll back the entire transaction
            await connection.rollback();
            connection.release();
            console.error(TAG, "❌ Error during cleanup transaction, rolling back:", txError);
            throw txError; // Re-throw to be caught by the outer catch block
        }

    } catch (error) {
        console.error(TAG, "❌ Error running cleanup task:", error);
        res.status(500).json({ success: false, message: 'Server error during message cleanup.' });
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

router.get('/favorites/:userId', async (req, res) => {
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

router.post('/favorites', async (req, res) => {
    const { userId, routeName, fromPlace, toPlace, fromPlaceLat, fromPlaceLng, toPlaceLat, toPlaceLng } = req.body;

    if (!userId || !routeName || !fromPlace || !toPlace || fromPlaceLat === undefined || fromPlaceLng === undefined || toPlaceLat === undefined || toPlaceLng === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required fields, including all coordinates.' });
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

// ADD THIS ENTIRE BLOCK TO YOUR index.js FILE

app.get("/user/:userId", async (req, res) => {
    const TAG = "/user/:userId"; // Logging tag
    try {
        const { userId } = req.params; // Get the user ID from the URL path (e.g., "64")

        // Validation
        if (!userId || isNaN(userId)) {
            console.warn(TAG, `Invalid or missing userId parameter: ${userId}`);
            return res.status(400).json({ success: false, message: "Invalid or missing user ID." });
        }

        console.log(TAG, `Fetching profile data for userId: ${userId}`);

        // --- Query the database for the user's details ---
        // IMPORTANT: Explicitly list columns and EXCLUDE 'password'
        const query = `
            SELECT
                id, name, college, gender, dob, degree, year, profile_pic, profile_visibility
            FROM users
            WHERE id = ?;
        `;
        
        const [rows] = await db.query(query, [parseInt(userId)]);

        // Check if a user was found
        if (rows.length === 0) {
            console.warn(TAG, `User not found with ID: ${userId}`);
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const user = rows[0]; // The user data

        // --- IMPORTANT: As requested, HIDE the phone number ---
        // We didn't select 'phone' or 'country_code', so they won't be sent.

        console.log(TAG, `Successfully found user, returning profile for ID: ${userId}`);
        
        // Send the successful response in the format GetUserResponse expects
        res.json({ 
            success: true, 
            user: user // Send the user object
        }); 

    } catch (err) {
        // Handle any unexpected server or database errors
        console.error(TAG, `❌ Error fetching user profile for ID: ${req.params.userId}`, err);
        res.status(500).json({ success: false, message: "Server error while fetching user profile." });
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
        console.error(' Error deleting favorite:', error);
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
        console.error(' Error updating visibility:', error);
        res.status(500).json({ success: false, message: 'Database error.' });
    }
});

app.post('/change-password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 6 characters long'
            });
        }

        const [rows] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);

        if (rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const user = rows[0];
        const currentHashedPassword = user.password;

        const isMatch = await bcrypt.compare(currentPassword, currentHashedPassword);

        if (!isMatch) {
            return res.status(400).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        const isSamePassword = await bcrypt.compare(newPassword, currentHashedPassword);
        
        if (isSamePassword) {
            return res.status(400).json({
                success: false,
                message: 'New password must be different from current password'
            });
        }

        const newHashedPassword = await bcrypt.hash(newPassword, saltRounds);
        await db.query('UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?', [newHashedPassword, userId]);

        res.json({ 
            success: true, 
            message: 'Password changed successfully' 
        });

    } catch (error) {
        console.error(' Error changing password:', error);
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
    console.error(' Error getting online users:', error);
    res.status(500).json({ success: false, message: 'Error fetching online users' });
  }
});

app.get('/api/user-status/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const onlineData = onlineUsers.get(userId);
    if (onlineData) {
      return res.json({
        success: true,
        userId,
        isOnline: true,
        lastSeen: onlineData.lastSeen
      });
    }

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
    console.error(' Error checking user status:', error);
    res.status(500).json({ success: false, message: 'Error checking user status' });
  }
});

app.get('/group/:groupId/messages', async (req, res) => {
    const TAG = "/group/:groupId/messages"; // Logging Tag
    const { groupId } = req.params;
    const { userId } = req.query; // Get userId from query param

    if (!userId || !groupId) {
        console.warn(TAG, "Missing groupId or userId");
        return res.status(400).json({ success: false, message: 'Missing group or user ID' });
    }

    const currentGroupId = parseInt(groupId);
    const currentUserId = parseInt(userId);

    try {
        console.log(TAG, `Fetching messages for group ${currentGroupId}, requested by user ${currentUserId}`);

        const query = `
            SELECT 
                gm.message_id AS id, 
                gm.sender_id,
                gm.message_content AS message, -- Still encrypted
                gm.timestamp,
                u.name as sender_name,
                
                -- 1. (FOR "Read by X") - Counts how many other users have read it.
                (SELECT COUNT(DISTINCT gmr.user_id) 
                 FROM group_message_read_status gmr 
                 WHERE gmr.message_id = gm.message_id 
                   AND gmr.user_id != gm.sender_id) AS read_by_count,
                   
                -- 2. (FOR "Total Members") - Counts total members.
                (SELECT COUNT(*) 
                 FROM group_members gmemb 
                 WHERE gmemb.group_id = gm.group_id) AS total_participants,
                 
                -- 3. (FOR "Unread Header") - Check if the CURRENT user has read it.
                --    We use 'CASE' to return 2 (Read) or 0 (Sent/Unread).
                (CASE 
                    WHEN EXISTS (
                        SELECT 1 
                        FROM group_message_read_status gmr_user 
                        WHERE gmr_user.message_id = gm.message_id 
                          AND gmr_user.user_id = ? -- Check against the current user
                    ) THEN 2
                    ELSE 0 
                END) AS status
                     
            FROM group_messages gm
            
            -- Get the sender's name
            JOIN users u ON gm.sender_id = u.id
            
            -- Filter out messages this user has hidden
            LEFT JOIN hidden_messages hm ON gm.message_id = hm.message_id AND hm.user_id = ?
            
            WHERE gm.group_id = ? AND hm.message_id IS NULL
            ORDER BY gm.timestamp ASC;
        `;
        
        // Note the parameters now:
        // 1. currentUserId (for the 'status' subquery)
        // 2. currentUserId (for the 'hidden_messages' join)
        // 3. currentGroupId (for the main 'WHERE' clause)
        const [messages] = await db.execute(query, [currentUserId, currentUserId, currentGroupId]);
        console.log(TAG, `Fetched ${messages.length} visible messages for group ${currentGroupId}`);

        // Decrypt message content AFTER fetching
        const decryptedMessages = messages.map(msg => {
            try {
                return {
                    ...msg,
                    message: decrypt(msg.message), // Decrypt the content
                };
            } catch (decryptError) {
                console.error(TAG, `Failed to decrypt message ID ${msg.id}:`, decryptError);
                return { ...msg, message: "[Failed to decrypt message]" }; // Show error on client
            }
        });

        res.json({ success: true, messages: decryptedMessages });

    } catch (error) {
        console.error(TAG, `Error fetching group messages for group ${currentGroupId}:`, error);
        res.status(500).json({
            success: false,
            message: 'Server error fetching messages',
            error: error.sqlMessage || error.message 
        });
    }
});

app.post('/group/send', async (req, res) => {
    const { senderId, groupId, content } = req.body;
    const TAG = '/group/send';

    if (!senderId || !groupId || !content) {
        return res.status(400).json({ success: false, message: 'senderId, groupId, and content are required' });
    }

    try {
        const addMemberQuery = `INSERT IGNORE INTO group_members (user_id, group_id, joined_at) VALUES (?, ?, NOW())`;
        await db.execute(addMemberQuery, [senderId, groupId]);
    } catch (error) {
        console.error(TAG, `Error ensuring group membership:`, error);
    }

    try {
        const encryptedMessage = encrypt(content);
        
        const insertMessageQuery = `
            INSERT INTO group_messages (group_id, sender_id, message_content, timestamp)
            VALUES (?, ?, ?, NOW())
        `;
        
        const [result] = await db.execute(insertMessageQuery, [groupId, senderId, encryptedMessage]);
        const newMessageId = result.insertId;

        // Get the inserted message details for socket emission
        const [insertedMsg] = await db.query(
            `SELECT gm.message_id as id, gm.sender_id, gm.message_content as message, 
                    gm.timestamp, u.name as sender_name,
                    (SELECT COUNT(*) FROM group_members WHERE group_id = ?) as total_participants
             FROM group_messages gm
             JOIN users u ON gm.sender_id = u.id
             WHERE gm.message_id = ?`,
            [groupId, newMessageId]
        );

        if (insertedMsg && insertedMsg.length > 0) {
            const messageToEmit = {
                ...insertedMsg[0],
                message: content, // Send decrypted
                readByCount: 0,
                status: 0
            };

            // Emit to all group members
            io.to(`group_${groupId}`).emit('new_group_message', messageToEmit);
            console.log(TAG, `Emitted new_group_message to group_${groupId}`);
        }

        res.json({ success: true, message: 'Message sent', messageId: newMessageId });

    } catch (error) {
        console.error(TAG, `Error sending group message:`, error);
        res.status(500).json({ success: false, message: 'Failed to send message' });
    }
});

app.get('/group/:groupId/members', async (req, res) => {
    const TAG = "/group/:groupId/members"; // Logging tag
    const { groupId } = req.params;

    if (!groupId || isNaN(groupId)) {
        console.warn(TAG, `Invalid or missing groupId: ${groupId}`);
        return res.status(400).json({ success: false, message: 'Valid Group ID is required.' });
    }
    const currentGroupId = parseInt(groupId);

    try {
        console.log(TAG, `Fetching members for groupId: ${currentGroupId}`);

        // --- QUERY CORRECTED ---
        const query = `
            SELECT
                u.id,           -- Select the correct primary key 'id'
                u.id as userId, -- Also select as userId for consistency if needed
                u.name,
                u.profile_pic   -- Select profile picture if available
            FROM users u
            -- Corrected JOIN: Use u.id to join with group_members.user_id
            JOIN group_members gm ON u.id = gm.user_id
            WHERE gm.group_id = ?
            ORDER BY u.name ASC; -- Optional: Order alphabetically
        `;
        // --- END CORRECTION ---

        const [members] = await db.execute(query, [currentGroupId]);

        console.log(TAG, `Found ${members.length} members for groupId: ${currentGroupId}`);

        // Ensure response structure matches GroupMembersResponse (includes 'members' array)
        // Ensure fields match User model used in Android (id, name, profilePic)
        const responseMembers = members.map(member => ({
            id: member.id,          // Standard ID field
            userId: member.id,      // Explicit userId if needed elsewhere
            name: member.name,
            profilePic: member.profile_pic // Map profile_pic to profilePic
        }));

        res.json({ success: true, members: responseMembers }); // Correct response structure

    } catch (error) {
        console.error(TAG, `Error fetching group members for groupId ${currentGroupId}:`, error);
        res.status(500).json({
             success: false,
             message: 'Server error fetching members',
             error: error.sqlMessage || error.message
         });
    }
});

app.post('/group/read', async (req, res) => {
    // --- THIS IS THE FIX ---
    // We are now using 'user_id' and 'group_id' (snake_case)
    // to match what your Android app is sending.
    const { user_id, group_id } = req.body; 

    if (!user_id || !group_id) {
        return res.status(400).json({ success: false, message: 'Missing fields' });
    }    
    
    try {
        // This query finds all messages in the group (gm)
        // that do NOT have a matching entry in the read_status table (gmrs)
        // for this user, and then inserts them.
        const query = `
            INSERT INTO group_message_read_status (message_id, user_id, group_id)
            SELECT 
                gm.message_id AS message_id,
                ? AS user_id,
                gm.group_id
            FROM 
                group_messages gm
            WHERE 
                gm.group_id = ?
                AND NOT EXISTS (
                    SELECT 1
                    FROM group_message_read_status gmrs
                    WHERE 
                        gmrs.message_id = gm.message_id
                        AND gmrs.user_id = ?
                )
        `;
        
        // Use the snake_case variables in the query
        const [result] = await db.execute(query, [user_id, group_id, user_id]);
        
        res.json({ success: true, message: 'Messages marked as read', newReadCount: result.affectedRows });
    } catch (error) {
        console.error('Error marking messages read:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.use(router);

const PORT = process.env.PORT || 8080;
// --- FINAL FIX: Use server.listen() instead of app.listen() ---
server.listen(PORT, () => {
  console.log(`✅ Server (with Socket.IO) listening on http://0.0.0.0:${PORT}`);
});
