//see this 
// index.js - Fixed Database Connection Version
require("dotenv").config();

const twilio = require("twilio");
const accountSid = process.env.TWILIO_SID;
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

// ---------- Middleware ----------
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Static for uploaded files
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------- DB Pool (GLOBAL) ----------
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || "localhost",
  user: process.env.MYSQLUSER || "root",
  password: process.env.MYSQLPASSWORD || "",
  database: process.env.MYSQLDATABASE || "yourdbname",
  port: process.env.MYSQLPORT ? Number(process.env.MYSQLPORT) : 3306,
  connectionLimit: 10,
  waitForConnections: true,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

// Create a promise-based wrapper for the pool
const db = pool.promise();

// Test database connection on startup
pool.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully');
    connection.release();
  }
});

// ---------- Multer (profile image) ----------
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase() || 
".jpg";
    cb(null, `profile_${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// ---------- Helpers ----------
async function getUserByPhone(phone) {
  try {
    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender, dob, degree, year, 
      profile_pic FROM users WHERE phone = ?`,
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
    // Test database connection
    await db.query('SELECT 1');
    res.json({ status: "OK", timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("❌ Health check failed:", err);
    res.status(500).json({ status: "ERROR", message: `Database connection 
failed: ${err.message}` });
  }
});

// Debug endpoint to check memory stores
app.get("/debug/stores", (req, res) => {
  // Only enable in development
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: "Not available in production" 
});
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

// Signup: expects { name, college, gender, phone }
app.post("/signup", async (req, res) => {
  try {
    const { name, college, gender, phone } = req.body || {};
    console.log("📩 /signup RAW body:", req.body);
    console.log("📩 /signup PARSED:", { name, college, gender, phone });

    if (!name || !college || !gender || !phone) {
      console.log("❌ Missing fields:", { 
        hasName: !!name, 
        hasCollege: !!college, 
        hasGender: !!gender, 
        hasPhone: !!phone 
      });
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields: name, college, gender, phone" 
      });
    }

    // Validate input
    if (name.trim().length < 2) {
      return res.status(400).json({ 
        success: false, 
        message: "Name must be at least 2 characters long" 
      });
    }

    // Check if user already exists
    const [existingUser] = await db.query(
      `SELECT id FROM users WHERE phone = ?`, 
      [phone]
    );
    
    if (existingUser.length > 0) {
      console.log("❌ User already exists for phone:", phone);
      return res.status(400).json({ 
        success: false, 
        message: "User with this phone number already exists" 
      });
    }

    // Save details in memory until OTP verified
    const signupData = { 
      name: name.trim(), 
      college: college.trim(), 
      gender 
    };
    
    signupStore[phone] = signupData;
    
    console.log("✅ Stored signup data for phone:", phone);
    console.log("✅ Signup data:", signupData);
    console.log("✅ Current signupStore keys:", Object.keys(signupStore));

    return res.json({ 
      success: true, 
      message: "Signup data received. Please verify OTP." 
    });
    
  } catch (err) {
    console.error("❌ /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- Send OTP ----------
app.post("/sendOtp", (req, res) => {
  const { phone } = req.body;
  console.log("📩 /sendOtp request:", { phone });
  
  if (!phone) {
    return res.status(400).json({ success: false, message: `Phone 
required` });
  }

  const otp = Math.floor(1000 + Math.random() * 9000);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

  // Store OTP as string for consistent comparison
  otpStore[phone] = { 
    otp: otp.toString(), 
    expires: expiresAt 
  };
  
  console.log(`📩 Generated OTP for ${phone}: ${otp}, expires: ${new 
Date(expiresAt)}`);

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
        // Remove OTP from response in production for security
        ...(process.env.NODE_ENV === 'development' && { otp })
      });
    })
    .catch(err => {
      console.error("❌ SMS Error:", err);
      res.status(500).json({ success: false, message: "Failed to send SMS" 
});
    });
});

// ---------- Verify OTP ----------
app.post("/verifyOtp", async (req, res) => {
  try {
    const { phone, otp } = req.body;
    console.log("📩 /verifyOtp request:", { phone, otp: otp ? "****" : 
"missing" });
    
    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: `Phone and 
OTP required` });
    }
    
    // Check OTP first
    const entry = otpStore[phone];
    console.log("📊 Stored OTP entry:", entry ? { hasOtp: !!entry.otp, 
expires: new Date(entry.expires), now: new Date() } : "not found");

    if (!entry) {
      return res.status(400).json({ success: false, message: `No OTP found 
for this phone. Please request a new OTP.` });
    }
    
    if (Date.now() > entry.expires) {
      delete otpStore[phone];
      return res.status(400).json({ success: false, message: `OTP expired. 
Please request a new OTP.` });
    }
    
    // Convert both to strings for comparison
    if (entry.otp !== otp.toString()) {
      console.log(`❌ OTP mismatch: stored="${entry.otp}", 
received="${otp}"`);
      return res.status(400).json({ success: false, message: "Invalid OTP" 
});
    }

    // Check signup data BEFORE clearing OTP
    const signupData = signupStore[phone];
    console.log("📊 Signup data for phone", phone, ":", signupData);
    console.log("📊 All signupStore keys:", Object.keys(signupStore));
    
    if (!signupData) {
      // DON'T clear OTP here - let user retry with proper signup data
      console.log("❌ No signup data found for phone:", phone);
      return res.status(400).json({ 
        success: false, 
        message: `Signup data missing. Please complete signup process 
first.` 
      });
    }

    // Validate signup data
    if (!signupData.name || !signupData.college || !signupData.gender) {
      console.log("❌ Invalid signup data:", signupData);
      return res.status(400).json({ 
        success: false, 
        message: "Invalid signup data. Please restart signup process." 
      });
    }

    // Clear OTP after successful verification AND valid signup data
    delete otpStore[phone];

    // Insert user into database
    console.log("🔄 Creating user with data:", signupData);
    const [result] = await db.query(
      `INSERT INTO users (name, college, password, phone, gender, 
created_at) VALUES (?, ?, ?, ?, ?, NOW())`,
      [signupData.name, signupData.college, "", phone, signupData.gender]
    );

    // Clear signup data after successful creation
    delete signupStore[phone];

    console.log(`✅ User created: ID=${result.insertId}, 
Name="${signupData.name}", Phone=${phone}`);

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
    return res.status(500).json({ success: false, message: `Database 
error: ` + err.message });
  }
});

// ✅ Save password & return userId - FIXED VERSION
app.post("/savePassword", async (req, res) => {
    try {
        const { phone, newPassword } = req.body;
        
        console.log("📩 /savePassword request:", { phone: phone ? "***" + 
phone.slice(-4) : "missing", hasPassword: !!newPassword });

        if (!phone || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: "Phone and password required" 
            });
        }

        // Validate password strength
        if (newPassword.length < 4) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 4 characters long" 
            });
        }

        // Use the promise-based db connection for consistency
        const [updateResult] = await db.query(
            "UPDATE users SET password = ? WHERE phone = ?", 
            [newPassword, phone]
        );

        console.log("📊 Update result:", updateResult);

        if (updateResult.affectedRows === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found" 
            });
        }

        // ✅ Fetch userId after updating
        const [userRows] = await db.query(
            "SELECT id FROM users WHERE phone = ?", 
            [phone]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: "User not found after update" 
            });
        }

        const userId = userRows[0].id;
        console.log(`✅ Password updated for phone: ***${phone.slice(-4)} 
-> userId: ${userId}`);

        return res.json({
            success: true,
            message: "Password updated successfully",
            userId: userId
        });

    } catch (err) {
        console.error("❌ Error in /savePassword:", err);
        return res.status(500).json({ 
            success: false, 
            message: "Database error",
            error: process.env.NODE_ENV === 'development' ? err.message : 
undefined
        });
    }
});

// Login: expects { phone, password }
app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
  console.log("📩 /login body:", { phone, hasPassword: !!password });

  if (!phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Missing phone or password" });
  }

  try {
    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender, dob, degree, year, 
      profile_pic FROM users WHERE phone = ? AND password = ?`,
      [phone, password]
    );
    
    if (!rows.length) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }
    
    console.log(`✅ Login successful for user: ${rows[0].name} (ID: 
${rows[0].id})`);
    
    res.json({
      success: true,
      message: "Login successful",
      userId: rows[0].id,
      user: rows[0],
    });
  } catch (err) {
    console.error("❌ /login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Submit travel plan - FIXED VERSION
app.post("/addTravelPlan", async (req, res) => {
  try {
    // Accept both 'time' and 'datetime' for flexibility
    const { userId, destination, datetime, time } = req.body;
    const actualTime = datetime || time; // Use datetime if provided, 

    console.log("📩 /addTravelPlan request:", req.body);

    if (!userId || !destination || !actualTime) {
      console.log("❌ Missing fields:", { userId, destination, datetime, 
time, actualTime });
      return res.json({ 
        success: false, 
        message: `Missing required fields: userId, destination, and 
time/datetime` 
      });
    }

    const [result] = await db.query(
      `INSERT INTO travel_plans (user_id, destination, time) VALUES (?, ?, 
?)`,
      [userId, destination, actualTime]
    );
    
    console.log(`✅ Travel plan created: ID=${result.insertId} for 
userId=${userId} to ${destination}`);
    
    res.json({ 
      success: true, 
      message: "Plan submitted successfully", 
      id: result.insertId 
    });
  } catch (err) {
    console.error("❌ Error inserting travel plan:", err);
    res.status(500).json({ 
      success: false, 
      message: "Database error",
      error: process.env.NODE_ENV === 'development' ? err.message : 
undefined
    });
  }
});



// Get all travel plans (with user info)
app.get("/getUserTravelPlan", (req, res) => {
  pool.query(
    `SELECT tp.id, tp.destination, tp.time, u.name, u.college
     FROM travel_plans tp
     JOIN users u ON tp.user_id = u.id
     ORDER BY tp.time ASC`,
    (err, results) => {
      if (err) {
        console.error("❌ Error fetching travel plans:", err);
        return res.json({ success: false, message: "Database error", 
users: [] });
      }
      console.log("Travel Plan fetched:", results);
      // ✅ Always return an array
      res.json({ success: true, users: results || [] });
    }
  );
});

app.get("/getUsersGoing", async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT tp.user_id, tp.destination,
       DATE_FORMAT(tp.time, '%Y-%m-%d %H:%i:%s') as time,
       u.name, u.college
       FROM travel_plans tp
       JOIN users u ON tp.user_id = u.id
       WHERE tp.time > NOW()
       ORDER BY tp.time ASC`
    );

    console.log("Raw query results:", rows);

    // Map to match your GoingUser class structure
    const usersGoing = rows.map(row => ({
      userId: row.user_id,  // Make sure this field exists
      name: row.name,
      destination: row.destination,
      time: row.time,
      college: row.college
    }));

    console.log("Mapped usersGoing:", usersGoing);

    res.json({ 
      success: true, 
      usersGoing: usersGoing  // This should match your UsersGoingResponse 
    });
    
  } catch (err) {
    console.error("❌ Error fetching users going:", err);
    res.status(500).json({ 
      success: false, 
      message: "Database error",
      usersGoing: []
    });
  }
});

// Fetch user by phone
app.get("/getUserByPhone", async (req, res) => {
  const phone = req.query.phone;
  console.log("📩 /getUserByPhone query:", req.query);

  if (!phone) {
    return res.status(400).json({ success: false, message: "Missing phone" 
});
  }

  try {
    const [results] = await db.query(
      "SELECT * FROM users WHERE phone = ?",
      [phone]
    );
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: `User not 
found` });
    }
    
    const user = results[0];
    res.json({ success: true, userId: user.id, user });
  } catch (err) {
    console.error("❌ /getUserByPhone error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Update profile (multipart form-data):
// Fields: userId, dob, degree, year
// File: profile_pic
app.post("/updateProfile", upload.single("profile_pic"), async (req, res) => {
  try {
    const { userId, dob, degree, year } = req.body || {};
    const file = req.file;
    console.log("📩 /updateProfile fields:", req.body);
    console.log("📎 /updateProfile file:", !!file ? file.filename : 
"none");

    if (!userId) {
      return res
        .status(400)
        .json({ success: false, message: "Missing userId" });
    }

    let imagePath = null;
    if (file) {
      imagePath = `/uploads/${file.filename}`;
    }

    const sets = [];
    const params = [];

    if (dob) {
      sets.push("dob = ?");
      params.push(dob);
    }
    if (degree) {
      sets.push("degree = ?");
      params.push(degree);
    }
    if (year) {
      sets.push("year = ?");
      params.push(year);
    }
    if (imagePath) {
      sets.push("profile_pic = ?");
      params.push(imagePath);
    }

    if (!sets.length) {
      return res
        .status(400)
        .json({ success: false, message: "Nothing to update" });
    }

    const sql = `UPDATE users SET ${sets.join(", ")} WHERE id = ?`;
    params.push(userId);

    const [result] = await db.query(sql, params);
    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender, dob, degree, year, 
      profile_pic FROM users WHERE id = ?`,
      [userId]
    );

    console.log(`✅ Profile updated for userId: ${userId}`);

    res.json({
      success: true,
      message: "Profile updated",
      user: rows[0],
    });
  } catch (err) {
    console.error("❌ /updateProfile error:", err);
    res
      .status(500)
      .json({ success: false, message: "Internal Server Error" });
  }
});


// Send a message
app.post('/sendMessage', async (req, res) => {
    try {
        const { senderId, receiverId, message } = req.body;
        
        if (!senderId || !receiverId || !message) {
            return res.status(400).json({ 
                success: false, 
                message: 'senderId, receiverId, and message are required' 
            });
        }

        const query = `
            INSERT INTO messages (sender_id, receiver_id, message) 
            VALUES (?, ?, ?)
        `;
        
        await db.execute(query, [senderId, receiverId, message]);
        
        res.json({ success: true, message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, message: `Failed to send 
message` });
    }
});

// Get messages between two users
app.get('/getMessages', async (req, res) => {
    try {
        const { senderId, receiverId } = req.query;
        
        if (!senderId || !receiverId) {
            return res.status(400).json({ 
                success: false, 
                message: 'senderId and receiverId are required' 
            });
        }

        const query = `
            SELECT id, sender_id as senderId, receiver_id as receiverId, 
                   message, created_at as timestamp
            FROM messages 
            WHERE (sender_id = ? AND reciever_id = ?) 
               OR (sender_id = ? AND reciever_id = ?)
            ORDER BY created_at ASC
        `;
        
        const [rows] = await db.execute(query, [senderId, receiverId, 
receiverId, senderId]);
        
        res.json({
            success: true,
            messages: rows || []
        });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ success: false, message: `Failed to fetch 
messages` });
    }
});

// Get chat users (simplified - users who have chatted with current user)
app.get('/getChatUsers', async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(400).json({ 
                success: false, 
                message: 'userId is required' 
            });
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
                WHERE sender_id = ? OR receiver_id = ?
            ) latest ON u.id = latest.other_user_id AND latest.rn = 1
            ORDER BY latest.last_timestamp DESC
        `;
        
        const [rows] = await db.execute(query, [userId, userId, userId, 
userId]);
        
        res.json({
            success: true,
            chats: rows || []
        });
    } catch (error) {
        console.error('Error fetching chat users:', error);
        res.status(500).json({ success: false, message: `Failed to fetch 
chat users` });
    }
});

// Mark messages as read (placeholder for now)
app.post('/markMessagesRead', async (req, res) => {
    try {
        res.json({ success: true, message: 'Messages marked as read' });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.status(500).json({ success: false, message: `Failed to mark 
messages as read` });
    }
});

// Get unread count (return 0 for now)
app.get('/unreadCount/:userId', async (req, res) => {
    try {
        res.json({
            success: true,
            unreadCount: 0
        });
    } catch (error) {
        console.error('Error getting unread count:', error);
        res.status(500).json({ success: false, message: `Failed to get 
unread count` });
    }
});

// Delete entire chat between two users
app.delete('/deleteChat/:userId/:receiverId', async (req, res) => {
    try {
        const { userId, receiverId } = req.params;
        
        const deleteQuery = `
            DELETE FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
               OR (sender_id = ? AND receiver_id = ?)
        `;
        
        await db.execute(deleteQuery, [userId, receiverId, receiverId, 
userId]);
        
        res.json({ success: true, message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Error deleting chat:', error);
        res.status(500).json({ success: false, message: `Failed to delete 
chat` });
    }
});

// Delete a specific message
app.delete('/deleteMessage/:messageId', async (req, res) => {
    try {
        const { messageId } = req.params;
        
        await db.execute('DELETE FROM messages WHERE id = ?', 
[messageId]);
        
        res.json({ success: true, message: 'Message deleted successfully' 
});
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ success: false, message: `Failed to delete 
message` });
    }
});

// ---------- Start ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
