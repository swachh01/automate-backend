// index.js - Complete Fixed Version with Debug Support
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
const mysql = require("mysql2/promise");

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
});
const db = pool.promise();

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
  const [rows] = await db.query(
    `SELECT id, name, college, phone, gender, dob, degree, year, 
profile_pic FROM users WHERE phone = ?`,
    [phone]
  );
  return rows && rows[0] ? rows[0] : null;
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
failed` });
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


// Submit travel plan
app.post("/addTravelPlan", async (req, res) => {
  const { userId, destination, datetime } = req.body;

  if (!userId || !destination || !datetime) {
    return res.json({ success: false, message: "Missing fields" });
  }

  try {
    await pool.query(
      "INSERT INTO travel_plans (user_id, destination, datetime) VALUES (?, ?, ?)",
      [userId, destination, datetime]
    );
    res.json({ success: true, message: "Plan submitted successfully" });
  } catch (err) {
    console.error("❌ Error inserting travel plan:", err);
    res.json({ success: false, message: "Database error" });
  }
});

// Get all travel plans (with user info)
app.get("/getUserTravelPlan", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT tp.id, tp.destination, tp.datetime, u.name, u.college 
       FROM travel_plans tp 
       JOIN users u ON tp.user_id = u.id
       ORDER BY tp.datetime ASC`
    );
    res.json({ success: true, users: rows });
  } catch (err) {
    console.error("❌ Error fetching travel plans:", err);
    res.json({ success: false, message: "Database error" });
  }
});


// For Android Stage 4 to fetch the userId by phone when needed
app.get("/getUserByPhone", async (req, res) => {
  const phone = req.query.phone;
  console.log("📩 /getUserByPhone query:", req.query);
  
  if (!phone) {
    return res.status(400).json({ success: false, message: "Missing phone" 
});
  }

  try {
    const user = await getUserByPhone(phone);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
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

// ---------- Start ----------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://0.0.0.0:${PORT}`);
});
