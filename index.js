// index.js
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
app.get("/health", (_req, res) => res.sendStatus(200));

// Signup: expects { name, college, gender, phone }

app.post("/signup", async (req, res) => {
  try {
    const { name, college, gender, phone } = req.body || {};
    console.log("📩 /signup body:", req.body);

    if (!name || !college || !gender || !phone) {
      return res.status(400).json({ success: false, message: "Missing name/college/gender/phone" });
    }

    // Save details in memory until OTP verified
    signupStore[phone] = { name, college, gender };
    console.log("✅ Stored signup data for", phone, signupStore[phone]);

    return res.json({ success: true, message: "Signup data received. Please verify OTP." });
  } catch (err) {
    console.error("❌ /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// ---------- Send OTP ----------
app.post("/sendOtp", (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: "Phone required" });

  const otp = Math.floor(1000 + Math.random() * 9000); // 4-digit OTP for simplicity

  otpStore[phone] = { otp: otp.toString(), expires: Date.now() + 5 * 60 * 1000 }; // store as string
  console.log(`📩 Generated OTP for ${phone}: ${otp}`);

  client.messages
    .create({
      body: `Your OTP is ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: `+91${phone}` // keep consistent format
    })
    .then(() => {
      res.json({ success: true, message: "OTP sent successfully", otp });
    })
    .catch(err => {
      console.error("❌ SMS Error:", err);
      res.status(500).json({ success: false, message: "Failed to send SMS" });
    });
});

// ---------- Verify OTP ----------

app.post("/verifyOtp", async (req, res) => {
  const { phone, otp } = req.body;
  const entry = otpStore[phone];

  console.log("📩 Verify request:", req.body, "Stored:", entry);

  if (!entry) return res.status(400).json({ success: false, message: "No OTP found for this phone" });
  if (Date.now() > entry.expires) {
    delete otpStore[phone];
    return res.status(400).json({ success: false, message: "OTP expired" });
  }
  if (entry.otp !== otp.toString()) {
    return res.status(400).json({ success: false, message: "Invalid OTP" });
  }
  delete otpStore[phone];
  const signupData = signupStore[phone];
  if (!signupData) {
    return res.status(400).json({ success: false, message: "Signup data missing, restart signup" });
  }

  try {
    const [result] = await db.query(
      `INSERT INTO users (name, college, password, phone, gender) VALUES (?, ?, ?, ?, ?)`,
      [signupData.name, signupData.college, "", phone, signupData.gender]
    );

    delete signupStore[phone];

    return res.json({
      success: true,
      message: "OTP verified and user created",
      userId: result.insertId
    });
  } catch (err) {
    console.error("❌ Error inserting user:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});



// ✅ Save password & return userId
app.post("/savePassword", (req, res) => {
    const { phone, newPassword } = req.body;

    if (!phone || !newPassword) {
        return res.status(400).json({ success: false, message: `Phone and 
password required` });
    }

    // Hash the password (recommended in production, but keeping plain 
    const sql = "UPDATE users SET password = ? WHERE phone = ?";
    pool.query(sql, [newPassword, phone], (err, result) => {
        if (err) {
            console.error("❌ Error saving password:", err);
            return res.status(500).json({ success: false, message: 
"Database error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: `User 
not found` });
        }

        // ✅ Fetch userId after updating
        pool.query("SELECT id FROM users WHERE phone = ?", [phone], (err2, 
rows) => {
            if (err2) {
                console.error("❌ Error fetching userId:", err2);
                return res.status(500).json({ success: false, message: 
"Database error" });
            }

            if (rows.length === 0) {
                return res.status(404).json({ success: false, message: 
"User not found" });
            }

            const userId = rows[0].id;
            console.log(`✅ Password updated for phone:", phone, "-> 
userId:`, userId);

            return res.json({
                success: true,
                message: "Password updated successfully",
                userId: userId
            });
        });
    });
});


// Login: expects { phone, password }
app.post("/login", async (req, res) => {
  const { phone, password } = req.body || {};
  console.log("📩 /login body:", req.body);

  if (!phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Missing phone or password" });
  }

  try {
    const [rows] = await db.query(
      `SELECT id, name, college, phone, gender FROM users WHERE phone = ? 
AND password = ?`,
      [phone, password]
    );
    if (!rows.length) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }
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
// File:   profile_pic
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

