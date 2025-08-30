// index.js
require("dotenv").config();

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

// In-memory OTP store (replace with DB table if you want)
const otps = {}; // { [phone]: { code, expires } }

// ---------- Routes ----------

// Health
app.get("/health", (_req, res) => res.sendStatus(200));

// Signup: expects { name, college, gender, phone }
app.post("/signup", async (req, res) => {
  try {
    const { name, college, gender, phone } = req.body || {};
    console.log("📩 /signup body:", req.body);

    if (!name || !college || !gender || !phone) {
      return res
        .status(400)
        .json({ success: false, message: `Missing 
name/college/gender/phone` });
    }

    // Does user already exist?
    const [exists] = await db.query(`SELECT id FROM users WHERE phone = 
?`, [
      phone,
    ]);
    if (exists.length) {
      // Update details if already exists
      await db.query(
        `UPDATE users SET name = ?, college = ?, gender = ? WHERE phone = 
?`,
        [name, college, gender, phone]
      );
      return res.json({
        success: true,
        message: "User updated",
        userId: exists[0].id,
      });
    }

    // NOTE: your schema has `password` NOT NULL.
    // If password is set later (Stage 3), insert a temporary placeholder.
    const [result] = await db.query(
      `INSERT INTO users (name, college, password, phone, gender) VALUES 
(?, ?, ?, ?, ?)`,
      [name, college, "", phone, gender]
    );

    return res.json({
      success: true,
      message: "User created",
      userId: result.insertId,
    });
  } catch (err) {
    console.error("❌ /signup error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Send OTP: expects { phone }
app.post("/sendOtp", (req, res) => {
  const { phone } = req.body || {};
  console.log("📩 /sendOtp body:", req.body);

  if (!phone) {
    return res.status(400).json({ success: false, message: "Missing phone" 
});
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  otps[phone] = { code, expires: Date.now() + 5 * 60 * 1000 };
  console.log(`🔐 OTP for ${phone}: ${code}`);
  // Send via SMS provider here in real life.

  res.json({ success: true, message: "OTP sent" });
});

// Verify OTP: expects { phone, otp }
app.post("/verifyOtp", async (req, res) => {
  const { phone, otp } = req.body || {};
  console.log("📩 /verifyOtp body:", req.body);

  if (!phone || !otp) {
    return res
      .status(400)
      .json({ success: false, message: "Missing phone or otp" });
  }

  const entry = otps[phone];
  if (!entry || entry.expires < Date.now() || entry.code !== otp) {
    return res.status(400).json({ success: false, message: "Invalid OTP" 
});
  }
  delete otps[phone];

  try {
    const user = await getUserByPhone(phone);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found for this phone" 
});
    }
    return res.json({
      success: true,
      message: "OTP verified",
      userId: user.id,
    });
  } catch (err) {
    console.error("❌ /verifyOtp error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Save password: expects { phone, newPassword }
app.post("/savePassword", async (req, res) => {
  const { phone, newPassword } = req.body || {};
  console.log("📩 /savePassword body:", req.body);

  if (!phone || !newPassword) {
    return res
      .status(400)
      .json({ success: false, message: "Missing phone or password" });
  }

  try {
    const [result] = await db.query(
      "UPDATE users SET password = ? WHERE phone = ?",
      [newPassword, phone]
    );

    if (result.affectedRows === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("❌ /savePassword error:", err);
    res.status(500).json({ success: false, message: `Failed to save 
password` });
  }
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

