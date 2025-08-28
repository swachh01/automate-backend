const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection pool
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// ✅ Test DB connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Failed to connect to MySQL:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Connected to MySQL database');
    connection.release();
  }
});

// ===================== AUTH =====================
// Signup
app.post('/signup', (req, res) => {
  const { name, college, password } = req.body;
  if (!name || !college || !password) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  const query = `INSERT INTO users (name, college, password) VALUES (?, ?, 
?)`;
  db.query(query, [name, college, password], (err) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: "User created" });
  });
});

// Login
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) {
    return res.status(400).json({ success: false, message: `Missing 
credentials` });
  }
  const query = "SELECT * FROM users WHERE name = ? AND password = ?";
  db.query(query, [name, password], (err, results) => {
    if (err) {
      console.error("DB Error:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    if (results.length > 0) {
      const user = results[0];
      res.json({ success: true, message: "Login successful", userId: 
user.id, name: user.name });
    } else {
      res.json({ success: false, message: "Invalid username or password" 
});
    }
  });
});

// ===================== TRAVEL PLANS =====================
// Get all travel plans with user details
app.get("/going-users", (req, res) => {
  const query = `
    SELECT users.id AS userId, users.name AS username, users.college,
           travel_plans.destination, travel_plans.time
    FROM travel_plans
    JOIN users ON travel_plans.user_id = users.id
    ORDER BY travel_plans.time ASC
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching going users:", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, users: results });
  });
});

// Add or Update Travel Plan (store UTC, accept IST)
app.post('/addTravelPlan', (req, res) => {
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }

  const checkQuery = "SELECT * FROM travel_plans WHERE user_id = ?";
  db.query(checkQuery, [userId], (err, results) => {
    if (err) {
      console.error("Check error:", err);
      return res.status(500).json({ success: false, message: "DB error" 
});
    }
    if (results.length > 0) {
      const updateQuery = `
        UPDATE travel_plans
        SET destination = ?, time = CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d 
%H:%i:%s'), '+05:30', '+00:00')
        WHERE user_id = ?
      `;
      db.query(updateQuery, [destination, time, userId], (err) => {
        if (err) {
          console.error("Update error:", err);
          return res.status(500).json({ success: false, message: `Update 
failed` });
        }
        res.json({ success: true, message: "Travel plan updated" });
      });
    } else {
      const insertQuery = `
        INSERT INTO travel_plans (user_id, destination, time)
        VALUES (?, ?, CONVERT_TZ(STR_TO_DATE(?, '%Y-%m-%d %H:%i:%s'), 
'+05:30', '+00:00'))
      `;
      db.query(insertQuery, [userId, destination, time], (err) => {
        if (err) {
          console.error("Insert error:", err);
          return res.status(500).json({ success: false, message: `Insert 
failed` });
        }
        res.json({ success: true, message: "Travel plan added" });
      });
    }
  });
});

// Get Current User's Travel Plan (return in IST)
app.get('/getUserTravelPlan', (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ success: false, message: 
"Missing userId" });

  const query = `
    SELECT destination,
           DATE_FORMAT(CONVERT_TZ(time, '+00:00', '+05:30'), '%Y-%m-%d 
%H:%i:%s') AS time
    FROM travel_plans
    WHERE user_id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Fetch error:", err);
      return res.status(500).json({ success: false, message: "DB error" 
});
    }
    if (results.length === 0) {
      return res.json(null);
    }
    res.json(results[0]);
  });
});

// Fetch ALL travel plans (return in IST)
app.get('/getTravelPlans', (req, res) => {
  const fetchQuery = `
    SELECT users.id AS userId, users.name AS username, users.college AS 
college,
           travel_plans.destination,
           DATE_FORMAT(CONVERT_TZ(travel_plans.time, '+00:00', '+05:30'), 
'%d/%m/%Y %H:%i') AS time
    FROM travel_plans
    INNER JOIN users ON travel_plans.user_id = users.id
    ORDER BY travel_plans.time ASC
  `;
  db.query(fetchQuery, (fetchErr, results) => {
    if (fetchErr) {
      console.error("Fetch Error:", fetchErr);
      return res.status(500).json({ success: false, message: `Fetch 
failed` });
    }
    res.json({ success: true, users: results });
  });
});

// ===================== CHAT =====================
// Send a message
app.post('/sendMessage', (req, res) => {
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }
  const query = `INSERT INTO messages (sender_id, receiver_id, message) 
VALUES (?, ?, ?)`;
  db.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error("DB Error (sendMessage):", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: "Message sent", messageId: 
result.insertId });
  });
});

// Get messages between two users
app.get('/getMessages', (req, res) => {
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) {
    return res.status(400).json({ success: false, message: `Missing 
senderId or receiverId` });
  }
  const query = `
    SELECT id, sender_id AS senderId, receiver_id AS receiverId, message,
           DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp
    FROM messages
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND 
receiver_id = ?)
    ORDER BY timestamp ASC
  `;
  db.query(query, [senderId, receiverId, receiverId, senderId], (err, 
results) => {
    if (err) {
      console.error("DB Error (getMessages):", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, messages: results });
  });
});

// Fetch recent chats (for ChatListActivity)
app.get('/getChatUsers', (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ success: false, message: `Missing 
userId` });
  }
  const query = `
    SELECT u.id, u.name AS username,
      (SELECT m.message FROM messages m
        WHERE (m.sender_id = u.id AND m.receiver_id = ?) OR (m.sender_id = 
? AND m.receiver_id = u.id)
        ORDER BY m.timestamp DESC LIMIT 1) AS lastMessage,
      (SELECT m.timestamp FROM messages m
        WHERE (m.sender_id = u.id AND m.receiver_id = ?) OR (m.sender_id = 
? AND m.receiver_id = u.id)
        ORDER BY m.timestamp DESC LIMIT 1) AS timestamp
    FROM users u
    WHERE u.id != ?
    HAVING lastMessage IS NOT NULL
    ORDER BY timestamp DESC
  `;
  db.query(query, [userId, userId, userId, userId, userId], (err, results) => { 
    if (err) {
      console.error("DB Error (getChatUsers):", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, chats: results });
  });
});

// ✅ Delete an entire chat between two users
app.delete('/deleteChat/:userId/:otherUserId', (req, res) => {
  const { userId, otherUserId } = req.params;
  if (!userId || !otherUserId) {
    return res.status(400).json({ success: false, message: `Missing userId 
or otherUserId` });
  }
  const query = `
    DELETE FROM messages
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND 
receiver_id = ?)
  `;
  db.query(query, [userId, otherUserId, otherUserId, userId], (err) => {
    if (err) {
      console.error("DB Error (deleteChat):", err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: "Chat deleted successfully" });
  });
});

// ===================== MISC =====================
app.get('/health', (req, res) => {
  res.status(200).json({ status: "ok" });
});

app.get('/', (req, res) => {
  res.send("✅ Backend is working!");
});

// Cleanup job to remove expired travel plans
setInterval(async () => {
  try {
    const [result] = await db.query(
      "DELETE FROM travel_plans WHERE travel_time <= NOW()"
    );
    if (result.affectedRows > 0) {
      console.log(`Deleted ${result.affectedRows} expired travel 
plan(s)`);
    }
  } catch (err) {
    console.error("Error cleaning travel plans:", err);
  }
}, 60000); // runs every 1 minute


// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on ${PORT}`);
});

