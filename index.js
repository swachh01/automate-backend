const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
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
    res.json({ success: true, message: 'User created' });
  });
});

// Login
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) {
    return res.status(400).json({ success: false, message: `Missing 
credentials` });
  }

  const query = 'SELECT * FROM users WHERE name = ? AND password = ?';
  db.query(query, [name, password], (err, results) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }

    if (results.length > 0) {
      const user = results[0];
      res.json({ success: true, message: 'Login successful', userId: 
user.id, name: user.name });
    } else {
      res.json({ success: false, message: 'Invalid username or password' 
});
    }
  });
});

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



// ===================== CHAT =====================

// Send a message (mark unread by default)
app.post('/sendMessage', (req, res) => {
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ success: false, message: `Missing fields` });
  }

  const query = `
    INSERT INTO messages (sender_id, receiver_id, message, is_read, deleted_by)
    VALUES (?, ?, ?, 0, JSON_ARRAY())
  `;
  db.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error('DB Error (sendMessage):', err);
      return res.status(500).json({ success: false, message: `Database error` });
    }
    res.json({ success: true, message: 'Message sent', messageId: result.insertId });
  });
});

// Get messages between two users (excluding deleted_by current user)
app.get('/getMessages', (req, res) => {
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) {
    return res.status(400).json({ success: false, message: `Missing senderId or receiverId` });
  }

  const query = `
    SELECT id, sender_id AS senderId, receiver_id AS receiverId, message,
           DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp,
           is_read
    FROM messages
    WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
      AND NOT JSON_CONTAINS(COALESCE(deleted_by, JSON_ARRAY()), JSON_ARRAY(?))
    ORDER BY timestamp ASC
  `;

  db.query(query, [senderId, receiverId, receiverId, senderId, senderId], (err, results) => {
    if (err) {
      console.error('DB Error (getMessages):', err);
      return res.status(500).json({ success: false, message: `Database error` });
    }
    res.json({ success: true, messages: results });
  });
});

// Mark messages as read
app.post('/markMessagesRead', (req, res) => {
  const { userId, otherUserId } = req.body;
  if (!userId || !otherUserId) {
    return res.status(400).json({ success: false, message: `Missing userId or otherUserId` });
  }

  const query = `
    UPDATE messages
    SET is_read = 1
    WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
  `;
  db.query(query, [otherUserId, userId], (err) => {
    if (err) {
      console.error('DB Error (markMessagesRead):', err);
      return res.status(500).json({ success: false, message: `Database error` });
    }
    res.json({ success: true, message: 'Messages marked as read' });
  });
});

// Delete a single message (soft delete)
app.delete("/deleteMessage/:messageId/:userId", (req, res) => {
  const { messageId, userId } = req.params;

  const query = `
    UPDATE messages
    SET deleted_by = JSON_ARRAY_APPEND(COALESCE(deleted_by, JSON_ARRAY()), '$', ?)
    WHERE id = ? AND NOT JSON_CONTAINS(COALESCE(deleted_by, JSON_ARRAY()), JSON_ARRAY(?))
  `;

  db.query(query, [userId, messageId, userId], (err, result) => {
    if (err) {
      console.error('DB Error (deleteMessage):', err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Message not found or already deleted" });
    }
    res.json({ success: true, message: "Message deleted for user" });
  });
});

// Delete entire chat (soft delete until both delete)
app.delete('/deleteChat/:userId/:otherUserId', (req, res) => {
  const { userId, otherUserId } = req.params;

  if (!userId || !otherUserId) {
    return res.status(400).json({ success: false, message: `Missing userId or otherUserId` });
  }

  // Step 1: Mark chat as deleted for this user
  const query = `
    UPDATE messages
    SET deleted_by = JSON_ARRAY_APPEND(COALESCE(deleted_by, JSON_ARRAY()), '$', ?)
    WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
      AND NOT JSON_CONTAINS(COALESCE(deleted_by, JSON_ARRAY()), JSON_ARRAY(?))
  `;

  db.query(query, [userId, userId, otherUserId, otherUserId, userId, userId], (err) => {
    if (err) {
      console.error('DB Error (deleteChat):', err);
      return res.status(500).json({ success: false, message: `Database error` });
    }

    // Step 2: Permanently delete if BOTH have deleted
    const cleanup = `
      DELETE FROM messages
      WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        AND JSON_CONTAINS(COALESCE(deleted_by, JSON_ARRAY()), JSON_ARRAY(?))
        AND JSON_CONTAINS(COALESCE(deleted_by, JSON_ARRAY()), JSON_ARRAY(?))
    `;
    db.query(cleanup, [userId, otherUserId, otherUserId, userId, userId, otherUserId], (cleanupErr) => {
      if (cleanupErr) {
        console.error('DB Error (deleteChat cleanup):', cleanupErr);
        return res.status(500).json({ success: false, message: `Database error` });
      }
      res.json({ success: true, message: 'Chat deleted for user (and cleaned if both deleted)' });
    });
  });
});



// ===================== TRAVEL PLANS =====================

// (your travel plan routes unchanged)

// ===================== MISC =====================
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.send('✅ Backend is working!');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on ${PORT}`);
});
