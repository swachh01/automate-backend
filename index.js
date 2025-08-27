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

// Send a message (mark unread by default) 🔥 NEW
app.post('/sendMessage', (req, res) => {
  const { senderId, receiverId, message } = req.body;

  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }

  const query = `INSERT INTO messages (sender_id, receiver_id, message, 
is_read) VALUES (?, ?, ?, 0)`;
  db.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error('DB Error (sendMessage):', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: 'Message sent', messageId: 
result.insertId });
  });
});

// Get messages between two users (chat history)
app.get('/getMessages', (req, res) => {
  const { senderId, receiverId } = req.query;

  if (!senderId || !receiverId) {
    return res.status(400).json({ success: false, message: `Missing 
senderId or receiverId` });
  }

  const query = `
    SELECT id, sender_id AS senderId, receiver_id AS receiverId, message,
           DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp,
           is_read
    FROM messages
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
    ORDER BY timestamp ASC
  `;

  db.query(query, [senderId, receiverId, receiverId, senderId], (err, 
results) => {
    if (err) {
      console.error('DB Error (getMessages):', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, messages: results });
  });
});

// 🔥 NEW: Mark messages as read
app.post('/markMessagesRead', (req, res) => {
  const { userId, otherUserId } = req.body;

  if (!userId || !otherUserId) {
    return res.status(400).json({ success: false, message: `Missing userId 
or otherUserId` });
  }

  const query = `
    UPDATE messages
    SET is_read = 1
    WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
  `;

  db.query(query, [otherUserId, userId], (err) => {
    if (err) {
      console.error('DB Error (markMessagesRead):', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: 'Messages marked as read' });
  });
});

// 🔥 NEW: Get unread chats count (for homepage badge)
app.get('/getUnreadChatsCount', (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ success: false, message: `Missing 
userId` });
  }

  const query = `
    SELECT COUNT(DISTINCT sender_id) AS unreadChats
    FROM messages
    WHERE receiver_id = ? AND is_read = 0
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('DB Error (getUnreadChatsCount):', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, unreadChats: results[0].unreadChats });
  });
});

// Fetch recent chats with unread count 🔥 UPDATED
app.get('/getChatUsers', (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ success: false, message: `Missing 
userId` });
  }

  const query = `
    SELECT u.id, u.name AS username,
           (SELECT m.message FROM messages m
            WHERE (m.sender_id = u.id AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = u.id)
            ORDER BY m.timestamp DESC LIMIT 1) AS lastMessage,
           (SELECT m.timestamp FROM messages m
            WHERE (m.sender_id = u.id AND m.receiver_id = ?)
               OR (m.sender_id = ? AND m.receiver_id = u.id)
            ORDER BY m.timestamp DESC LIMIT 1) AS timestamp,
           (SELECT COUNT(*) FROM messages m
            WHERE m.sender_id = u.id AND m.receiver_id = ? AND m.is_read = 
0) AS unreadCount
    FROM users u
    WHERE u.id != ?
    HAVING lastMessage IS NOT NULL
    ORDER BY timestamp DESC;
  `;

  db.query(query, [userId, userId, userId, userId, userId, userId], (err, 
results) => {
    if (err) {
      console.error('DB Error (getChatUsers):', err);
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
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
  `;

  db.query(query, [userId, otherUserId, otherUserId, userId], (err) => {
    if (err) {
      console.error('DB Error (deleteChat):', err);
      return res.status(500).json({ success: false, message: `Database 
error` });
    }
    res.json({ success: true, message: 'Chat deleted successfully' });
  });
});

// DELETE a single message
app.delete("/deleteMessage/:messageId", (req, res) => {
    const { messageId } = req.params;

    db.query("DELETE FROM messages WHERE id = ?", [messageId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Database error" });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Message not found" });
        }
        res.json({ success: true, message: "Message deleted successfully" });
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
