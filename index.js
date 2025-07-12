const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ MySQL connection pool
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT,
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

// 🔐 Signup
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

// 🔐 Login
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

// ✏️ Add or Update Travel Plan
app.post('/addTravelPlan', (req, res) => {
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }

  const checkQuery = `SELECT * FROM travel_plans WHERE user_id = ?`;
  db.query(checkQuery, [userId], (err, results) => {
    if (err) {
      console.error('Check error:', err);
      return res.status(500).json({ success: false, message: 'DB error' 
});
    }

    if (results.length > 0) {
      const updateQuery = `UPDATE travel_plans SET destination = ?, time = 
? WHERE user_id = ?`;
      db.query(updateQuery, [destination, time, userId], (err) => {
        if (err) {
          console.error('Update error:', err);
          return res.status(500).json({ success: false, message: `Update 
failed` });
        }
        res.json({ success: true, message: 'Travel plan updated' });
      });
    } else {
      const insertQuery = `INSERT INTO travel_plans (user_id, destination, 
time) VALUES (?, ?, ?)`;
      db.query(insertQuery, [userId, destination, time], (err) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ success: false, message: `Insert 
failed` });
        }
        res.json({ success: true, message: 'Travel plan added' });
      });
    }
  });
});

// 👤 Get Current User's Travel Plan
app.get('/getUserTravelPlan', (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ success: false, message: 
'Missing userId' });

  const query = `SELECT destination, time FROM travel_plans WHERE user_id 
= ?`;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Fetch error:', err);
      return res.status(500).json({ success: false, message: 'DB error' 
});
    }
    if (results.length === 0) {
      return res.json(null);
    }
    res.json(results[0]);
  });
});

// 👀 Get All Valid Travel Plans (🧹 Delete if time < NOW)
app.get('/getTravelPlans', (req, res) => {
  const deleteQuery = `
    DELETE FROM travel_plans
    WHERE time < NOW()
  `;
  db.query(deleteQuery, (deleteErr) => {
    if (deleteErr) {
      console.error('Delete Error:', deleteErr);
      return res.status(500).json({ success: false, message: `Cleanup 
failed` });
    }

    const fetchQuery = `
      SELECT users.name AS username, users.id AS userId, users.college AS 
college,
             travel_plans.destination, travel_plans.time AS time
      FROM travel_plans
      INNER JOIN users ON travel_plans.user_id = users.id
      ORDER BY travel_plans.time DESC
    `;

    db.query(fetchQuery, (fetchErr, results) => {
      if (fetchErr) {
        console.error('Fetch Error:', fetchErr);
        return res.status(500).json({ success: false, message: 'DB error' 
});
      }
      res.json({ success: true, users: results });
    });
  });
});

// ✉️ Send a message
app.post('/sendMessage', (req, res) => {
  const { senderId, receiverId, message } = req.body;
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ success: false, message: `Missing 
fields` });
  }

  const insertQuery = `INSERT INTO messages (sender_id, receiver_id, 
message) VALUES (?, ?, ?)`;
  db.query(insertQuery, [senderId, receiverId, message], (err) => {
    if (err) {
      console.error('Send Message Error:', err);
      return res.status(500).json({ success: false, message: `Message send 
failed` });
    }
    res.json({ success: true, message: 'Message sent' });
  });
});

// 📥 Get messages between two users
app.get('/getMessages', (req, res) => {
  const { senderId, receiverId } = req.query;
  if (!senderId || !receiverId) {
    return res.status(400).json({ success: false, message: `Missing query 
parameters` });
  }

  const fetchQuery = `
    SELECT * FROM messages
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
    ORDER BY timestamp ASC
  `;
  db.query(fetchQuery, [senderId, receiverId, receiverId, senderId], (err, 
results) => {
    if (err) {
      console.error('Fetch Messages Error:', err);
      return res.status(500).json({ success: false, message: `Fetch 
failed` });
    }
    res.json({ success: true, messages: results });
  });
});

// 👥 Get list of chat users for a user
app.get('/getChatList', (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ success: false, message: `Missing 
userId` });
  }

  const query = `
    SELECT u.id, u.name, u.college
    FROM users u
    WHERE u.id IN (
      SELECT DISTINCT CASE
        WHEN sender_id = ? THEN receiver_id
        WHEN receiver_id = ? THEN sender_id
      END
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?
    )
  `;

  db.query(query, [userId, userId, userId, userId], (err, results) => {
    if (err) {
      console.error('Chat List Error:', err);
      return res.status(500).json({ success: false, message: `Chat list 
fetch failed` });
    }
    res.json({ success: true, users: results });
  });
});

// ✅ Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// 🔄 Root route
app.get('/', (req, res) => {
  res.send('✅ Backend is working!');
});

// 🚀 Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on ${PORT}`);
});

