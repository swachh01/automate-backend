const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// MySQL connection
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

/* ---------------- AUTH ---------------- */
app.post('/signup', async (req, res) => {
  const { name, college, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      `INSERT INTO users (name, college, password) VALUES (?, ?, ?)`,
      [name, college, hashedPassword],
      (err, result) => {
        if (err) return res.json({ success: false, message: `Signup 
failed` });
        res.json({ success: true, userId: result.insertId });
      }
    );
  } catch (err) {
    res.json({ success: false, message: 'Error creating account' });
  }
});

app.post('/login', (req, res) => {
  const { name, password } = req.body;
  db.query('SELECT * FROM users WHERE name = ?', [name], async (err, 
results) => {
    if (err || results.length === 0) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, message: `Invalid 
credentials` });

    res.json({ success: true, userId: user.id, name: user.name, college: 
user.college });
  });
});

/* ---------------- CHATS ---------------- */
// Fetch chat list (with unread count)
app.get('/chats/:userId', (req, res) => {
  const { userId } = req.params;
  const sql = `
    SELECT u.id, u.name, u.college,
      (SELECT COUNT(*) FROM messages m 
       WHERE m.receiver_id = ? AND m.sender_id = u.id AND m.is_read = 0) 
AS unread_count
    FROM users u
    WHERE u.id IN (
      SELECT DISTINCT CASE 
        WHEN sender_id = ? THEN receiver_id 
        ELSE sender_id 
      END AS chat_user
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?
    )`;
  db.query(sql, [userId, userId, userId, userId], (err, results) => {
    if (err) return res.json({ success: false, message: `Failed to load 
chats` });
    res.json({ success: true, chats: results });
  });
});

// Fetch messages between two users
app.get('/messages/:userId/:otherUserId', (req, res) => {
  const { userId, otherUserId } = req.params;
  db.query(
    `SELECT * FROM messages 
     WHERE (sender_id = ? AND receiver_id = ?) 
        OR (sender_id = ? AND receiver_id = ?) 
     ORDER BY timestamp ASC`,
    [userId, otherUserId, otherUserId, userId],
    (err, results) => {
      if (err) return res.json({ success: false, message: `Failed to load 
messages` });

      // mark as read
      db.query(
        `UPDATE messages SET is_read = 1 WHERE sender_id = ? AND 
receiver_id = ?`,
        [otherUserId, userId]
      );

      res.json({ success: true, messages: results });
    }
  );
});

// Send message
app.post('/messages', (req, res) => {
  const { sender_id, receiver_id, content } = req.body;
  db.query(
    `INSERT INTO messages (sender_id, receiver_id, content, is_read) 
VALUES (?, ?, ?, 0)`,
    [sender_id, receiver_id, content],
    (err, result) => {
      if (err) return res.json({ success: false, message: `Failed to send 
message` });
      res.json({ success: true, messageId: result.insertId });
    }
  );
});

/* ---------------- TRAVEL PLANS ---------------- */
// Add or update travel plan
app.post('/travel_plans', (req, res) => {
  const { userId, destination, travel_time } = req.body;
  db.query(
    `INSERT INTO travel_plans (user_id, destination, travel_time) VALUES 
(?, ?, ?) ON DUPLICATE KEY UPDATE destination = VALUES(destination), 
travel_time = VALUES(travel_time)`,
    [userId, destination, travel_time],
    (err) => {
      if (err) {
        console.error(err);
        return res.json({ success: false, message: `Failed to save travel 
plan` });
      }
      res.json({ success: true, message: 'Travel plan saved' });
    }
  );
});

// Get all travel plans with user details
app.get('/travel_plans', (req, res) => {
  db.query(
    `SELECT tp.id, tp.destination, tp.travel_time, u.name, u.college
     FROM travel_plans tp
     JOIN users u ON tp.user_id = u.id`,
    (err, results) => {
      if (err) {
        console.error(err);
        return res.json({ success: false, message: `Failed to fetch travel 
plans` });
      }
      res.json({ success: true, plans: results });
    }
  );
});

/* ---------------- SERVER ---------------- */
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`);
});

