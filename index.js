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

// Test DB connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Failed to connect to MySQL:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Connected to MySQL database');
    connection.release();
  }
});

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

// Add or Update Travel Plan (store in UTC)
// Add or Update Travel Plan (convert IST to UTC before storing)
app.post('/addTravelPlan', (req, res) => {
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) {
    return res.status(400).json({ success: false, message: `Missing fields` });
  }

  const checkQuery = `SELECT * FROM travel_plans WHERE user_id = ?`;
  db.query(checkQuery, [userId], (err, results) => {
    if (err) {
      console.error('Check error:', err);
      return res.status(500).json({ success: false, message: 'DB error' });
    }

    if (results.length > 0) {
      const updateQuery = `
        UPDATE travel_plans 
        SET destination = ?, time = CONVERT_TZ(?, '+05:30', '+00:00') 
        WHERE user_id = ?
      `;
      db.query(updateQuery, [destination, time, userId], (err) => {
        if (err) {
          console.error('Update error:', err);
          return res.status(500).json({ success: false, message: `Update failed` });
        }
        res.json({ success: true, message: 'Travel plan updated' });
      });
    } else {
      const insertQuery = `
        INSERT INTO travel_plans (user_id, destination, time) 
        VALUES (?, ?, CONVERT_TZ(?, '+05:30', '+00:00'))
      `;
      db.query(insertQuery, [userId, destination, time], (err) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ success: false, message: `Insert failed` });
        }
        res.json({ success: true, message: 'Travel plan added' });
      });
    }
  });
});

// Get Current User's Travel Plan (always return IST)
app.get('/getUserTravelPlan', (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ success: false, message: 'Missing userId' });

  const query = `
    SELECT destination, 
           DATE_FORMAT(CONVERT_TZ(time, '+00:00', '+05:30'), '%Y-%m-%d %H:%i:%s') AS time
    FROM travel_plans
    WHERE user_id = ?
  `;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Fetch error:', err);
      return res.status(500).json({ success: false, message: 'DB error' });
    }
    if (results.length === 0) {
      return res.json(null);
    }
    res.json(results[0]);
  });
});

// Delete expired travel plans and fetch valid ones (IST only)
app.get('/getTravelPlans', (req, res) => {
  const deleteQuery = `
    DELETE FROM travel_plans
    WHERE CONVERT_TZ(time, '+00:00', '+05:30') < NOW()
  `;

  db.query(deleteQuery, (deleteErr) => {
    if (deleteErr) {
      console.error('Delete Error:', deleteErr);
      return res.status(500).json({ success: false, message: `Delete failed` });
    }

    const fetchQuery = `
      SELECT
        users.id AS userId,
        users.name AS username,
        users.college AS college,
        travel_plans.destination,
        DATE_FORMAT(CONVERT_TZ(travel_plans.time, '+00:00', '+05:30'), '%d/%m/%Y %H:%i') AS time
      FROM travel_plans
      INNER JOIN users ON travel_plans.user_id = users.id
      WHERE CONVERT_TZ(travel_plans.time, '+00:00', '+05:30') >= NOW()
      ORDER BY travel_plans.time ASC
    `;

    db.query(fetchQuery, (fetchErr, results) => {
      if (fetchErr) {
        console.error('Fetch Error:', fetchErr);
        return res.status(500).json({ success: false, message: `Fetch failed` });
      }
      res.json({ success: true, users: results });
    });
  });
});


// Health check
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

