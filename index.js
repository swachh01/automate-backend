const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Local MySQL (on Mac)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'swaraj2004', // Use your local MySQL password
  database: 'automatedb'
});

// 📌 Test DB connection
db.connect((err) => {
  if (err) {
    console.error('❌ Failed to connect to MySQL:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Connected to MySQL database');
  }
});

// 🔐 Signup
app.post('/signup', (req, res) => {
  const { name, college, password } = req.body;
  if (!name || !college || !password) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  const query = `INSERT INTO users (name, college, password) VALUES (?, ?, ?)`;
  db.query(query, [name, college, password], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ success: false, message: 'DB Error' });
    }
    return res.json({ success: true, message: 'User created' });
  });
});

// 🔐 Login
app.post('/login', (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) {
    return res.status(400).json({ success: false, message: 'Missing credentials' });
  }

  const query = 'SELECT * FROM users WHERE name = ? AND password = ?';
  db.query(query, [name, password], (err, results) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length > 0) {
      const user = results[0];
      res.json({ success: true, message: 'Login successful', userId: user.id, name: user.name });
    } else {
      res.json({ success: false, message: 'Invalid username or password' });
    }
  });
});

// ✏️ Add or Update Travel Plan
app.post('/addTravelPlan', (req, res) => {
  const { userId, destination, time } = req.body;
  if (!userId || !destination || !time) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  // Check if the user already has a travel plan
  const checkQuery = `SELECT * FROM travel_plans WHERE user_id = ?`;
  db.query(checkQuery, [userId], (err, results) => {
    if (err) {
      console.error('Check error:', err);
      return res.status(500).json({ success: false, message: 'DB error' });
    }

    if (results.length > 0) {
      // Update existing
      const updateQuery = `UPDATE travel_plans SET destination = ?, time = ? WHERE user_id = ?`;
      db.query(updateQuery, [destination, time, userId], (err) => {
        if (err) {
          console.error('Update error:', err);
          return res.status(500).json({ success: false, message: 'Update failed' });
        }
        res.json({ success: true, message: 'Travel plan updated' });
      });
    } else {
      // Insert new
      const insertQuery = `INSERT INTO travel_plans (user_id, destination, time) VALUES (?, ?, ?)`;
      db.query(insertQuery, [userId, destination, time], (err) => {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ success: false, message: 'Insert failed' });
        }
        res.json({ success: true, message: 'Travel plan added' });
      });
    }
  });
});

// 👤 Get Current User's Travel Plan
app.get('/getUserTravelPlan', (req, res) => {
  const userId = req.query.userId;
  if (!userId) return res.status(400).json({ success: false, message: 'Missing userId' });

  const query = `SELECT destination, time FROM travel_plans WHERE user_id = ?`;
  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Fetch error:', err);
      return res.status(500).json({ success: false, message: 'DB error' });
    }
    if (results.length === 0) {
      return res.json(null); // No travel plan yet
    }
    res.json(results[0]);
  });
});

// 🧹 Get Travel Plans (Recent only)
app.get('/getTravelPlans', (req, res) => {
  const deleteQuery = `
      DELETE FROM travel_plans
      WHERE time < DATE_SUB(NOW(), INTERVAL 3 HOUR)
  `;
  db.query(deleteQuery, (deleteErr) => {
    if (deleteErr) {
      console.error('Delete Error:', deleteErr);
      return res.status(500).json({ success: false, message: 'Cleanup failed' });
    }

const fetchQuery = `
  SELECT users.name AS username, travel_plans.destination,
         CONVERT_TZ(travel_plans.time, '+00:00', '+05:30') AS time
  FROM travel_plans
  INNER JOIN users ON travel_plans.user_id = users.id
  ORDER BY travel_plans.time DESC
`;


    db.query(fetchQuery, (fetchErr, results) => {
      if (fetchErr) {
        console.error('Fetch Error:', fetchErr);
        return res.status(500).json({ success: false, message: 'DB error' });
      }
      res.json({ success: true, users: results });
    });
  });
});

// 🟢 Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// 🔄 Default root
app.get('/', (req, res) => {
  res.send('✅ Backend is working!');
});

// 🌐 Start local server on 3000
const port =process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on ${PORT}`);
});

