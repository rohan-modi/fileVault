const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(bodyParser.json());
app.use(cors());

const pool = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});

// Serve static files from the "frontend" directory
app.use(express.static(path.join(__dirname, '../frontend')));

// Handle all other routes by serving the frontend's index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Handle user account creation
app.post('/create-account', async (req, res) => {
  const { username, first_name, last_name, user_password } = req.body;

  if (!first_name || !last_name || !username || !user_password) {
    console.log(username);
    console.log(first_name);
    console.log(last_name);
    console.log(user_password);
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(user_password, 10);
    const insertResult = await pool.query(
      'INSERT INTO Users (username, first_name, last_name, user_password) VALUES ($1, $2, $3, $4) RETURNING id, username',
      [username, first_name, last_name, hashedPassword]
    );

    return res.status(201).json({
      message: 'Account created successfully!',
      user: insertResult.rows[0],
    });
  } catch (error) {
    console.error('Error creating account:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Add this route to check if the username exists
app.post('/check-username', async (req, res) => {
    const { username } = req.body;  // Get the username from the request body

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length > 0) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    } catch (error) {
        console.error('Error checking username:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add this route to check if the username and password match
app.post('/check-username-password', async (req, res) => {
    const { username, password } = req.body;  // Get the username and password from the request body

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];

            // Compare the provided password with the stored hashed password
            const passwordMatch = await bcrypt.compare(password, user.user_password);

            if (passwordMatch) {
                return res.json({ valid: true });
            } else {
                return res.json({ valid: false });
            }
        } else {
            return res.json({ valid: false });
        }
    } catch (error) {
        console.error('Error checking username and password:', error);
        res.status(500).json({ error: 'Server error' });
    }
});


// Start the server
app.listen(5001, () => {
  console.log('Server is running on http://localhost:5001');
});
