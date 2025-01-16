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

// Database connection using DATABASE_URL
const pool = new Pool({
    user: process.env.PG_USER,           // Username from .env
    host: process.env.PG_HOST || 'db',   // Host is 'db' for Docker Compose
    database: process.env.PG_DATABASE,   // Database name from .env
    password: process.env.PG_PASSWORD,   // Password from .env
    port: process.env.PG_PORT || 5432,   // Default port for PostgreSQL
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, // SSL setting for production
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
    console.log(username, first_name, last_name, user_password);
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

// Check if the username exists
app.post('/check-username', async (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    return res.json({ exists: result.rows.length > 0 });
  } catch (error) {
    console.error('Error checking username:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check username and password match
app.post('/check-username-password', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const passwordMatch = await bcrypt.compare(password, user.user_password);

      return res.json({ valid: passwordMatch });
    } else {
      return res.json({ valid: false });
    }
  } catch (error) {
    console.error('Error checking username and password:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save a password for the user
app.post('/save-password', async (req, res) => {
  const { title, password } = req.body;
  const username = req.headers['username'];

  if (!title || !password || !username) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    await pool.query(
      `UPDATE users 
      SET saved_passwords = array_append(saved_passwords, ROW($1, $2)::password_entry) 
      WHERE username = $3`,
      [title, password, username]
    );

    return res.status(200).json({ message: 'Password saved successfully' });
  } catch (error) {
    console.error('Error saving password:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get saved passwords for the user
app.post('/get-saved-passwords', async (req, res) => {
  const username = req.headers['username'];

  try {
    const result = await pool.query('SELECT saved_passwords FROM users WHERE username = $1', [username]);

    if (result.rows.length > 0) {
      res.json(result.rows[0].saved_passwords);
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Error fetching saved passwords:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start the server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
