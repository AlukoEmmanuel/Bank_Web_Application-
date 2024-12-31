// Import dependencies
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { Client } = require('pg');

dotenv.config();
const app = express();
app.use(express.json());

// PostgreSQL client setup
const client = new Client({
  connectionString: process.env.DATABASE_URL,
});
client.connect();

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Register route (create user)
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  
  try {
    // Hash password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await client.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );
    
    res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

// Login route (authenticate user)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Middleware to verify JWT token and extract userId
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.userId = user.userId;
    next();
  });
};

// Create an account for the user
app.post('/create-account', authenticateToken, async (req, res) => {
  const userId = req.userId;
  const accountNumber = `ACC${Math.floor(Math.random() * 1000000000)}`; // Generate random account number
  
  try {
    const result = await client.query(
      'INSERT INTO accounts (user_id, account_number) VALUES ($1, $2) RETURNING *',
      [userId, accountNumber]
    );
    
    res.status(201).json({ message: 'Account created successfully', account: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: 'Error creating account', error: err.message });
  }
});

// Get account details
app.get('/account', authenticateToken, async (req, res) => {
  const userId = req.userId;

  try {
    const result = await client.query('SELECT * FROM accounts WHERE user_id = $1', [userId]);
    if (result.rows.length > 0) {
      res.json({ account: result.rows[0] });
    } else {
      res.status(404).json({ message: 'Account not found' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Error fetching account details', error: err.message });
  }
});

// Money transfer between accounts
app.post('/transfer', authenticateToken, async (req, res) => {
  const { fromAccount, toAccount, amount } = req.body;
  const userId = req.userId;

  try {
    const fromAccountResult = await client.query(
      'SELECT * FROM accounts WHERE account_number = $1 AND user_id = $2',
      [fromAccount, userId]
    );
    if (!fromAccountResult.rows.length) {
      return res.status(400).json({ message: 'Invalid source account' });
    }

    const fromAccountBalance = fromAccountResult.rows[0].balance;
    if (fromAccountBalance < amount) {
      return res.status(400).json({ message: 'Insufficient funds' });
    }

    const toAccountResult = await client.query(
      'SELECT * FROM accounts WHERE account_number = $1',
      [toAccount]
    );
    if (!toAccountResult.rows.length) {
      return res.status(400).json({ message: 'Invalid destination account' });
    }

    // Perform the transfer
    await client.query('BEGIN');
    await client.query('UPDATE accounts SET balance = balance - $1 WHERE account_number = $2', [amount, fromAccount]);
    await client.query('UPDATE accounts SET balance = balance + $1 WHERE account_number = $2', [amount, toAccount]);
    await client.query('COMMIT');

    res.json({ message: 'Transfer successful' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ message: 'Error processing transfer', error: err.message });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
