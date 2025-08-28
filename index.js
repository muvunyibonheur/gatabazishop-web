const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'pssms',
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL');
});

// --- AUTH ---
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hash],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ message: 'User registered successfully.' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });
    req.session.user = { id: user.id, username: user.username };
    res.json({ message: 'Logged in successfully.' });
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out successfully.' });
});

function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized access.' });
}

// --- CRUD: parkingslot ---
app.get('/parkingslot', isAuthenticated, (req, res) => {
  db.query('SELECT * FROM parkingslot', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    res.json(results);
  });
});

app.post('/parkingslot', isAuthenticated, (req, res) => {
  const { slotnumber, slotstatus } = req.body;
  if (!slotnumber || !slotstatus) {
    return res.status(400).json({ error: 'Slot number and status are required.' });
  }
  db.query(
    'INSERT INTO parkingslot (slotnumber, slotstatus) VALUES (?, ?)',
    [slotnumber, slotstatus],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ message: 'Parking slot added successfully.' });
    }
  );
});

// --- CRUD: car ---
app.get('/cars', isAuthenticated, (req, res) => {
  db.query('SELECT * FROM car', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    res.json(results);
  });
});

app.post('/cars', isAuthenticated, (req, res) => {
  const { platenumber, drivername, phonenumber } = req.body;
  if (!platenumber || !drivername || !phonenumber) {
    return res.status(400).json({ error: 'Plate number, driver name, and phone number are required.' });
  }
  db.query(
    'INSERT INTO car (platenumber, drivername, phonenumber) VALUES (?, ?, ?)',
    [platenumber, drivername, phonenumber],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ message: 'Car added successfully.' });
    }
  );
});

// --- CRUD: parkingrecord ---
app.get('/parkingrecords', isAuthenticated, (req, res) => {
  db.query('SELECT * FROM parkingrecord', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    res.json(results);
  });
});

app.post('/parkingrecords', isAuthenticated, (req, res) => {
  const { EntryTime, ExitTime, Duration } = req.body;
  if (!EntryTime || !ExitTime || !Duration) {
    return res.status(400).json({ error: 'Entry time, exit time, and duration are required.' });
  }
  db.query(
    'INSERT INTO parkingrecord (EntryTime, ExitTime, Duration) VALUES (?, ?, ?)',
    [EntryTime, ExitTime, Duration],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ message: 'Parking record added successfully.' });
    }
  );
});

// --- CRUD: payment ---
app.get('/payments', isAuthenticated, (req, res) => {
  db.query('SELECT * FROM payment', (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error.' });
    res.json(results);
  });
});

app.post('/payments', isAuthenticated, (req, res) => {
  const { amountpaid, paymentdate } = req.body;
  if (!amountpaid || !paymentdate) {
    return res.status(400).json({ error: 'Amount paid and payment date are required.' });
  }
  db.query(
    'INSERT INTO payment (amountpaid, paymentdate) VALUES (?, ?)',
    [amountpaid, paymentdate],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error.' });
      res.json({ message: 'Payment added successfully.' });
    }
  );
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});