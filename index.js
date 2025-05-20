// Entry point for the Secrets authentication project
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const path = require('path');

const app = express();

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: {
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Import User model
const User = require('./models/User');

// Home page
app.get('/', (req, res) => {
  res.render('index');
});

// Registration page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Registration handler
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  // Email format check
  if (!validator.isEmail(email)) {
    return res.render('register', { error: 'Invalid email format.' });
  }
  // Password format check
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  if (!passwordRegex.test(password)) {
    return res.render('register', { error: 'Password must be at least 6 characters, include uppercase, lowercase, and a number.' });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render('register', { error: 'Email already registered.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.redirect('/login');
  } catch (err) {
    res.render('register', { error: 'Registration failed. Try again.' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login handler
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!validator.isEmail(email)) {
    return res.render('login', { error: 'Invalid email format.' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'Invalid email or password.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render('login', { error: 'Invalid email or password.' });
    }
    // JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    req.session.userId = user._id;
    req.session.token = token;
    res.redirect('/secrets');
  } catch (err) {
    res.render('login', { error: 'Login failed. Try again.' });
  }
});

// Middleware to protect routes
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Protected secrets page
app.get('/secrets', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId);
  res.render('secrets', { user });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
