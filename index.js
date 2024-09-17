// 




import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import router from './controllers/Authcontroller.js';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
// import authRoutes from './routes/authRoutes.js';  // Your auth routes
import adminRoutes from './routes/adminRoutes.js'; // Admin routes

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json());

const corsOptions = {
  origin: 'http://localhost:3000', // Adjust this to match your frontend URL
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));

// Security Headers (Adjust as necessary)
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Basic Auth Logic (Replace with real authentication and database logic)
const mockUser = {
  email: 'test@example.com',
  hashedPassword: bcrypt.hashSync('password', 10), // Hash the password for comparison
};

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  // Check if the email exists and passwords match
  if (email === mockUser.email && bcrypt.compareSync(password, mockUser.hashedPassword)) {
    // Generate a token
    const token = jwt.sign({ email }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });

    return res.json({ token, role: 'user' });
  } else {
    return res.status(401).json({ message: 'Invalid email or password' });
  }
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // Basic validation
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Username, email, and password are required' });
  }

  // Hash password and store user (Implement actual storage logic)
  const hashedPassword = bcrypt.hashSync(password, 10);
  // Store hashedPassword and email in DB (mockUser is just for demo)
  mockUser.email = email;
  mockUser.hashedPassword = hashedPassword;

  // Generate a token
  const token = jwt.sign({ email }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });

  return res.json({ token, role: 'user' });
});

const MONGODB_URL = 'mongodb+srv://biranbiranavan:biranavan05@cluster0.odif3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Successfully connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:', err));

// Routes
app.use('/', router);

app.get('/', (req, res) => {
  res.send('Welcome to the API');
});

// Use helmet to set security headers
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
