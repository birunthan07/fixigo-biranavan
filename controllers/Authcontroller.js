// // 


// // controllers/Authcontroller.js

// import express from 'express';
// import bcrypt from 'bcryptjs';
// import jwt from 'jsonwebtoken';
// import User from '../models/User.js';
// import winston from 'winston';

// const router = express.Router();

// // Initialize winston logger
// const logger = winston.createLogger({
//   level: 'info',
//   format: winston.format.json(),
//   transports: [
//     new winston.transports.Console(),
//     new winston.transports.File({ filename: 'error.log', level: 'error' }),
//   ],
// });

// // Middleware to verify the token
// const verifyToken = (req, res, next) => {
//   const token = req.headers['authorization']?.split(' ')[1];
//   if (!token) return res.status(403).json({ error: 'No token provided' });

//   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//     if (err) return res.status(500).json({ error: 'Failed to authenticate token' });

//     req.userId = decoded.userId;
//     req.userRole = decoded.role;
//     next();
//   });
// };

// // Register route
// router.post('/register', async (req, res) => {
//   const { username, email, password, role } = req.body;

//   try {
//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ error: 'User already exists' });
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);

//     const newUser = new User({
//       username,
//       email,
//       password: hashedPassword,
//       role: role || 'user',
//     });

//     await newUser.save();

//     const token = jwt.sign({ userId: newUser._id, role: newUser.role }, process.env.JWT_SECRET, {
//       expiresIn: '1h',
//     });

//     res.status(201).json({
//       message: 'User registered successfully',
//       token,
//       user: {
//         id: newUser._id,
//         username: newUser.username,
//         email: newUser.email,
//         role: newUser.role,
//       },
//     });
//   } catch (error) {
//     logger.error('Error during registration:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Login route
// router.post('/login', async (req, res) => {
//   const { email, password } = req.body;

//   try {
//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(400).json({ error: 'Invalid credentials' });
//     }

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ error: 'Invalid credentials' });
//     }

//     const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, {
//       expiresIn: '1h',
//     });

//     res.json({
//       message: 'Login successful',
//       token,
//       user: {
//         id: user._id,
//         username: user.username,
//         email: user.email,
//         role: user.role,
//       },
//     });
//   } catch (error) {
//     logger.error('Error during login:', error);
//     res.status(500).json({ error: 'Server error' });
//   }
// });

// // Middleware to check user roles
// const verifyRole = (roles) => (req, res, next) => {
//   if (!roles.includes(req.userRole)) {
//     return res.status(403).json({ error: 'Access denied' });
//   }
//   next();
// };

// // Example protected route for admin
// router.get('/admin', verifyToken, verifyRole(['admin']), (req, res) => {
//   res.json({ message: 'Welcome, Admin!' });
// });

// // router.get('/users', verifyToken, verifyRole(['admin']), async (req, res) => {
// //   const page = parseInt(req.query.page) || 1;
// //   const limit = parseInt(req.query.limit) || 10;
// //   try {
// //     const users = await User.find().skip((page - 1) * limit).limit(limit);
// //     res.json(users);
// //   } catch (error) {
// //     res.status(500).json({ error: 'Server error' });
// //   }
// // });

// router.get('/user/dashboard', authenticateToken, (req, res) => {
//   // Simulated user data (replace with actual data from database)
//   const user = {
//     username: 'exampleUser',
//     email: 'example@example.com',
//     role: 'user'
//   };
//   res.json({ user });
// });

// export default router;


// // import express from 'express';
// // import bcrypt from 'bcryptjs';
// // import jwt from 'jsonwebtoken';
// // import User from '../models/User.js';
// // import winston from 'winston';

// // const router = express.Router();
// // const logger = winston.createLogger({
// //   level: 'info',
// //   format: winston.format.json(),
// //   transports: [
// //     new winston.transports.Console(),
// //     new winston.transports.File({ filename: 'error.log', level: 'error' }),
// //   ],
// // });

// // const verifyToken = (req, res, next) => {
// //   const token = req.headers['authorization']?.split(' ')[1];
// //   if (!token) return res.status(403).json({ error: 'No token provided' });

// //   jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
// //     if (err) return res.status(500).json({ error: 'Failed to authenticate token' });
// //     req.userId = decoded.userId;
// //     req.userRole = decoded.role;
// //     next();
// //   });
// // };

// // router.post('/register', async (req, res) => {
// //   const { username, email, password, role } = req.body;

// //   try {
// //     const existingUser = await User.findOne({ email });
// //     if (existingUser) return res.status(400).json({ error: 'User already exists' });

// //     const hashedPassword = await bcrypt.hash(password, 10);
// //     const newUser = new User({ username, email, password: hashedPassword, role: role || 'user' });

// //     await newUser.save();

// //     const token = jwt.sign({ userId: newUser._id, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
// //     res.status(201).json({ token, user: newUser });
// //   } catch (err) {
// //     logger.error(err);
// //     res.status(500).json({ error: 'Server error' });
// //   }
// // });

// // router.post('/login', async (req, res) => {
// //   const { email, password } = req.body;

// //   try {
// //     const user = await User.findOne({ email });
// //     if (!user) return res.status(400).json({ error: 'Invalid email or password' });

// //     const passwordMatch = await bcrypt.compare(password, user.password);
// //     if (!passwordMatch) return res.status(400).json({ error: 'Invalid email or password' });

// //     const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
// //     res.status(200).json({ token, user });
// //   } catch (err) {
// //     logger.error(err);
// //     res.status(500).json({ error: 'Server error' });
// //   }
// // });

// // router.get('/admin', verifyToken, async (req, res) => {
// //   if (req.userRole !== 'admin') return res.status(403).json({ error: 'Access denied' });

// //   try {
// //     const users = await User.find({}, '-password');
// //     res.json(users);
// //   } catch (err) {
// //     logger.error(err);
// //     res.status(500).json({ error: 'Server error' });
// //   }
// // });

// // router.get('/user/dashboard', verifyToken, async (req, res) => {
// //   try {
// //     const user = await User.findById(req.userId, '-password');
// //     res.json({ user });
// //   } catch (err) {
// //     logger.error(err);
// //     res.status(500).json({ error: 'Server error' });
// //   }
// // });

// // export default router;



// controllers/Authcontroller.js

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import winston from 'winston';

const router = express.Router();

// Initialize winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
  ],
});

// Middleware to verify the token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(500).json({ error: 'Failed to authenticate token' });

    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  });
};

// Register route
router.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: role || 'user',
    });

    await newUser.save();

    const token = jwt.sign({ userId: newUser._id, role: newUser.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (error) {
    logger.error('Error during registration:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error('Error during login:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to check user roles
const verifyRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.userRole)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

// Example protected route for admin
router.get('/admin', verifyToken, verifyRole(['admin']), (req, res) => {
  res.json({ message: 'Welcome, Admin!' });
});

// Example protected route for user dashboard
// Example route for user dashboard
router.get('/user/dashboard', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).exec(); // Use async/await and .exec()

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


export default router;
