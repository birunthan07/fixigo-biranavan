// routes/adminRoutes.js
import express from 'express';
import { verifyToken, isAdmin } from '../middleware/authMiddleware.js';
import User from '../models/User.js';

const router = express.Router();

// Get all users (Admin only)
router.get('/admin', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password'); // Don't send the password
    res.status(200).json(users);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit a user by ID (Admin only)
router.put('/admin/edit/:id', verifyToken, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { username, email, role } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(userId, { username, email, role }, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a user by ID (Admin only)
router.delete('/admin/delete/:id', verifyToken, isAdmin, async (req, res) => {
  const userId = req.params.id;
  try {
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;
