import bcrypt from 'bcryptjs';

const hashPassword = async (password) => {
  try {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  } catch (err) {
    console.error('Error hashing password:', err); // Log any errors
    throw err;
  }
};

export default hashPassword;
