const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Signup function
const signup = async (req, res, users) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Check if user already exists
  if (users.find(user => user.email === email)) {
    return res.status(400).json({ error: 'User already exists' });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { email, password: hashedPassword };
    users.push(user);

    // Generate JWT
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Login function
const login = async (req, res, users) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  try {
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Forgot Password function
const forgotPassword = async (req, res, users) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry

    // Store reset token and expiry in user object
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;

    // Log the reset token (in production, send this via email)
    console.log(`Reset Token for ${email}: ${resetToken}`);
    console.log('Copy the above token and use it to reset the password.');

    res.status(200).json({ message: 'Reset token generated. Check server logs for the token.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Reset Password function
const resetPassword = async (req, res, users) => {
  const { email, token, newPassword } = req.body;

  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (
    !user.resetToken ||
    user.resetToken !== token ||
    !user.resetTokenExpiry ||
    Date.now() > user.resetTokenExpiry
  ) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  try {
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    // Clear reset token and expiry
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Google login function
const googleLogin = async (req, res, users) => {
  const { email, googleId } = req.body;

  if (!email || !googleId) {
    return res.status(400).json({ error: 'Email and Google ID are required' });
  }

  let user = users.find(user => user.email === email);
  if (!user) {
    // Create new user for Google login
    user = { email, googleId };
    users.push(user);
  } else if (user.googleId !== googleId) {
    return res.status(401).json({ error: 'Invalid Google account' });
  }

  try {
    // Generate JWT
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (err) {
    console.error('Google login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Token verification function
const verifyToken = (req, res) => {
  const token = req.headers.authorization?.split('Bearer ')[1];

  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token provided' });
  }

  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ valid: true });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
};

module.exports = {
  signup,
  login,
  forgotPassword,
  resetPassword,
  googleLogin,
  verifyToken
};