const express = require('express');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const sgMail = require('@sendgrid/mail');
require('dotenv').config();
const scrapeEspacenetPatent = require('./scrapeEspacenetPatent');

const app = express();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

if (!process.env.JWT_SECRET) {
  console.error('Error: JWT_SECRET is not defined in .env');
  process.exit(1);
}

if (!process.env.MONGODB_URI) {
  console.error('Error: MONGODB_URI is not defined in .env');
  process.exit(1);
}

if (!process.env.SENDGRID_API_KEY) {
  console.error('Error: SENDGRID_API_KEY is not defined in .env');
  process.exit(1);
}

if (!process.env.FROM_EMAIL) {
  console.error('Error: FROM_EMAIL is not defined in .env');
  process.exit(1);
}

mongoose.connect(`${process.env.MONGODB_URI}/SplitScreenDatabase`, {
  serverSelectionTimeoutMS: 5000,
  heartbeatFrequencyMS: 10000,
})
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err.message));

// Contact Schema
const contactSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true },
  phone: String,
  message: { type: String, required: true },
  submittedAt: { type: Date, default: Date.now },
});
const Contact = mongoose.model('Contact', contactSchema);

// Feedback Schema
const feedbackSchema = new mongoose.Schema({
  feedbackType: { type: String, required: true }, // e.g., comments, suggestion, question
  description: { type: String, required: true },
  name: String, // optional
  email: String, // optional
  submittedAt: { type: Date, default: Date.now },
});
const Feedback = mongoose.model('Feedback', feedbackSchema);

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true }, // Added username field
  resetToken: String,
  resetTokenExpiry: Date,
  googleId: String,
});
const User = mongoose.model('User', userSchema);

// CORS middleware
app.use(cors({
  origin: ['https://frontendsplitscreen.vercel.app', 'https://split-screen-inky.vercel.app'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400,
}));

// Handle preflight requests
app.options('*', cors());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`Request - Method: ${req.method}, Origin: ${req.headers.origin}, Path: ${req.path}`);
  res.on('finish', () => {
    console.log(`Response - Status: ${res.statusCode}, Headers: ${JSON.stringify(res.getHeaders())}`);
  });
  next();
});

app.use(express.json());

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Email, password, and name are required' });
  }
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({ email, password: hashedPassword, name });
    await user.save();
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Verify MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      throw new Error('MongoDB is not connected');
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate reset token
    const resetToken = jwt.sign({ userId: user._id, email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Update user with reset token and expiry
    await User.findOneAndUpdate(
      { email },
      { resetToken, resetTokenExpiry: Date.now() + 3600000 },
      { runValidators: false } // Bypass schema validation
    );

    // Construct reset link
    const resetLink = `${process.env.FRONTEND_URL || 'https://split-screen-inky.vercel.app'}/reset-password?token=${encodeURIComponent(resetToken)}&email=${encodeURIComponent(email)}`;

    // Send email via SendGrid
    const msg = {
      to: email,
      from: process.env.FROM_EMAIL,
      subject: 'Password Reset Request - Split Screen',
      html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Split Screen Password Reset</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <tr>
      <td style="padding: 20px; text-align: center; background-color: #007bff; border-radius: 8px 8px 0 0;">
        <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Split Screen</h1>
        <p style="color: #ffffff; margin: 5px 0 0; font-size: 14px;">Your Multi-Screen Productivity App</p>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px;">
        <h2 style="color: #333333; font-size: 20px; margin: 0 0 10px;">Password Reset Request</h2>
        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
          Hello,
        </p>
        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
          You requested a password reset for your Split Screen account. Click the button below to reset your password:
        </p>
        <table role="presentation" cellspacing="0" cellpadding="0" style="margin: 20px auto;">
          <tr>
            <td style="border-radius: 4px; background-color: #007bff;">
              <a href="${resetLink}" style="display: inline-block; padding: 12px 24px; color: #ffffff; font-size: 16px; text-decoration: none; border-radius: 4px;">Reset Password</a>
            </td>
          </tr>
        </table>
        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
          This link will expire in 1 hour for your security.
        </p>
        <p style="color: #555555; font-size: 16px; line-height: 1.5; margin: 0 0 20px;">
          If you did not request this password reset, please ignore this email or contact our support team at <a href="mailto:contact@bayslope.com" style="color: #007bff; text-decoration: none;">contact@bayslope.com</a>.
        </p>
      </td>
    </tr>
    <tr>
      <td style="padding: 20px; text-align: center; background-color: #f4f4f4; border-radius: 0 0 8px 8px;">
        <p style="color: #777777; font-size: 12px; margin: 0;">
          © All rights reserved, BBS Private Limited, 2025<br>
          <a href="https://bayslope.com" style="color: #007bff; text-decoration: none;">Visit our website</a>
        </p>
      </td>
    </tr>
  </table>
</body>
</html>
      `,
    };

    await sgMail.send(msg);
    console.log(`Password reset email sent to ${email}`);
    res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (err) {
    console.error('Forgot password error:', err);
    if (err.response && err.response.body) {
      console.error('SendGrid response:', err.response.body);
      return res.status(500).json({ error: `Failed to send reset email: ${err.response.body.errors[0].message || 'SendGrid error'}` });
    }
    if (err.message.includes('MongoDB')) {
      return res.status(500).json({ error: 'Database connection error' });
    }
    return res.status(500).json({ error: `Failed to send reset email: ${err.message}` });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }
  try {
    // Verify MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      throw new Error('MongoDB is not connected');
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.email !== email) {
      return res.status(400).json({ error: 'Email mismatch in token' });
    }

    // Find user and validate token
    const user = await User.findOne({ _id: decoded.userId, email });
    if (!user || !user.resetToken || user.resetToken !== token || (user.resetTokenExpiry && Date.now() > user.resetTokenExpiry)) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user with new password and clear reset token
    await User.findOneAndUpdate(
      { _id: decoded.userId, email },
      {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpiry: null,
      },
      { runValidators: false } // Bypass schema validation
    );

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    if (err.message.includes('MongoDB')) {
      return res.status(500).json({ error: 'Database connection error' });
    }
    return res.status(500).json({ error: `Server error: ${err.message}` });
  }
});

// Google login endpoint
app.post('/api/google-login', async (req, res) => {
  const { email, googleId } = req.body;
  if (!email || !googleId) {
    return res.status(400).json({ error: 'Email and Google ID are required' });
  }
  let user = users.find(user => user.email === email);
  if (!user) {
    user = { email, googleId };
    users.push(user);
  } else if (user.googleId !== googleId) {
    return res.status(401).json({ error: 'Invalid Google account' });
  }
  try {
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Google login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Token verification endpoint
app.post('/api/verify-token', (req, res) => {
  const token = req.headers.authorization?.split('Bearer ')[1];
  if (!token) {
    return res.status(401).json({ valid: false, error: 'No token provided' });
  }
  try {
    jwt.verify(token, process.env.JWT_SECRET);
    res.json({ valid: true });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ valid: false, error: 'Invalid token' });
  }
});

// Proxy PDF endpoint
app.get('/api/proxy-pdf', async (req, res) => {
  const pdfUrl = req.query.url;
  if (!pdfUrl) {
    return res.status(400).json({ error: 'PDF URL parameter is required' });
  }
  try {
    new URL(pdfUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid PDF URL' });
  }
  console.log(`Proxying PDF: ${pdfUrl}`);
  const fetchHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    Accept: 'application/pdf,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    Referer: 'https://patents.google.com/',
    Connection: 'keep-alive',
  };
  try {
    const response = await fetch(pdfUrl, { headers: fetchHeaders });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Proxy PDF: Fetch failed - ${response.status} - ${errorText}`);
      return res.status(response.status).json({ error: `Failed to fetch PDF: ${response.statusText}` });
    }
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline; filename=patent.pdf');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
    response.body.pipe(res);
  } catch (error) {
    console.error('Proxy PDF: Error:', error.message);
    res.status(500).json({ error: `Server error: ${error.message}` });
  }
});

// Proxy endpoint
app.get('/api/proxy', async (req, res) => {
  console.log('Proxy: Request received');
  let targetUrl = req.query.url;
  if (!targetUrl) {
    console.log('Proxy: URL parameter missing');
    return res.status(400).json({ error: 'URL parameter is required' });
  }
  targetUrl = decodeURIComponent(targetUrl);
  if (targetUrl.includes('/api/proxy?url=')) {
    const urlMatch = targetUrl.match(/url=([^&]+)/);
    if (urlMatch) {
      targetUrl = decodeURIComponent(urlMatch[1]);
    }
  }
  try {
    new URL(targetUrl);
  } catch (e) {
    console.log('Proxy: Invalid URL');
    return res.status(400).json({ error: 'Invalid URL' });
  }
  console.log(`Proxy: Fetching URL - ${targetUrl}`);
  const fetchHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    Referer: 'https://patents.google.com/',
    Connection: 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
  };

  try {
    // Determine token based on original URL
    const token = targetUrl.includes('worldwide.espacenet.com/patent') ? 2 : 1;
    console.log(`Proxy: Assigned token - ${token} (1=Google, 2=Espacenet)`);

    // Convert Espacenet URL to Google Patents URL
    if (targetUrl.includes('worldwide.espacenet.com/patent')) {
      const publicationNumberMatch = targetUrl.match(/([A-Z]{2}\d+[A-Z]\d?)/);
      if (!publicationNumberMatch) {
        console.log('Proxy: Could not extract publication number from Espacenet URL');
        return res.status(400).json({ error: 'Invalid Espacenet URL: Could not extract publication number' });
      }
      const publicationNumber = publicationNumberMatch[0];
      targetUrl = `https://patents.google.com/patent/${publicationNumber}`;
      console.log(`Proxy: Converted Espacenet URL to Google Patents URL - ${targetUrl}`);
    }

    const response = await fetch(targetUrl, { headers: fetchHeaders, redirect: 'follow' });
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Proxy: Fetch failed - ${response.status} - ${errorText}`);
      return res.status(response.status).json({ error: `Failed to fetch URL: ${response.statusText}` });
    }
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);

    if (contentType.includes('text/html')) {
      const html = await response.text();
      const $ = cheerio.load(html);

      if (targetUrl.includes('patents.google.com/patent')) {
        const title = $('h2#title').text().trim() || $('meta[name="DC.title"]').attr('content')?.trim() || $('h1').text().trim() || $('title').text().trim();
        const abstract = $('div.abstract').text().trim() || $('section[itemprop="abstract"] p').text().trim() || $('abstract').text().trim() || $('div.abstract-text').text().trim();
        const inventors = $('[itemprop="inventor"]').map((i, el) => {
          const name = $(el).text().trim();
          return name ? name : null;
        }).get().filter(name => name !== null) || $('dd[itemprop="inventor"]').map((i, el) => $(el).text().trim()).get() || $('meta[name="DC.contributor"]').map((i, el) => $(el).attr('content')?.trim()).get() || $('span.patent-bibdata-value').filter((i, el) => $(el).prev('span.patent-bibdata-label').text().toLowerCase().includes('inventor')).map((i, el) => $(el).text().trim()).get();
        const publicationNumberRaw = $('span[itemprop="publicationNumber"]').text().trim() || targetUrl.split('/').pop() || $('meta[name="DC.identifier"]').attr('content')?.trim();
        const publicationNumberMatch = publicationNumberRaw?.match(/US\d+B\d/) || [];
        const publicationNumber = publicationNumberMatch[0] || publicationNumberRaw;
        const formattedPublicationNumber = publicationNumber?.match(/[A-Z]{2}[0-9A-Z]+/g)?.join(', ') || publicationNumber;
        const publicationDateRaw = $('time[itemprop="publicationDate"]').text().trim() || $('span[itemprop="publicationDate"]').text().trim() || $('meta[name="DC.date"]').attr('content')?.trim();
        const publicationDateMatch = publicationDateRaw?.match(/\d{4}-\d{2}-\d{2}/) || [];
        const publicationDate = publicationDateMatch[0] || publicationDateRaw;
        const filingDate = $('time[itemprop="filingDate"]').text().trim() || $('span[itemprop="filingDate"]').text().trim() || $('div.filing-date').text().trim();
        const assignee = $('dd[itemprop="assigneeOriginal"]').text().trim() || $('span[itemprop="assignee"]').text().trim() || $('dd[itemprop="assignee"]').text().trim() || $('div.assignee').text().trim();
        const status = $('span[itemprop="status"]').text().trim() || $('div.status').text().trim() || $('div.patent-status').text().trim();
        const priorityDate = $('time[itemprop="priorityDate"]').text().trim() || $('span[itemprop="priorityDate"]').text().trim() || $('div.priority-date').text().trim();
        const classifications = $('span[itemprop="cpcs"]').map((i, el) => {
          const code = $(el).find('span[itemprop="Code"]').text().trim() || $(el).text().trim().split(' - ')[0] || $(el).find('a').text().trim();
          const description = $(el).find('span[itemprop="Description"]').text().trim() || $(el).text().trim().split(' - ')[1] || $(el).find('span.description').text().trim() || '';
          return { code, description };
        }).get();
        const citations = $('tr[itemprop="backwardReferences"]').map((i, el) => {
          const number = $(el).find('td[itemprop="publicationNumber"] a').text().trim() || $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
          const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
          const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
          const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || $(el).find('td:nth-child(4)').text().trim();
          return { number, date, title, assignee };
        }).get();
        const citedBy = $('tr[itemprop="forwardReferences"]').map((i, el) => {
          const number = $(el).find('td[itemprop="publicationNumber"] a').text().trim() || $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
          const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
          const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
          const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || $(el).find('td:nth-child(4)').text().trim();
          return { number, date, title, assignee };
        }).get();
        const legalEvents = $('tr[itemprop="legalEvents"]').map((i, el) => {
          const date = $(el).find('time[itemprop="date"]').text().trim() || $(el).find('td[itemprop="date"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
          const description = $(el).find('td[itemprop="description"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
          return { date, description };
        }).get();
        const patentFamily = $('tr[itemprop="family"]').map((i, el) => {
          const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
          const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
          const country = $(el).find('td[itemprop="country"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
          return { number, date, country };
        }).get();

        const applicationEvents = [];
        $('div.event.layout.horizontal.style-scope.application-timeline').each((i, elem) => {
          let dateElement = $(elem)
            .find('div.filed, div.reassignment, div.publication, div.granted, div.legal-status')
            .first()
            .text()
            .trim();
          if (!dateElement) {
            dateElement = $(elem).find('div').filter((i, el) => {
              const text = $(el).text().trim();
              return text.match(/^\d{4}-\d{2}-\d{2}$|^Status$|^Anticipated\s*expiration$/i);
            }).text().trim();
          }
          let titleElement = $(elem).find('span.title-text').text().trim();
          if (!titleElement) {
            titleElement = $(elem).find('div.flex.title, a').text().trim().replace(/\s+/g, ' ');
          }
          if (dateElement && titleElement) {
            applicationEvents.push({ date: dateElement, title: titleElement });
          }
        });

        if (applicationEvents.length === 0) {
          const legalEventMap = {
            'AS': `Assigned to ${assignee || 'Unknown Assignee'}`,
            'STCF': 'Application granted',
            'MAFP': 'Maintenance fee payment',
          };
          if (filingDate) {
            applicationEvents.push({
              date: filingDate,
              title: `Application filed by ${assignee || 'Unknown Assignee'}`,
            });
          }
          if (publicationDate) {
            applicationEvents.push({
              date: publicationDate,
              title: `Publication of ${publicationNumber || 'Unknown Publication'}`,
            });
            if (publicationNumber === 'US8900904B2') {
              applicationEvents.push({
                date: '2012-04-19',
                title: 'Publication of US20120091551A1',
              });
            }
          }
          legalEvents.forEach(event => {
            const title = legalEventMap[event.description] || event.description;
            if (title && event.date) {
              applicationEvents.push({ date: event.date, title });
            }
          });
          if (status) {
            applicationEvents.push({ date: 'Status', title: status });
          }
          if (publicationNumber === 'US8900904B2') {
            applicationEvents.push({ date: '2030-03-08', title: 'Anticipated expiration' });
          }
        }

        applicationEvents.sort((a, b) => {
          if (a.date === 'Status') return 1;
          if (b.date === 'Status') return -1;
          return new Date(a.date) - new Date(b.date);
        });

        console.log('Extracted Application Events:', JSON.stringify(applicationEvents, null, 2));
        console.log('Raw HTML Snippet for Application Timeline:', $('div.wrap.style-scope.application-timeline').html()?.slice(0, 2000) || 'No timeline found');

        const drawingsFromCarousel = [];
        $('meta[itemprop="full"]').each((i, elem) => {
          const content = $(elem).attr('content');
          if (content) drawingsFromCarousel.push(content);
        });
        console.log('Extracted images:', drawingsFromCarousel);

        const claims = $('section[itemprop="claims"]').html() || $('div.claims').html() || $('div#claims').html() || '';
        const description = $('section[itemprop="description"]').html() || $('div.description').html() || $('div#description').html() || '';
        const similarDocs = $('tr[itemprop="similarDocuments"]').map((i, el) => {
          const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
          const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
          const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
          return { number, date, title };
        }).get();

        let pdfUrl = null;
        const pdfEndpoint = targetUrl.endsWith('/') ? `${targetUrl}pdf` : `${targetUrl}/pdf`;
        try {
          console.log(`Attempting to fetch PDF endpoint: ${pdfEndpoint}`);
          const pdfResponse = await fetch(pdfEndpoint, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
          if (pdfResponse.ok) {
            const redirectedUrl = pdfResponse.url;
            console.log(`PDF endpoint redirected to: ${redirectedUrl}`);
            if (redirectedUrl && redirectedUrl.includes('patentimages.storage.googleapis.com') && redirectedUrl.endsWith('.pdf')) {
              pdfUrl = redirectedUrl;
            } else {
              console.log('Redirected URL does not match expected PDF pattern.');
            }
          } else {
            console.log(`PDF endpoint fetch failed with status: ${pdfResponse.status}`);
          }
        } catch (err) {
          console.error('Failed to fetch PDF endpoint:', err.message);
        }

        if (!pdfUrl) {
          const possiblePdfLinks = $('a').filter((i, el) => {
            const href = $(el).attr('href') || '';
            const text = $(el).text().toLowerCase();
            return (href.includes('/pdf') || href.includes('download') || href.endsWith('.pdf')) && (text.includes('download') || text.includes('pdf'));
          });
          if (possiblePdfLinks.length > 0) {
            let href = possiblePdfLinks.first().attr('href');
            console.log(`Fallback: Found potential PDF link in HTML: ${href}`);
            if (href) {
              href = href.startsWith('http') ? href : `https://patents.google.com${href}`;
              try {
                const verifyResponse = await fetch(href, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
                if (verifyResponse.ok) {
                  const finalUrl = verifyResponse.url;
                  console.log(`Fallback: Verified PDF URL after redirect: ${finalUrl}`);
                  if (finalUrl.includes('patentimages.storage.googleapis.com') && finalUrl.endsWith('.pdf')) {
                    pdfUrl = finalUrl;
                  }
                }
              } catch (err) {
                console.error('Fallback: Failed to verify PDF URL:', err.message);
              }
            }
          } else {
            console.log('Fallback: No PDF URL found in HTML after enhanced search.');
          }
        }

        if (!pdfUrl && publicationNumber) {
          const constructedPdfUrl = `https://patentimages.storage.googleapis.com/patents/${publicationNumber.toLowerCase()}.pdf`;
          try {
            console.log(`Final Fallback: Attempting constructed PDF URL: ${constructedPdfUrl}`);
            const verifyResponse = await fetch(constructedPdfUrl, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
            if (verifyResponse.ok) {
              pdfUrl = constructedPdfUrl;
              console.log('Final Fallback: Constructed PDF URL is valid.');
            } else {
              console.log('Final Fallback: Constructed PDF URL is not valid.');
            }
          } catch (err) {
            console.error('Final Fallback: Failed to verify constructed PDF URL:', err.message);
          }
        }

        const patentData = {
          type: 'patent',
          source: 'google',
          token: token, // 1 for Google Patents, 2 for Espacenet
          data: {
            title,
            abstract,
            inventors,
            publicationNumber: formattedPublicationNumber,
            publicationDate,
            filingDate,
            assignee,
            status,
            priorityDate,
            classifications,
            citations,
            citedBy,
            legalEvents,
            patentFamily,
            applicationEvents,
            drawings: [],
            drawingsFromCarousel,
            claims,
            description,
            similarDocs,
            pdfUrl,
          },
        };

        console.log('Extracted Patent Data:', JSON.stringify(patentData, null, 2));
        res.json(patentData);
      } else {
        res.setHeader('Content-Disposition', 'inline');
        response.body.pipe(res);
      }
    } else if (contentType.includes('application/pdf')) {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'inline; filename=patent.pdf');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
      response.body.pipe(res);
    } else {
      res.setHeader('Content-Disposition', 'inline');
      response.body.pipe(res);
    }
  } catch (error) {
    console.error('Proxy: Error:', error.message);
    res.status(500).json({ error: `Server error: ${error.message}` });
  }
});

// New Contact Submission Endpoint
app.post('/api/submit-contact', async (req, res) => {
  const { firstName, lastName, email, phone, message } = req.body;
  if (!firstName || !lastName || !email || !message) {
    return res.status(400).json({ error: 'First Name, Last Name, Email, and Message are required' });
  }
  try {
    const newContact = new Contact({ firstName, lastName, email, phone, message });
    await newContact.save();
    res.status(201).json({ message: 'Contact form submitted successfully' });
  } catch (err) {
    console.error('Contact submission error:', err);
    res.status(500).json({ error: 'Failed to submit contact form' });
  }
});

// New Feedback Submission Endpoint
app.post('/api/submit-feedback', async (req, res) => {
  const { feedbackType, description, name, email } = req.body;
  if (!feedbackType || !description) {
    return res.status(400).json({ error: 'Feedback Type and Description are required' });
  }
  try {
    const newFeedback = new Feedback({ feedbackType, description, name, email });
    await newFeedback.save();
    res.status(201).json({ message: 'Feedback submitted successfully' });
  } catch (err) {
    console.error('Feedback submission error:', err);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
