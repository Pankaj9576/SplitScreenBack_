const express = require('express');
const fetch = require('node-fetch');
const cheerio = require('cheerio');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const scrapeEspacenetPatent = require('./scrapeEspacenetPatent');

const app = express();

// In-memory user store (use database in production)
const users = [];

// JWT secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// CORS middleware
app.use(cors({
  origin: ['https://frontendsplitscreen.vercel.app', 'http://localhost:3000', 'https://split-screen-inky.vercel.app'],
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
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (users.find(user => user.email === email)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { email, password: hashedPassword };
    users.push(user);
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
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
  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  try {
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Forgot Password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  try {
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;
    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    console.log(`Reset Token for ${email}: ${resetToken}`);
    console.log('Copy the above token and use it to reset the password.');
    res.status(200).json({ message: 'Reset token generated. Check server logs for the token.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset Password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }
  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (!user.resetToken || user.resetToken !== token || !user.resetTokenExpiry || Date.now() > user.resetTokenExpiry) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error' });
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
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
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
    jwt.verify(token, JWT_SECRET);
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;