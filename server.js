const express = require('express');
const cors = require('cors');
const { SESClient, SendBulkTemplatedEmailCommand, SendEmailCommand, CreateTemplateCommand, GetSendQuotaCommand } = require('@aws-sdk/client-ses');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const csv = require('csv-parse/sync');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

// ─── In-memory DB (replace with real DB like MongoDB/Supabase later) ───
const users = [];
const contacts = {};   // { userId: [...contacts] }
const campaigns = {};  // { userId: [...campaigns] }

const JWT_SECRET = process.env.JWT_SECRET || 'mailflow-secret-change-in-production';

// ─── AUTH MIDDLEWARE ───
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── CREATE SES CLIENT FROM USER CREDENTIALS ───
function getSESClient(user) {
  return new SESClient({
    region: user.awsRegion || 'us-east-1',
    credentials: {
      accessKeyId: user.awsKey,
      secretAccessKey: user.awsSecret,
    },
  });
}

// ══════════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════════

// REGISTER
app.post('/api/register', async (req, res) => {
  const { name, email, password, plan, awsKey, awsSecret, awsRegion } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now().toString(),
    name, email,
    password: hashed,
    plan: plan || 'starter',
    awsKey, awsSecret,
    awsRegion: awsRegion || 'us-east-1',
    createdAt: new Date().toISOString()
  };
  users.push(user);
  contacts[user.id] = [];
  campaigns[user.id] = [];

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name, email, plan: user.plan } });
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan } });
});

// GET PROFILE
app.get('/api/me', auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, plan: user.plan, awsRegion: user.awsRegion });
});

// UPDATE AWS CREDENTIALS
app.put('/api/me/aws', auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { awsKey, awsSecret, awsRegion } = req.body;
  if (awsKey) user.awsKey = awsKey;
  if (awsSecret) user.awsSecret = awsSecret;
  if (awsRegion) user.awsRegion = awsRegion;
  res.json({ success: true });
});

// ══════════════════════════════════════════
//  SES TEST CONNECTION
// ══════════════════════════════════════════
app.get('/api/ses/test', auth, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user?.awsKey) return res.status(400).json({ error: 'No AWS credentials configured' });

  try {
    const ses = getSESClient(user);
    const quota = await ses.send(new GetSendQuotaCommand({}));
    res.json({
      success: true,
      quota: {
        max24HourSend: quota.Max24HourSend,
        maxSendRate: quota.MaxSendRate,
        sentLast24Hours: quota.SentLast24Hours,
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ══════════════════════════════════════════
//  CONTACTS ROUTES
// ══════════════════════════════════════════

// GET ALL CONTACTS
app.get('/api/contacts', auth, (req, res) => {
  res.json(contacts[req.user.id] || []);
});

// ADD SINGLE CONTACT
app.post('/api/contacts', auth, (req, res) => {
  const { email, name, company, list } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const list_ = contacts[req.user.id];
  if (list_.find(c => c.email === email)) return res.status(400).json({ error: 'Contact already exists' });

  const contact = {
    id: Date.now().toString(),
    email, name: name || '', company: company || '',
    list: list || 'All',
    status: 'subscribed',
    createdAt: new Date().toISOString()
  };
  list_.push(contact);
  res.json(contact);
});

// IMPORT CONTACTS VIA CSV
app.post('/api/contacts/import', auth, upload.single('file'), (req, res) => {
  try {
    const fileContent = fs.readFileSync(req.file.path, 'utf8');
    const records = csv.parse(fileContent, { columns: true, skip_empty_lines: true });

    const list_ = contacts[req.user.id];
    let added = 0, skipped = 0;

    records.forEach(row => {
      const email = row.email || row.Email || row.EMAIL;
      if (!email) { skipped++; return; }
      if (list_.find(c => c.email === email)) { skipped++; return; }
      list_.push({
        id: Date.now().toString() + Math.random(),
        email,
        name: row.name || row.Name || '',
        company: row.company || row.Company || '',
        list: 'All',
        status: 'subscribed',
        createdAt: new Date().toISOString()
      });
      added++;
    });

    fs.unlinkSync(req.file.path);
    res.json({ success: true, added, skipped, total: list_.length });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// DELETE CONTACT
app.delete('/api/contacts/:id', auth, (req, res) => {
  contacts[req.user.id] = contacts[req.user.id].filter(c => c.id !== req.params.id);
  res.json({ success: true });
});

// ══════════════════════════════════════════
//  CAMPAIGNS ROUTES
// ══════════════════════════════════════════

// GET ALL CAMPAIGNS
app.get('/api/campaigns', auth, (req, res) => {
  res.json(campaigns[req.user.id] || []);
});

// CREATE & SEND CAMPAIGN
app.post('/api/campaigns/send', auth, async (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user?.awsKey) return res.status(400).json({ error: 'No AWS credentials. Please add them in Settings.' });

  const { name, fromName, fromEmail, subject, body, listFilter } = req.body;
  if (!name || !fromEmail || !subject || !body) {
    return res.status(400).json({ error: 'Missing required fields: name, fromEmail, subject, body' });
  }

  // Get recipients
  let recipients = contacts[req.user.id].filter(c => c.status === 'subscribed');
  if (listFilter && listFilter !== 'All') {
    recipients = recipients.filter(c => c.list === listFilter);
  }

  if (recipients.length === 0) {
    return res.status(400).json({ error: 'No subscribed contacts found. Please import contacts first.' });
  }

  const ses = getSESClient(user);
  const campaign = {
    id: Date.now().toString(),
    name, fromName, fromEmail, subject, body,
    status: 'sending',
    totalRecipients: recipients.length,
    sent: 0, failed: 0,
    opens: 0, clicks: 0,
    createdAt: new Date().toISOString()
  };
  campaigns[req.user.id].push(campaign);

  // Send in background
  res.json({ success: true, campaignId: campaign.id, totalRecipients: recipients.length });

  // Send emails in batches of 50
  const BATCH_SIZE = 50;
  const delay = ms => new Promise(r => setTimeout(r, ms));

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    const batch = recipients.slice(i, i + BATCH_SIZE);

    await Promise.all(batch.map(async (contact) => {
      const personalizedBody = body
        .replace(/{{name}}/g, contact.name || 'Friend')
        .replace(/{{email}}/g, contact.email)
        .replace(/{{company}}/g, contact.company || '');

      const personalizedSubject = subject
        .replace(/{{name}}/g, contact.name || 'Friend')
        .replace(/{{email}}/g, contact.email);

      try {
        await ses.send(new SendEmailCommand({
          Source: `${fromName || fromEmail} <${fromEmail}>`,
          Destination: { ToAddresses: [contact.email] },
          Message: {
            Subject: { Data: personalizedSubject },
            Body: {
              Html: { Data: `<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">${personalizedBody.replace(/\n/g, '<br>')}</body></html>` },
              Text: { Data: personalizedBody }
            }
          }
        }));
        campaign.sent++;
      } catch (err) {
        campaign.failed++;
        console.error(`Failed to send to ${contact.email}:`, err.message);
      }
    }));

    // Rate limiting — wait between batches
    if (i + BATCH_SIZE < recipients.length) {
      await delay(1000);
    }
  }

  campaign.status = campaign.failed === 0 ? 'delivered' : 'partial';
  console.log(`Campaign "${name}" done. Sent: ${campaign.sent}, Failed: ${campaign.failed}`);
});

// GET CAMPAIGN STATS
app.get('/api/campaigns/:id', auth, (req, res) => {
  const campaign = campaigns[req.user.id]?.find(c => c.id === req.params.id);
  if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
  res.json(campaign);
});

// ══════════════════════════════════════════
//  ANALYTICS
// ══════════════════════════════════════════
app.get('/api/analytics', auth, (req, res) => {
  const userCampaigns = campaigns[req.user.id] || [];
  const userContacts = contacts[req.user.id] || [];

  const totalSent = userCampaigns.reduce((sum, c) => sum + (c.sent || 0), 0);
  const totalFailed = userCampaigns.reduce((sum, c) => sum + (c.failed || 0), 0);

  res.json({
    totalCampaigns: userCampaigns.length,
    totalContacts: userContacts.length,
    subscribedContacts: userContacts.filter(c => c.status === 'subscribed').length,
    totalSent,
    totalFailed,
    deliveryRate: totalSent > 0 ? ((totalSent / (totalSent + totalFailed)) * 100).toFixed(1) : 0,
    campaigns: userCampaigns
  });
});

// ══════════════════════════════════════════
//  HEALTH CHECK
// ══════════════════════════════════════════
app.get('/api/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`✅ MailFlow backend running on port ${PORT}`));
