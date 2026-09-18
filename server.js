const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_upvc_saas_2026';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/upvc_billing_saas';

// MongoDB Database Connection
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB Cloud Database'))
  .catch(err => console.error('❌ DB Connection Error:', err));

// --- Schemas ---

// 1. User Schema (With Trial & Subscription Expiry)
const userSchema = new mongoose.Schema({
  shopName: { type: String, required: true },
  ownerName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subscription: {
    plan: { type: String, enum: ['FREE_TRIAL', 'MONTHLY', 'YEARLY'], default: 'FREE_TRIAL' },
    status: { type: String, enum: ['ACTIVE', 'EXPIRED'], default: 'ACTIVE' },
    validUntil: { type: Date, default: () => new Date(+new Date() + 7*24*60*60*1000) } // 7-day Free Trial
  }
});

const User = mongoose.model('User', userSchema);

// 2. Invoice Schema
const invoiceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  invoiceNo: { type: String, required: true },
  clientName: { type: String, required: true },
  items: Array,
  grandTotal: Number,
  paidAmount: Number,
  dueAmount: Number,
  date: { type: Date, default: Date.now }
});

const Invoice = mongoose.model('Invoice', invoiceSchema);

// --- Middleware: Verify User & Subscription Expiry ---
const verifyUserAndLicense = async (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

  try {
    const verified = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    const user = await User.findById(verified.id);
    if (!user) return res.status(404).json({ message: 'User Not Found' });

    // Check License Expiry
    if (new Date() > new Date(user.subscription.validUntil)) {
      user.subscription.status = 'EXPIRED';
      await user.save();
      return res.status(403).json({ 
        message: 'Your Subscription Has Expired! Please renew your plan to continue.',
        expired: true 
      });
    }

    req.user = user;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid Token' });
  }
};

// --- API Routes ---

// Registration API
app.post('/api/auth/register', async (req, res) => {
  try {
    const { shopName, ownerName, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already registered!' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ shopName, ownerName, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Account created with 7-day Free Trial!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login API
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid Email or Password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid Email or Password' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: {
        id: user._id,
        shopName: user.shopName,
        ownerName: user.ownerName,
        validUntil: user.subscription.validUntil,
        status: user.subscription.status
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save Invoice to Cloud API
app.post('/api/invoices', verifyUserAndLicense, async (req, res) => {
  try {
    const { invoiceNo, clientName, items, grandTotal, paidAmount, dueAmount } = req.body;
    const invoice = new Invoice({
      userId: req.user._id,
      invoiceNo,
      clientName,
      items,
      grandTotal,
      paidAmount,
      dueAmount
    });
    await invoice.save();
    res.json({ message: 'Invoice saved to Cloud Database successfully!', invoice });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get User Invoices API
app.get('/api/invoices', verifyUserAndLicense, async (req, res) => {
  try {
    const invoices = await Invoice.find({ userId: req.user._id }).sort({ date: -1 });
    res.json(invoices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 SaaS Server running on port ${PORT}`));