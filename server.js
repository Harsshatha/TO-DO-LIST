const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
console.log('Loaded MONGO_URI:', process.env.MONGO_URI); // Debug log

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Ensure all POST bodies are parsed

// Use local MongoDB
const mongoUri = 'mongodb://127.0.0.1:27017/smart-todo';
mongoose.connect(mongoUri)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Task schema
const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  category: { type: String, default: 'General' },
  isCompleted: { type: Boolean, default: false },
  dueDate: { type: Date },
  priority: { type: Number, min: 1, max: 5 },
  location: { type: String },
  notes: { type: String },
  tags: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date }
});
const Task = mongoose.model('Task', taskSchema);

const JWT_SECRET = 'supersecretkey'; // In production, use env var

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ error: 'Username already exists' });
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash });
    await user.save();
    res.status(201).json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '2d' });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Auth middleware
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// CRUD routes (all require auth)
app.get('/tasks', auth, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(tasks);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/tasks', auth, async (req, res) => {
  const { text, category, dueDate, priority, location, notes, tags } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });
  try {
    const task = new Task({ userId: req.userId, text, category, dueDate: dueDate ? new Date(dueDate) : undefined, priority, location, notes, tags });
    await task.save();
    res.status(201).json(task);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/tasks/:id', auth, async (req, res) => {
  try {
    const update = req.body;
    if (update.isCompleted) update.completedAt = new Date();
    const task = await Task.findOneAndUpdate({ _id: req.params.id, userId: req.userId }, update, { new: true });
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/tasks/:id', auth, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
