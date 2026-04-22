const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = 8080;

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'blacksauce-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));
app.use('/static', express.static(path.join(__dirname, 'static')));

// Data structures
let users = {};
let activities = [];
let codeRuns = [];
let userIdCounter = 1;
let activityIdCounter = 1;
let codeRunIdCounter = 1;

// Initialize admin user
users['admin'] = {
  id: 1,
  username: 'admin',
  hash: hashPassword('admin123'),
  isAdmin: true,
  createdAt: new Date()
};

// Utility functions
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateSessionId() {
  return crypto.randomBytes(32).toHexString();
}

function logActivity(username, action, details) {
  const activity = {
    id: activityIdCounter++,
    username,
    action,
    details,
    time: new Date()
  };
  activities.push(activity);
  saveActivities();
}

function saveActivities() {
  const csvData = activities.map(a =>
    `${a.id},${a.username},${a.action},${a.details},${a.time.toISOString()}`
  ).join('\n');
  const header = 'ID,Username,Action,Details,Time\n';
  fs.writeFileSync('activities.csv', header + csvData);
}

function saveUsers() {
  const userData = Object.values(users).filter(u => u.username);
  fs.writeFileSync('users.json', JSON.stringify(userData, null, 2));
}

function loadUsers() {
  try {
    const data = fs.readFileSync('users.json', 'utf8');
    const userArray = JSON.parse(data);
    users = {};
    userArray.forEach(u => {
      users[u.username] = u;
      if (u.id >= userIdCounter) userIdCounter = u.id + 1;
    });
  } catch (err) {
    // File doesn't exist or error, use default
  }
}

function loadActivities() {
  try {
    const data = fs.readFileSync('activities.csv', 'utf8');
    const lines = data.split('\n').slice(1); // Skip header
    activities = [];
    lines.forEach(line => {
      if (line.trim()) {
        const [id, username, action, details, timeStr] = line.split(',');
        activities.push({
          id: parseInt(id),
          username,
          action,
          details,
          time: new Date(timeStr)
        });
        if (parseInt(id) >= activityIdCounter) activityIdCounter = parseInt(id) + 1;
      }
    });
  } catch (err) {
    // File doesn't exist or error
  }
}

// Load data on startup
loadUsers();
loadActivities();

// Routes
app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/dologin', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (!user || user.hash !== hashPassword(password)) {
    return res.render('login', { error: 'Invalid credentials' });
  }

  req.session.userId = username;
  logActivity(username, 'login', 'User logged in');

  if (user.isAdmin) {
    res.redirect('/admin');
  } else {
    res.redirect('/dashboard');
  }
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/doregister', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render('register', { error: 'All fields required' });
  }

  if (users[username]) {
    return res.render('register', { error: 'Username exists' });
  }

  users[username] = {
    id: userIdCounter++,
    username,
    hash: hashPassword(password),
    isAdmin: false,
    createdAt: new Date()
  };

  saveUsers();
  logActivity(username, 'register', 'New user registered');
  res.render('login', { success: 'Registered! Login now.', error: null });
});

app.get('/logout', (req, res) => {
  if (req.session.userId) {
    logActivity(req.session.userId, 'logout', 'Logged out');
  }
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.render('dashboard', { username: req.session.userId });
});

app.get('/terminal', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  logActivity(req.session.userId, 'terminal', 'Opened terminal');
  res.render('terminal', { username: req.session.userId });
});

app.post('/run', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { code } = req.body;
  const username = req.session.userId;

  logActivity(username, 'code_run', `Ran code: ${code.length} chars`);

  runJavaScript(code, (output, error) => {
    const result = {
      id: codeRunIdCounter++,
      username,
      code,
      output,
      error,
      time: new Date()
    };
    codeRuns.push(result);

    res.json({ output, error });
  });
});

function runJavaScript(code, callback) {
  // Create a temporary file
  const tempFile = path.join(require('os').tmpdir(), `code_${Date.now()}.js`);
  const fullCode = `
try {
  ${code}
} catch (error) {
  console.error(error.message);
}
`;

  fs.writeFileSync(tempFile, fullCode);

  exec(`node ${tempFile}`, { timeout: 5000 }, (err, stdout, stderr) => {
    fs.unlinkSync(tempFile);
    if (err && !stderr) {
      callback('', err.message);
    } else {
      callback(stdout, stderr);
    }
  });
}

app.post('/logact', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { action, details } = req.body;
  logActivity(req.session.userId, action, details);
  res.json({ success: true });
});

app.get('/admin', (req, res) => {
  if (!req.session.userId || !users[req.session.userId] || !users[req.session.userId].isAdmin) {
    return res.status(403).send('Forbidden');
  }
  res.render('admin', {
    userCount: Object.keys(users).length,
    activityCount: activities.length,
    codeCount: codeRuns.length
  });
});

app.get('/admin/users', (req, res) => {
  if (!req.session.userId || !users[req.session.userId] || !users[req.session.userId].isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(users);
});

app.get('/admin/activities', (req, res) => {
  if (!req.session.userId || !users[req.session.userId] || !users[req.session.userId].isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(activities);
});

app.get('/admin/codes', (req, res) => {
  if (!req.session.userId || !users[req.session.userId] || !users[req.session.userId].isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.json(codeRuns);
});

app.post('/admin/deluser', (req, res) => {
  if (!req.session.userId || !users[req.session.userId] || !users[req.session.userId].isAdmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { username } = req.body;
  if (users[username]?.isAdmin) {
    return res.json({ error: 'Cannot delete admin' });
  }

  delete users[username];
  saveUsers();
  logActivity('admin', 'delete_user', `Deleted: ${username}`);
  res.json({ success: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`BLACKSAUCE running on 0.0.0.0:${PORT}`);
});