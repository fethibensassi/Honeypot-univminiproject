/*********************************
 * Imports
 *********************************/
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

/*********************************
 * App Initialization
 *********************************/
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/*********************************
 * Serve Frontend Files
 *********************************/
app.use(express.static(path.join(__dirname, 'public')));

/*********************************
 * Constants
 *********************************/
const PORT = 3000;
const LOG_FILE = path.join(__dirname, 'logs', 'web.log');

/* Common sensitive paths attackers probe */
const sensitivePaths = [
  '/admin',
  '/.env',
  '/config',
  '/backup.zip',
  '/phpmyadmin',
  '/api/login',
  '/wp-admin',
  '/wp-login.php'
];

/*********************************
 * Attack Classification
 *********************************/
function classifyAttack(req) {
  const payload = JSON.stringify(req.body || {}) + req.originalUrl;

  if (/('|--|;|\bOR\b|\bAND\b)/i.test(payload)) return 'SQL Injection';
  if (/<script>|onerror=|onload=/i.test(payload)) return 'XSS';
  if (/(\.\.\/|%2e%2e%2f)/i.test(payload)) return 'Directory Traversal';
  if (req.method === 'POST') return 'Credential Brute Force';

  return 'Reconnaissance';
}

/*********************************
 * Utilities
 *********************************/
function generateFakeToken() {
  return crypto.randomBytes(24).toString('hex');
}

function logAttack(req, attackType) {
  const logEntry = {
    service: 'web',
    time: new Date().toISOString(),
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    method: req.method,
    url: req.originalUrl,
    body: req.body,
    attack_type: attackType
  };

  fs.appendFileSync(LOG_FILE, JSON.stringify(logEntry) + '\n');
}

/*********************************
 * Frontend Route
 *********************************/
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/*********************************
 * Login Endpoint (INTENTIONALLY WEAK)
 *********************************/
app.post('/login', (req, res) => {
  const attackType = classifyAttack(req);
  logAttack(req, attackType);

  const { username, password } = req.body;

  // Deliberately weak credentials (honeypot)
  if (username === 'admin' && password === 'admin123') {
    return res.redirect('/dashboard.html');
  }

  setTimeout(() => {
    res.status(401).send('Invalid credentials');
  }, 800);
});

/*********************************
 * Central Honeypot Handler
 *********************************/
function handleRequest(req, res) {
  const attackType = classifyAttack(req);
  logAttack(req, attackType);

  setTimeout(() => {
    if (sensitivePaths.includes(req.path)) {
      return res.status(200).send('<h3>Access denied</h3>');
    }

    return res.status(401).send('Unauthorized');
  }, 1200);
}

/*********************************
 * Honeypot Routes
 *********************************/

/* Explicit sensitive endpoints */
sensitivePaths.forEach(p => {
  app.all(p, handleRequest);
});

/* Catch-all route (recon & scanners) */
app.use(handleRequest);

/*********************************
 * Server Startup
 *********************************/
app.listen(PORT, () => {
  console.log(`🕷 Web honeypot listening on port ${PORT}`);
});

