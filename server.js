// ═══════════════════════════════════════════════════════════════
//  ISRO ICC — Infrastructure Command Centre · Backend Server
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cron = require('node-cron');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'isro_default_secret';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '24h';
const PROM_URL = process.env.PROMETHEUS_URL || 'http://localhost:9090';
const PROM_CONFIG = process.env.PROMETHEUS_CONFIG || '';
const LOG_RETENTION = parseInt(process.env.LOG_RETENTION_DAYS) || 180;

// ─── Middleware ───
app.use(cors());
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── MySQL Pool ───
let pool;
async function initDB() {
  try {
    // First connect without DB to create it if missing
    const tmpPool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      multipleStatements: true,
    });
    const schemaSQL = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
    await tmpPool.query(schemaSQL);
    await tmpPool.end();

    // Now connect to the actual DB
    pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 3306,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'isro_icc',
      waitForConnections: true,
      connectionLimit: 20,
      queueLimit: 0,
    });
    console.log('✅ MySQL connected — database isro_icc ready');
  } catch (err) {
    console.error('⚠️  MySQL connection failed:', err.message);
    console.log('⚠️  Server will run without database. Auth & persistence disabled.');
    pool = null;
  }
}

// ─── Auth Middleware ───
function authRequired(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminRequired(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ─── Audit helper ───
async function logAudit(userId, username, action, details, ip) {
  if (!pool) return;
  try {
    await pool.execute(
      'INSERT INTO audit_log (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
      [userId, username, action, details, ip]
    );
  } catch (e) { /* silent */ }
}

// ═══════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════
app.post('/api/auth/register', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { username, email, password, fullName } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const [existing] = await pool.execute(
      'SELECT id FROM users WHERE username = ? OR email = ?', [username, email]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)',
      [username, email, hash, fullName || '', 'viewer']
    );
    await logAudit(result.insertId, username, 'USER_REGISTER', `New user registered: ${username}`, req.ip);
    res.status(201).json({ message: 'Account created successfully', userId: result.insertId });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    // Search by exact username/email
    let [rows] = await pool.execute(
      'SELECT * FROM users WHERE username = ? OR email = ?', [username, username]
    );

    // Robust bootstrap for default Administrator account so the provided
    // credentials always work, even if the DB was altered.
    if (username === 'Administrator' && password === 'Admin@1234Area51') {
      if (rows.length === 0) {
        // Create Administrator user if missing
        const hash = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
          'INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)',
          ['Administrator', 'admin@isro.gov.in', hash, 'ISRO Administrator', 'admin']
        );
        rows = [{
          id: result.insertId,
          username: 'Administrator',
          email: 'admin@isro.gov.in',
          password_hash: hash,
          full_name: 'ISRO Administrator',
          role: 'admin',
          is_active: 1,
        }];
      } else if (!(await bcrypt.compare(password, rows[0].password_hash))) {
        // Reset password & ensure admin role if hash does not match
        const hash = await bcrypt.hash(password, 10);
        await pool.execute(
          'UPDATE users SET password_hash = ?, role = "admin", is_active = TRUE WHERE id = ?',
          [hash, rows[0].id]
        );
        rows[0].password_hash = hash;
        rows[0].role = 'admin';
        rows[0].is_active = 1;
      }
    }

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role, fullName: user.full_name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );
    await pool.execute('UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]);
    await logAudit(user.id, user.username, 'USER_LOGIN', 'User logged in', req.ip);
    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role, fullName: user.full_name }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});


app.get('/api/auth/me', authRequired, async (req, res) => {
  res.json({ user: req.user });
});

// ═══════════════════════════════════════
//  USER MANAGEMENT (Admin)
// ═══════════════════════════════════════
app.get('/api/users', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, email, full_name, role, is_active, last_login, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.put('/api/users/:id/role', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { role } = req.body;
    if (!['admin', 'operator', 'viewer'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    await pool.execute('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
    await logAudit(req.user.id, req.user.username, 'USER_ROLE_CHANGE', `Changed user #${req.params.id} role to ${role}`, req.ip);
    res.json({ message: 'Role updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

// ═══════════════════════════════════════
//  PROMETHEUS PROXY
// ═══════════════════════════════════════
app.get('/api/prom/query', authRequired, async (req, res) => {
  try {
    const url = `${PROM_URL}/api/v1/query?query=${encodeURIComponent(req.query.query)}`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Prometheus unreachable', details: err.message });
  }
});

app.get('/api/prom/query_range', authRequired, async (req, res) => {
  try {
    const { query, start, end, step } = req.query;
    const url = `${PROM_URL}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: 'Prometheus unreachable', details: err.message });
  }
});

app.get('/api/prom/status', authRequired, async (req, res) => {
  try {
    const r = await fetch(`${PROM_URL}/api/v1/query?query=up`);
    const data = await r.json();
    res.json({ connected: true, targets: data.data?.result?.length || 0 });
  } catch (err) {
    res.json({ connected: false, error: err.message });
  }
});

// ═══════════════════════════════════════
//  TARGET MANAGEMENT
// ═══════════════════════════════════════

// Get all targets from DB
app.get('/api/targets', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [rows] = await pool.execute('SELECT * FROM targets ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch targets' });
  }
});

// Add a new target
app.post('/api/targets', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { host, port, jobName, osType, displayName, labels } = req.body;
    if (!host || !port) {
      return res.status(400).json({ error: 'Host and port are required' });
    }
    const [existing] = await pool.execute(
      'SELECT id FROM targets WHERE host = ? AND port = ?', [host, parseInt(port)]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Target already exists' });
    }
    const [result] = await pool.execute(
      'INSERT INTO targets (host, port, job_name, os_type, display_name, labels, added_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [host, parseInt(port), jobName || 'node_exporter', osType || 'linux', displayName || '', JSON.stringify(labels || {}), req.user.id]
    );
    await logAudit(req.user.id, req.user.username, 'TARGET_ADD', `Added target ${host}:${port}`, req.ip);

    // Sync to prometheus.yml
    await syncPrometheusConfig();

    res.status(201).json({ message: 'Target added and Prometheus config updated', targetId: result.insertId });
  } catch (err) {
    console.error('Add target error:', err);
    res.status(500).json({ error: 'Failed to add target' });
  }
});

// Delete a target
app.delete('/api/targets/:id', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [target] = await pool.execute('SELECT * FROM targets WHERE id = ?', [req.params.id]);
    if (target.length === 0) return res.status(404).json({ error: 'Target not found' });
    await pool.execute('DELETE FROM targets WHERE id = ?', [req.params.id]);
    await logAudit(req.user.id, req.user.username, 'TARGET_DELETE', `Deleted target ${target[0].host}:${target[0].port}`, req.ip);
    await syncPrometheusConfig();
    res.json({ message: 'Target removed and Prometheus config updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete target' });
  }
});

// Toggle target active/inactive
app.put('/api/targets/:id/toggle', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    await pool.execute('UPDATE targets SET is_active = NOT is_active WHERE id = ?', [req.params.id]);
    await logAudit(req.user.id, req.user.username, 'TARGET_TOGGLE', `Toggled target #${req.params.id}`, req.ip);
    await syncPrometheusConfig();
    res.json({ message: 'Target toggled' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle target' });
  }
});

// Sync DB targets → prometheus.yml
async function syncPrometheusConfig() {
  if (!pool || !PROM_CONFIG) return;
  try {
    const [targets] = await pool.execute('SELECT * FROM targets WHERE is_active = TRUE');

    // Group by job_name
    const jobMap = {};
    targets.forEach(t => {
      if (!jobMap[t.job_name]) jobMap[t.job_name] = [];
      jobMap[t.job_name].push(`${t.host}:${t.port}`);
    });

    // Build config
    const config = {
      global: {
        scrape_interval: '15s',
        evaluation_interval: '15s',
      },
      alerting: {
        alertmanagers: [{ static_configs: [{ targets: [] }] }],
      },
      rule_files: [],
      scrape_configs: [
        {
          job_name: 'prometheus',
          static_configs: [{ targets: ['localhost:9090'], labels: { app: 'prometheus' } }],
        },
      ],
    };

    // Add managed jobs
    Object.entries(jobMap).forEach(([job, tgts]) => {
      config.scrape_configs.push({
        job_name: job,
        static_configs: [{ targets: tgts }],
      });
    });

    const yamlStr = yaml.dump(config, { lineWidth: -1, noRefs: true });
    fs.writeFileSync(PROM_CONFIG, yamlStr, 'utf8');
    console.log('📝 prometheus.yml updated with', targets.length, 'targets');

    // Trigger Prometheus reload
    try {
      await fetch(`${PROM_URL}/-/reload`, { method: 'POST' });
      console.log('🔄 Prometheus config reloaded');
    } catch (e) {
      console.log('⚠️  Could not reload Prometheus (lifecycle API may be disabled)');
    }
  } catch (err) {
    console.error('Sync config error:', err);
  }
}

// ═══════════════════════════════════════
//  INCIDENTS
// ═══════════════════════════════════════
app.get('/api/incidents', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { status, severity, limit } = req.query;
    let sql = 'SELECT * FROM incidents WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (severity) { sql += ' AND severity = ?'; params.push(severity); }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(parseInt(limit) || 500);
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch incidents' });
  }
});

app.post('/api/incidents', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { host, severity, type, description, autoDetected } = req.body;
    if (!type) return res.status(400).json({ error: 'Incident type is required' });

    // Dedup auto-detected
    if (autoDetected) {
      const [existing] = await pool.execute(
        'SELECT id FROM incidents WHERE host = ? AND type = ? AND status = "OPEN" AND auto_detected = TRUE',
        [host || 'SYSTEM', type]
      );
      if (existing.length > 0) return res.json({ message: 'Duplicate — already tracked', id: existing[0].id });
    }

    const [result] = await pool.execute(
      'INSERT INTO incidents (host, severity, type, description, reporter_id, reporter_name, auto_detected) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [host || 'SYSTEM', severity || 'WARNING', type, description || '', req.user.id, req.user.fullName || req.user.username, autoDetected ? true : false]
    );
    await logAudit(req.user.id, req.user.username, 'INCIDENT_CREATE', `Logged incident: ${type} on ${host}`, req.ip);
    res.status(201).json({ message: 'Incident logged', id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: 'Failed to log incident' });
  }
});

app.put('/api/incidents/:id/resolve', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  // Operators and Admins can resolve, Viewers cannot.
  if (req.user.role === 'viewer') return res.status(403).json({ error: 'View-only access' });
  try {
    const { resolvedBy, notes } = req.body;
    await pool.execute(
      'UPDATE incidents SET status = "RESOLVED", resolved_by = ?, resolved_at = NOW(), resolution_notes = ? WHERE id = ?',
      [resolvedBy || req.user.username, notes || '', req.params.id]
    );
    await logAudit(req.user.id, req.user.username, 'INCIDENT_RESOLVE', `Resolved incident #${req.params.id}`, req.ip);
    res.json({ message: 'Incident resolved' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to resolve incident' });
  }
});

app.delete('/api/incidents/:id', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    await pool.execute('DELETE FROM incidents WHERE id = ?', [req.params.id]);
    res.json({ message: 'Incident deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete incident' });
  }
});

app.delete('/api/incidents/clear/resolved', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [result] = await pool.execute('DELETE FROM incidents WHERE status = "RESOLVED"');
    res.json({ message: `Cleared ${result.affectedRows} resolved incidents` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear incidents' });
  }
});

// ═══════════════════════════════════════
//  METRIC SNAPSHOTS (for historical)
// ═══════════════════════════════════════
app.post('/api/snapshots', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { hosts } = req.body; // array of { host, cpu, mem, disk, netIn, netOut, isUp }
    if (!hosts || !hosts.length) return res.status(400).json({ error: 'No host data' });
    const values = hosts.map(h => [h.host, h.cpu, h.mem, h.disk, h.netIn, h.netOut, h.isUp !== false]);
    const placeholders = values.map(() => '(?, ?, ?, ?, ?, ?, ?)').join(', ');
    const flat = values.flat();
    await pool.execute(
      `INSERT INTO metric_snapshots (host, cpu_usage, mem_usage, disk_usage, net_in, net_out, is_up) VALUES ${placeholders}`,
      flat
    );
    res.json({ message: `Saved ${hosts.length} snapshots` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save snapshots' });
  }
});

app.get('/api/snapshots', authRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { host, hours } = req.query;
    const h = parseInt(hours) || 24;
    let sql = 'SELECT * FROM metric_snapshots WHERE recorded_at > DATE_SUB(NOW(), INTERVAL ? HOUR)';
    const params = [h];
    if (host) { sql += ' AND host = ?'; params.push(host); }
    sql += ' ORDER BY recorded_at ASC LIMIT 5000';
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch snapshots' });
  }
});

// ═══════════════════════════════════════
//  AUDIT LOG
// ═══════════════════════════════════════
app.get('/api/audit', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const limit = parseInt(req.query.limit) || 200;
    const [rows] = await pool.execute(
      'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?', [limit]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// ═══════════════════════════════════════
//  ALERT EMAILS
// ═══════════════════════════════════════
app.get('/api/alert-emails', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [rows] = await pool.execute('SELECT * FROM alert_emails ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch alert emails' });
  }
});

app.post('/api/alert-emails', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });
    await pool.execute('INSERT INTO alert_emails (email) VALUES (?)', [email]);
    await logAudit(req.user.id, req.user.username, 'EMAIL_ADD', `Added alert email: ${email}`, req.ip);
    res.status(201).json({ message: 'Email added' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Failed to add email' });
  }
});

app.delete('/api/alert-emails/:id', authRequired, adminRequired, async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not available' });
  try {
    const [email] = await pool.execute('SELECT email FROM alert_emails WHERE id = ?', [req.params.id]);
    if (email.length === 0) return res.status(404).json({ error: 'Email not found' });
    await pool.execute('DELETE FROM alert_emails WHERE id = ?', [req.params.id]);
    await logAudit(req.user.id, req.user.username, 'EMAIL_DELETE', `Deleted alert email: ${email[0].email}`, req.ip);
    res.json({ message: 'Email deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete email' });
  }
});


// ═══════════════════════════════════════
//  CRON — Log Retention & Snapshots
// ═══════════════════════════════════════
// Daily at 2 AM: purge old data
cron.schedule('0 2 * * *', async () => {
  if (!pool) return;
  try {
    const [r1] = await pool.execute(
      'DELETE FROM incidents WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [LOG_RETENTION]
    );
    const [r2] = await pool.execute(
      'DELETE FROM metric_snapshots WHERE recorded_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [LOG_RETENTION]
    );
    const [r3] = await pool.execute(
      'DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)', [LOG_RETENTION]
    );
    console.log(`🧹 Retention cleanup: ${r1.affectedRows} incidents, ${r2.affectedRows} snapshots, ${r3.affectedRows} audit entries purged`);
  } catch (err) {
    console.error('Retention cleanup error:', err);
  }
});

// ═══════════════════════════════════════
//  SPA FALLBACK
// ═══════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
async function start() {
  await initDB();
  
  // Add default localhost:9100 target if it doesn't exist
  if (pool) {
    try {
      const [existing] = await pool.execute(
        'SELECT id FROM targets WHERE host = ? AND port = ?',
        ['127.0.0.1', 9100]
      );
      if (existing.length === 0) {
        await pool.execute(
          'INSERT INTO targets (host, port, job_name, os_type, display_name, labels, is_active, added_by) VALUES (?, ?, ?, ?, ?, ?, TRUE, 1)',
          ['127.0.0.1', 9100, 'node_exporter', 'linux', 'Localhost Node Exporter', '{}', 1]
        );
        console.log('✅ Added default target: 127.0.0.1:9100 (node_exporter)');
        await syncPrometheusConfig();
      }
    } catch (err) {
      console.log('⚠️  Could not add default target:', err.message);
    }
  }
  
  app.listen(PORT, () => {
    console.log(`\n🚀 ═══════════════════════════════════════════`);
    console.log(`   ISRO ICC — Infrastructure Command Centre`);
    console.log(`   Running on http://localhost:${PORT}`);
    console.log(`   Prometheus: ${PROM_URL}`);
    console.log(`═══════════════════════════════════════════════\n`);
  });
}

start();
