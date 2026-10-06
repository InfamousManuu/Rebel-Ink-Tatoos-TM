/**
 * Rebel Ink Tattoos — zero-dependency Node server
 * JSON file storage (data/users.json) — works across devices while process is running.
 * On Render free tier the disk is ephemeral; for permanent storage use a paid disk or MongoDB.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data', 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'rebel-ink-change-me-in-production-32chars';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@rebelink.com').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';

// ----- File helpers -----
function ensureData() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
}
function readUsers() {
  ensureData();
  try {
    const list = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}
function writeUsers(users) {
  ensureData();
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// ----- Crypto helpers (no bcrypt/jsonwebtoken deps) -----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
  } catch {
    return false;
  }
}
function signToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expect = crypto.createHmac('sha256', JWT_SECRET).update(body).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  } catch {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
function newId() {
  return crypto.randomBytes(12).toString('hex');
}

// ----- Seed admin -----
function seedAdmin() {
  const users = readUsers();
  let admin = users.find(u => (u.email || '').toLowerCase() === ADMIN_EMAIL);
  if (!admin) {
    users.push({
      id: newId(),
      name: 'Admin',
      email: ADMIN_EMAIL,
      phone: '+14025175821',
      country: 'United States',
      state: '',
      password: hashPassword(ADMIN_PASSWORD),
      role: 'admin',
      status: 'approved',
      bookings: [],
      adminNotes: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
    writeUsers(users);
    console.log('Admin created:', ADMIN_EMAIL);
  } else if (admin.role !== 'admin') {
    admin.role = 'admin';
    admin.status = 'approved';
    writeUsers(users);
  }
}

// ----- HTTP helpers -----
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8'
};
function send(res, code, body, type) {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(code, {
    'Content-Type': type || (typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8'),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', c => {
      buf += c;
      if (buf.length > 12e6) {
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(buf ? JSON.parse(buf) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}
function getAuth(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  return token ? verifyToken(token) : null;
}
function publicUser(u) {
  if (!u) return null;
  const { password, ...rest } = u;
  // Frontend expects _id (Mongo-style); file store uses id
  if (rest.id && !rest._id) rest._id = rest.id;
  if (Array.isArray(rest.bookings)) {
    rest.bookings = rest.bookings.map(b => {
      if (b && b._id) return b;
      if (b && b.id) return Object.assign({}, b, { _id: b.id });
      return b;
    });
  }
  return rest;
}

// ----- Routes -----
async function handleApi(req, res, urlPath, method) {
  // Health
  if (urlPath === '/api/health' && method === 'GET') {
    return send(res, 200, { ok: true, time: new Date().toISOString() });
  }

  // Register
  if (urlPath === '/api/register' && method === 'POST') {
    try {
      const body = await readBody(req);
      const { name, phone, country, state, email, password } = body;
      if (!name || !phone || !country || !email || !password) {
        return send(res, 400, { error: 'All required fields must be filled' });
      }
      if (country === 'United States' && !state) {
        return send(res, 400, { error: 'Please select your state' });
      }
      if (
        password.length < 8 ||
        !/[a-zA-Z]/.test(password) ||
        !/[0-9]/.test(password) ||
        !/[^a-zA-Z0-9]/.test(password)
      ) {
        return send(res, 400, {
          error: 'Password must be at least 8 characters and include letters, numbers, and a special character'
        });
      }
      const users = readUsers();
      const em = String(email).toLowerCase().trim();
      if (users.find(u => (u.email || '').toLowerCase() === em)) {
        return send(res, 409, { error: 'Email already registered. Please login.' });
      }
      const user = {
        id: newId(),
        name: String(name).trim(),
        email: em,
        phone: String(phone).trim(),
        country,
        state: country === 'United States' ? state || '' : '',
        password: hashPassword(password),
        role: 'member',
        status: 'pending',
        bookings: [],
        adminNotes: '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      users.push(user);
      writeUsers(users);
      return send(res, 201, {
        message:
          'Account created. An admin will review and approve your account shortly. You can log in once approved.',
        user: { id: user.id, name: user.name, email: user.email, status: user.status }
      });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Registration failed' });
    }
  }

  // Login
  if (urlPath === '/api/login' && method === 'POST') {
    try {
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      const password = body.password || '';
      if (!email || !password) return send(res, 400, { error: 'Email and password required' });
      const users = readUsers();
      const user = users.find(u => (u.email || '').toLowerCase() === email);
      if (!user) return send(res, 401, { error: 'No account found. Please register.' });
      if (!verifyPassword(password, user.password)) {
        return send(res, 401, { error: 'Incorrect password' });
      }
      if (user.role === 'member' && user.status === 'pending') {
        return send(res, 403, {
          error: 'Your account is pending admin approval. Please wait for confirmation.'
        });
      }
      if (user.status === 'suspended') {
        return send(res, 403, { error: 'Your account has been suspended. Contact support.' });
      }
      const token = signToken({ id: user.id, email: user.email, role: user.role, status: user.status });
      return send(res, 200, {
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          country: user.country,
          state: user.state,
          role: user.role,
          status: user.status,
          createdAt: user.createdAt
        }
      });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Login failed' });
    }
  }

  // Admin login
  if (urlPath === '/api/admin/login' && method === 'POST') {
    try {
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      const password = body.password || '';
      const users = readUsers();
      const user = users.find(u => (u.email || '').toLowerCase() === email && u.role === 'admin');
      if (!user || !verifyPassword(password, user.password)) {
        return send(res, 401, { error: 'Invalid admin credentials' });
      }
      const token = signToken({ id: user.id, email: user.email, role: user.role, status: user.status });
      return send(res, 200, {
        token,
        user: { id: user.id, name: user.name, email: user.email, role: user.role }
      });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Admin login failed' });
    }
  }

  // Me
  if (urlPath === '/api/me' && method === 'GET') {
    const auth = getAuth(req);
    if (!auth) return send(res, 401, { error: 'Authentication required' });
    const users = readUsers();
    const user = users.find(u => u.id === auth.id || (u.email || '').toLowerCase() === auth.email);
    if (!user) return send(res, 404, { error: 'User not found' });
    return send(res, 200, { user: publicUser(user) });
  }

  // Reset password
  if (urlPath === '/api/reset-password' && method === 'POST') {
    try {
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      const password = body.password || '';
      if (!email || !password) return send(res, 400, { error: 'Email and new password required' });
      if (
        password.length < 8 ||
        !/[a-zA-Z]/.test(password) ||
        !/[0-9]/.test(password) ||
        !/[^a-zA-Z0-9]/.test(password)
      ) {
        return send(res, 400, {
          error: 'Password must be at least 8 characters and include letters, numbers, and a special character'
        });
      }
      const users = readUsers();
      const user = users.find(u => (u.email || '').toLowerCase() === email);
      if (!user) return send(res, 404, { error: 'No account found with that email' });
      user.password = hashPassword(password);
      user.updatedAt = new Date().toISOString();
      writeUsers(users);
      return send(res, 200, { message: 'Password updated. You can now log in.' });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Reset failed' });
    }
  }

  // Create booking
  if (urlPath === '/api/bookings' && method === 'POST') {
    const auth = getAuth(req);
    if (!auth) return send(res, 401, { error: 'Authentication required' });
    try {
      const body = await readBody(req);
      const users = readUsers();
      const user = users.find(u => u.id === auth.id || (u.email || '').toLowerCase() === auth.email);
      if (!user) return send(res, 404, { error: 'User not found' });
      if (user.status !== 'approved' && user.role !== 'admin') {
        return send(res, 403, { error: 'Account not yet approved' });
      }
      const { service, date, problem, photos } = body;
      if (!service || !problem) return send(res, 400, { error: 'Service and description required' });
      if (!user.bookings) user.bookings = [];
      const booking = {
        _id: newId(),
        service,
        date: date || '',
        problem: String(problem).trim(),
        status: 'Pending',
        adminNote: '',
        photos: Array.isArray(photos)
          ? photos.slice(0, 5).map(p => ({ name: p.name || 'photo', dataUrl: p.dataUrl }))
          : [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      user.bookings.unshift(booking);
      user.updatedAt = new Date().toISOString();
      writeUsers(users);
      return send(res, 201, { message: 'Booking submitted', booking });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Booking failed' });
    }
  }

  // List own bookings
  if (urlPath === '/api/bookings' && method === 'GET') {
    const auth = getAuth(req);
    if (!auth) return send(res, 401, { error: 'Authentication required' });
    const users = readUsers();
    const user = users.find(u => u.id === auth.id || (u.email || '').toLowerCase() === auth.email);
    if (!user) return send(res, 404, { error: 'User not found' });
    return send(res, 200, { bookings: user.bookings || [] });
  }

  // Admin: list members
  if (urlPath === '/api/admin/members' && method === 'GET') {
    const auth = getAuth(req);
    if (!auth || auth.role !== 'admin') return send(res, 403, { error: 'Forbidden' });
    const members = readUsers()
      .filter(u => u.role === 'member')
      .map(publicUser)
      .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    const stats = {
      total: members.length,
      pending: members.filter(u => u.status === 'pending').length,
      approved: members.filter(u => u.status === 'approved').length,
      suspended: members.filter(u => u.status === 'suspended').length,
      withBookings: members.filter(u => (u.bookings || []).length > 0).length,
      pendingBookings: members.reduce(
        (n, u) => n + (u.bookings || []).filter(b => b.status === 'Pending').length,
        0
      )
    };
    return send(res, 200, { members, stats });
  }

  // Admin: member status  /api/admin/members/:id/status
  const memberStatusMatch = urlPath.match(/^\/api\/admin\/members\/([^/]+)\/status$/);
  if (memberStatusMatch && method === 'PATCH') {
    const auth = getAuth(req);
    if (!auth || auth.role !== 'admin') return send(res, 403, { error: 'Forbidden' });
    try {
      const body = await readBody(req);
      const { status } = body;
      if (!['pending', 'approved', 'suspended'].includes(status)) {
        return send(res, 400, { error: 'Invalid status' });
      }
      const users = readUsers();
      const user = users.find(u => u.id === memberStatusMatch[1]);
      if (!user || user.role !== 'member') return send(res, 404, { error: 'Member not found' });
      user.status = status;
      user.updatedAt = new Date().toISOString();
      writeUsers(users);
      return send(res, 200, {
        message: 'Member ' + status,
        user: { id: user.id, email: user.email, status: user.status }
      });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Update failed' });
    }
  }

  // Admin: member notes
  const memberNotesMatch = urlPath.match(/^\/api\/admin\/members\/([^/]+)\/notes$/);
  if (memberNotesMatch && method === 'PATCH') {
    const auth = getAuth(req);
    if (!auth || auth.role !== 'admin') return send(res, 403, { error: 'Forbidden' });
    try {
      const body = await readBody(req);
      const users = readUsers();
      const user = users.find(u => u.id === memberNotesMatch[1]);
      if (!user) return send(res, 404, { error: 'Member not found' });
      user.adminNotes = body.notes || '';
      user.updatedAt = new Date().toISOString();
      writeUsers(users);
      return send(res, 200, { message: 'Notes saved' });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Failed to save notes' });
    }
  }

  // Admin: booking status  /api/admin/bookings/:userId/:bookingId/status
  const bookingMatch = urlPath.match(/^\/api\/admin\/bookings\/([^/]+)\/([^/]+)\/status$/);
  if (bookingMatch && method === 'PATCH') {
    const auth = getAuth(req);
    if (!auth || auth.role !== 'admin') return send(res, 403, { error: 'Forbidden' });
    try {
      const body = await readBody(req);
      const users = readUsers();
      const user = users.find(u => u.id === bookingMatch[1]);
      if (!user) return send(res, 404, { error: 'User not found' });
      const booking = (user.bookings || []).find(b => b._id === bookingMatch[2]);
      if (!booking) return send(res, 404, { error: 'Booking not found' });
      if (body.status && ['Pending', 'Approved', 'Rejected', 'Done', 'Cancelled'].includes(body.status)) {
        booking.status = body.status;
      }
      if (typeof body.adminNote === 'string') booking.adminNote = body.adminNote;
      booking.updatedAt = new Date().toISOString();
      user.updatedAt = new Date().toISOString();
      writeUsers(users);
      return send(res, 200, { message: 'Booking updated', booking });
    } catch (e) {
      return send(res, 400, { error: e.message || 'Failed to update booking' });
    }
  }

  // Admin export CSV
  if (urlPath === '/api/admin/export' && method === 'GET') {
    const auth = getAuth(req);
    if (!auth || auth.role !== 'admin') return send(res, 403, { error: 'Forbidden' });
    const members = readUsers().filter(u => u.role === 'member');
    const rows = [
      ['Name', 'Email', 'Phone', 'Country', 'State', 'Status', 'Joined', 'Bookings count', 'Admin notes']
    ];
    members.forEach(u => {
      rows.push([
        u.name,
        u.email,
        u.phone,
        u.country,
        u.state || '',
        u.status,
        u.createdAt || '',
        (u.bookings || []).length,
        (u.adminNotes || '').replace(/\n/g, ' ')
      ]);
    });
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename=rebel-ink-members.csv',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store'
    });
    return res.end(csv);
  }

  return send(res, 404, { error: 'Not found' });
}

// ----- Server -----
const server = http.createServer(async (req, res) => {
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
  const method = (req.method || 'GET').toUpperCase();

  if (method === 'OPTIONS') {
    return send(res, 204, '');
  }

  if (urlPath.startsWith('/api/')) {
    try {
      await handleApi(req, res, urlPath, method);
    } catch (e) {
      console.error(e);
      send(res, 500, { error: 'Server error' });
    }
    return;
  }

  // Static files
  let filePath = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
  if (!filePath.startsWith(ROOT)) {
    return send(res, 403, 'Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      fs.readFile(path.join(ROOT, 'public', 'index.html'), (e2, d2) => {
        if (e2) return send(res, 404, 'Not found');
        send(res, 200, d2, 'text/html; charset=utf-8');
      });
      return;
    }
    send(res, 200, data, TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream');
  });
});

ensureData();
seedAdmin();
server.listen(PORT, () => {
  console.log('Rebel Ink Tattoos on port ' + PORT);
  console.log('Admin: set ADMIN_EMAIL / ADMIN_PASSWORD env vars (defaults seeded on first run)');
});
