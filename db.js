const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');
const fs = require('fs');

// Initialize database
// database stored in data directory for persistence
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}
const dbPath = path.join(dataDir, 'ztna-tools.db');

// Create blank .db file if it doesn't exist
if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, '');
  console.log('Created new database file at:', dbPath);
}

const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

// Initialize database schema
function initializeDatabase() {
  // Users table with role_id and optional forced password change flag
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT,
      password_hash TEXT NOT NULL,
      role_id INTEGER,
      status TEXT DEFAULT 'active',
      force_password_change INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
    )
  `);

  // add column if migrating from older schema
  try {
    db.exec('ALTER TABLE users ADD COLUMN force_password_change INTEGER DEFAULT 0');
  } catch (err) {
    // ignore errors (column already exists)
  }

  // Permissions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Roles table
  db.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      is_default INTEGER DEFAULT 0,
      is_system INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Role permissions junction table
  db.exec(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      UNIQUE(role_id, permission_id)
    )
  `);

  // Legacy user permissions table (kept for backward compatibility)
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      UNIQUE(user_id, permission_id)
    )
  `);

  // Password reset tokens table
  db.exec(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at DATETIME NOT NULL,
      used INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Audit logs table
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      resource TEXT,
      details TEXT,
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  // Create default permissions if they don't exist
  const permissions = [
    { name: 'administration', description: 'Full access to administration and all tools' },
    { name: 'tool_ping', description: 'Access to Ping tool' },
    { name: 'tool_nslookup', description: 'Access to NSLookup tool' },
    { name: 'tool_nslookup_bulk', description: 'Access to NSLookup Bulk tool' },
    { name: 'tool_traceroute', description: 'Access to Traceroute tool' },
    { name: 'tool_mtr', description: 'Access to TCP Traceroute (MTR) tool' },
    { name: 'tool_openssl', description: 'Access to TLS Handshake (OpenSSL) tool' },
    { name: 'tool_curl', description: 'Access to HTTP Timing Stats (Curl) tool' }
  ];

  const existingPerms = db.prepare('SELECT name FROM permissions').all();
  const existingPermNames = existingPerms.map(p => p.name);

  for (const perm of permissions) {
    if (!existingPermNames.includes(perm.name)) {
      db.prepare('INSERT INTO permissions (name, description) VALUES (?, ?)').run(
        perm.name,
        perm.description
      );
    }
  }

  // Create default roles if they don't exist
  const adminRoleExists = db.prepare('SELECT id FROM roles WHERE name = ?').get('Admin');
  let adminRoleId = adminRoleExists?.id;

  if (!adminRoleExists) {
    const allPerms = db.prepare('SELECT id FROM permissions').all();
    adminRoleId = db
      .prepare('INSERT INTO roles (name, description, is_default, is_system) VALUES (?, ?, 1, 1)')
      .run('Admin', 'Administrator with full access')
      .lastInsertRowid;

    // Assign all permissions to Admin role
    for (const perm of allPerms) {
      db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)')
        .run(adminRoleId, perm.id);
    }
  }

  const fullUserRoleExists = db.prepare('SELECT id FROM roles WHERE name = ?').get('Full User');
  let fullUserRoleId = fullUserRoleExists?.id;

  if (!fullUserRoleExists) {
    const allPerms = db.prepare('SELECT id, name FROM permissions').all();
    fullUserRoleId = db
      .prepare('INSERT INTO roles (name, description, is_default, is_system) VALUES (?, ?, 1, 0)')
      .run('Full User', 'User with access to all tools')
      .lastInsertRowid;

    // Assign all permissions except administration to Full User role
    for (const perm of allPerms) {
      if (perm.name !== 'administration') {
        db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)')
          .run(fullUserRoleId, perm.id);
      }
    }
  } else {
    // Fix existing Full User role permissions (remove administration if present)
    const adminPerm = db.prepare('SELECT id FROM permissions WHERE name = ?').get('administration');
    if (adminPerm) {
      db.prepare('DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?')
        .run(fullUserRoleId, adminPerm.id);
    }
  }

  // Create default admin user if it doesn't exist
  const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!adminExists) {
    const passwordHash = bcrypt.hashSync('admin', 10);
    db.prepare(
      'INSERT INTO users (username, email, password_hash, role_id, force_password_change) VALUES (?, ?, ?, ?, 1)'
    ).run('admin', '', passwordHash, adminRoleId);

    console.log('Default admin user created: username=admin, password=admin (force password change on first login)');
  }
}

// Functions to interact with database
const dbFunctions = {
  // User operations
  getUserById(userId) {
    return db.prepare(`
      SELECT u.id, u.username, u.email, u.status, u.role_id, u.force_password_change, r.name as role_name
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.id = ?
    `).get(userId);
  },

  getUserByUsername(username) {
    return db
      .prepare(`
        SELECT u.id, u.username, u.email, u.password_hash, u.status, u.role_id, r.name as role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.username = ?
      `)
      .get(username);
  },

  getUserByEmail(email) {
    return db.prepare(`
      SELECT u.id, u.username, u.email, u.status, u.role_id, r.name as role_name
      FROM users u
      LEFT JOIN roles r ON u.role_id = r.id
      WHERE u.email = ?
    `).get(email);
  },

  createUser(username, email, password, roleId = null) {
    const passwordHash = bcrypt.hashSync(password, 10);
    const stmt = db.prepare(
      'INSERT INTO users (username, email, password_hash, role_id) VALUES (?, ?, ?, ?)'
    );
    const result = stmt.run(username, email, passwordHash, roleId);
    return result.lastInsertRowid;
  },

  updateUser(userId, updates) {
    const fields = [];
    const values = [];
    for (const [key, value] of Object.entries(updates)) {
      if (['username', 'email', 'status', 'role_id'].includes(key)) {
        fields.push(`${key} = ?`);
        values.push(value);
      }
    }
    if (fields.length === 0) return null;

    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(userId);

    const query = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
    return db.prepare(query).run(...values);
  },

  updateUserPassword(userId, newPassword) {
    const passwordHash = bcrypt.hashSync(newPassword, 10);
    return db
      .prepare('UPDATE users SET password_hash = ?, force_password_change = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(passwordHash, userId);
  },

  deleteUser(userId) {
    return db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  },

  getAllUsers() {
    return db
      .prepare(`
        SELECT u.id, u.username, u.email, u.status, u.role_id, r.name as role_name, u.created_at
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        ORDER BY u.created_at DESC
      `)
      .all();
  },

  // Role operations
  getAllRoles() {
    return db
      .prepare('SELECT id, name, description, is_default, is_system FROM roles ORDER BY name ASC')
      .all();
  },

  getRoleById(roleId) {
    return db
      .prepare('SELECT id, name, description, is_default, is_system FROM roles WHERE id = ?')
      .get(roleId);
  },

  createRole(name, description = '') {
    const stmt = db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)');
    const result = stmt.run(name, description);
    return result.lastInsertRowid;
  },

  updateRole(roleId, name, description) {
    return db
      .prepare('UPDATE roles SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?')
      .run(name, description, roleId);
  },

  deleteRole(roleId) {
    // cannot delete system or default roles
    const role = db
      .prepare('SELECT is_system, is_default FROM roles WHERE id = ?')
      .get(roleId);

    if (!role || role.is_system || role.is_default) {
      return false;
    }

    // clear any user assignments first (avoid deleting users)
    db.prepare('UPDATE users SET role_id = NULL WHERE role_id = ?').run(roleId);
    // remove associated permissions
    db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(roleId);

    const result = db.prepare('DELETE FROM roles WHERE id = ?').run(roleId);
    return result.changes > 0;
  },


  // Role permission operations
  getRolePermissions(roleId) {
    return db
      .prepare(`
        SELECT p.id, p.name, p.description
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
        ORDER BY p.name ASC
      `)
      .all(roleId);
  },

  grantPermissionToRole(roleId, permissionName) {
    const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permissionName);
    if (!perm) return null;

    return db
      .prepare('INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)')
      .run(roleId, perm.id);
  },

  revokePermissionFromRole(roleId, permissionName) {
    const perm = db.prepare('SELECT id FROM permissions WHERE name = ?').get(permissionName);
    if (!perm) return null;

    return db
      .prepare('DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?')
      .run(roleId, perm.id);
  },

  // Permission operations
  getUserPermissions(userId) {
    return db
      .prepare(`
        SELECT DISTINCT p.id, p.name, p.description
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        JOIN users u ON u.role_id = r.id
        WHERE u.id = ?
      `)
      .all(userId);
  },

  hasPermission(userId, permissionName) {
    const result = db
      .prepare(`
        SELECT 1 FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        JOIN users u ON u.role_id = r.id
        WHERE u.id = ? AND (p.name = ? OR p.name = 'administration')
      `)
      .get(userId, permissionName);
    return !!result;
  },

  getUserToolPermissions(userId) {
    return db
      .prepare(`
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        JOIN users u ON u.role_id = r.id
        WHERE u.id = ? AND (p.name LIKE 'tool_%' OR p.name = 'administration')
      `)
      .all(userId)
      .map(p => p.name.replace('tool_', ''));
  },

  getAllPermissions() {
    return db.prepare('SELECT id, name, description FROM permissions ORDER BY name ASC').all();
  },

  // Password reset operations
  createPasswordResetToken(userId) {
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    db.prepare('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)')
      .run(userId, token, expiresAt);

    return token;
  },

  verifyPasswordResetToken(token) {
    const result = db
      .prepare(`
        SELECT user_id FROM password_reset_tokens 
        WHERE token = ? AND used = 0 AND expires_at > datetime('now')
      `)
      .get(token);
    return result ? result.user_id : null;
  },

  usePasswordResetToken(token) {
    return db
      .prepare('UPDATE password_reset_tokens SET used = 1 WHERE token = ?')
      .run(token);
  },

  // Audit logging
  logAudit(userId, action, resource = null, details = null, ipAddress = null) {
    return db
      .prepare(`
        INSERT INTO audit_logs (user_id, action, resource, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(userId, action, resource, details ? JSON.stringify(details) : null, ipAddress);
  },

  getAuditLogs(limit = 100, offset = 0) {
    return db
      .prepare(`
        SELECT id, user_id, action, resource, details, ip_address, timestamp
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
      `)
      .all(limit, offset);
  },

  verifyPassword(passwordHash, password) {
    return bcrypt.compareSync(password, passwordHash);
  }
};

// Initialize database on module load
initializeDatabase();

module.exports = { db, ...dbFunctions };
