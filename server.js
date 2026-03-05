require('dotenv').config();
const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const {
  getUserById,
  getUserByUsername,
  getUserByEmail,
  createUser,
  updateUser,
  updateUserPassword,
  deleteUser,
  getAllUsers,
  getUserPermissions,
  hasPermission,
  getAllRoles,
  getRoleById,
  createRole,
  updateRole,
  deleteRole,
  getRolePermissions,
  grantPermissionToRole,
  revokePermissionFromRole,
  getAllPermissions,
  createPasswordResetToken,
  verifyPasswordResetToken,
  usePasswordResetToken,
  logAudit,
  verifyPassword
} = require('./db');

const { authMiddleware, requireAdmin, generateToken } = require('./auth');

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Email transporter setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'localhost',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: process.env.SMTP_USER ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  } : undefined
});

// Public routes - serve login page
app.get('/', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
  } else {
    res.sendFile(path.join(__dirname, 'login.html'));
  }
});

// ======================
// AUTHENTICATION ROUTES
// ======================

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = getUserByUsername(username);

  if (!user || !verifyPassword(user.password_hash, password)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  if (user.status !== 'active') {
    return res.status(401).json({ error: 'User account is inactive' });
  }

  const permissions = getUserPermissions(user.id);
  const token = generateToken(user, permissions);

  logAudit(user.id, 'LOGIN', null, null, req.ip);

  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });

  res.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  });
});

// Logout endpoint
app.post('/api/auth/logout', authMiddleware, (req, res) => {
  logAudit(req.user.userId, 'LOGOUT', null, null, req.ip);
  res.clearCookie('token');
  res.json({ success: true });
});

// Get current user info
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = getUserById(req.user.userId);
  const permissions = getUserPermissions(req.user.userId);

  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      forcePasswordChange: !!user.force_password_change
    },
    permissions: permissions.map(p => p.name)
  });
});

// Change password for authenticated user
app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  const { newPassword } = req.body;

  if (!newPassword) {
    return res.status(400).json({ error: 'New password required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    updateUserPassword(req.user.userId, newPassword);
    logAudit(req.user.userId, 'PASSWORD_CHANGED', null, null, req.ip);
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Request password reset
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  const user = getUserByEmail(email);

  if (!user) {
    // Don't reveal if email exists
    return res.json({ success: true, message: 'If email exists, password reset link will be sent' });
  }

  try {
    const resetToken = createPasswordResetToken(user.id);
    const resetUrl = `${process.env.APP_URL || 'http://localhost:8080'}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.SMTP_FROM || 'noreply@ztna-tools.local',
      to: email,
      subject: 'ZTNA Net-Tools Password Reset',
      html: `
        <h2>Password Reset Request</h2>
        <p>Click the link below to reset your password. This link expires in 24 hours.</p>
        <a href="${resetUrl}" style="background-color: #9D003A; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
        <p>Or copy this link: ${resetUrl}</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error('Email error:', err);
        return res.status(500).json({ error: 'Failed to send reset email' });
      }

      logAudit(user.id, 'PASSWORD_RESET_REQUESTED', null, null, req.ip);
      res.json({ success: true, message: 'Password reset email sent' });
    });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ error: 'Invalid email configuration' });
  }
});

// Verify reset token and reset password
app.post('/api/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password required' });
  }

  const userId = verifyPasswordResetToken(token);

  if (!userId) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  try {
    updateUserPassword(userId, newPassword);
    usePasswordResetToken(token);

    logAudit(userId, 'PASSWORD_CHANGED', null, null, req.ip);
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ======================
// USER MANAGEMENT ROUTES (Admin Only)
// ======================

// Get all users
app.get('/api/admin/users', authMiddleware, requireAdmin, (req, res) => {
  const users = getAllUsers();
  const enrichedUsers = users.map(user => ({
    ...user,
    permissions: getUserPermissions(user.id)
  }));

  res.json(enrichedUsers);
});

// Create new user
app.post('/api/admin/users', authMiddleware, requireAdmin, (req, res) => {
  const { username, email, password, roleId } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (getUserByUsername(username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  try {
    const userId = createUser(username, email || null, password, roleId || null);
    logAudit(req.user.userId, 'USER_CREATED', 'user', { user_id: userId, username }, req.ip);

    res.json({
      success: true,
      user: {
        id: userId,
        username,
        email,
        role_id: roleId || null
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Update user
app.put('/api/admin/users/:userId', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const { username, email, status, roleId } = req.body;

  const existingUser = getUserById(userId);
  if (!existingUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const updates = {};
  if (username !== undefined) updates.username = username;
  if (email !== undefined) updates.email = email;
  if (status !== undefined) updates.status = status;
  if (roleId !== undefined) updates.role_id = roleId;

  try {
    updateUser(userId, updates);
    const updatedUser = getUserById(userId);

    logAudit(req.user.userId, 'USER_UPDATED', 'user', { user_id: userId, updates }, req.ip);

    res.json({
      success: true,
      user: updatedUser
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Update user password (Admin only)
app.post('/api/admin/users/:userId/password', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'New password required' });
  }

  const user = getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    updateUserPassword(userId, password);
    logAudit(req.user.userId, 'USER_PASSWORD_CHANGED', 'user', { user_id: userId }, req.ip);

    res.json({ success: true, message: 'Password updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// Delete user
app.delete('/api/admin/users/:userId', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;

  if (parseInt(userId) === req.user.userId) {
    return res.status(400).json({ error: 'Cannot delete your own user account' });
  }

  const user = getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  try {
    deleteUser(userId);
    logAudit(req.user.userId, 'USER_DELETED', 'user', { user_id: userId, username: user.username }, req.ip);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ======================
// PERMISSION MANAGEMENT ROUTES (Admin Only)
// ======================

// ====================== ROLE MANAGEMENT ======================

// Get all roles
app.get('/api/admin/roles', authMiddleware, requireAdmin, (req, res) => {
  try {
    const roles = getAllRoles();
    // Add permission count to each role
    const rolesWithCounts = roles.map(role => ({
      ...role,
      permissionCount: getRolePermissions(role.id).length
    }));
    res.json(rolesWithCounts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch roles' });
  }
});

// Create a new role
app.post('/api/admin/roles', authMiddleware, requireAdmin, (req, res) => {
  const { name, description } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Role name required' });
  }

  // Check if role name already exists
  const existingRoles = getAllRoles();
  if (existingRoles.some(r => r.name.toLowerCase() === name.toLowerCase())) {
    return res.status(400).json({ error: 'Role name already exists' });
  }

  try {
    const roleId = createRole(name, description || '');
    logAudit(req.user.userId, 'ROLE_CREATED', 'role', { role_id: roleId, role_name: name }, req.ip);
    res.json({ id: roleId, name, description });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create role' });
  }
});

// Update a role
app.put('/api/admin/roles/:roleId', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;
  const { name, description } = req.body;

  const role = getRoleById(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  // Prevent modifying system roles
  if (role.is_system) {
    return res.status(403).json({ error: 'Cannot modify system roles' });
  }

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Role name required' });
  }

  try {
    updateRole(roleId, name, description || '');
    logAudit(req.user.userId, 'ROLE_UPDATED', 'role', { role_id: roleId, role_name: name }, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update role' });
  }
});

// Delete a role
app.delete('/api/admin/roles/:roleId', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;

  const role = getRoleById(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  // deleteRole returns false if role is system or default
  const deleted = deleteRole(roleId);
  if (!deleted) {
    return res.status(403).json({ error: 'Cannot delete system or default roles' });
  }

  logAudit(req.user.userId, 'ROLE_DELETED', 'role', { role_id: roleId, role_name: role.name }, req.ip);
  res.json({ success: true });
});

// Get permissions for a role
app.get('/api/admin/roles/:roleId/permissions', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;

  const role = getRoleById(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  try {
    const permissions = getRolePermissions(roleId);
    res.json(permissions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch role permissions' });
  }
});

// Grant permission to a role
app.post('/api/admin/roles/:roleId/permissions', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;
  const { permissionName } = req.body;

  if (!permissionName) {
    return res.status(400).json({ error: 'Permission name required' });
  }

  const role = getRoleById(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  // Verify permission exists
  const allPermissions = getAllPermissions();
  if (!allPermissions.some(p => p.name === permissionName)) {
    return res.status(400).json({ error: 'Invalid permission name' });
  }

  try {
    grantPermissionToRole(roleId, permissionName);
    logAudit(req.user.userId, 'PERMISSION_GRANTED_TO_ROLE', 'role', { role_id: roleId, permission: permissionName }, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to grant permission to role' });
  }
});

// Revoke permission from a role
app.delete('/api/admin/roles/:roleId/permissions/:permissionName', authMiddleware, requireAdmin, (req, res) => {
  const { roleId, permissionName } = req.params;

  const role = getRoleById(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  try {
    revokePermissionFromRole(roleId, permissionName);
    logAudit(req.user.userId, 'PERMISSION_REVOKED_FROM_ROLE', 'role', { role_id: roleId, permission: permissionName }, req.ip);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke permission from role' });
  }
});

// Helper function to execute a command and return output as a promise
function executeCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let output = '';
    let errorOutput = '';

    child.stdout.on('data', (data) => {
      output += data.toString();
    });

    child.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    child.on('close', (code) => {
      resolve(output + errorOutput);
    });

    child.on('error', (err) => {
      reject(err);
    });
  });
}

// API endpoint to run network tools
app.post('/api/net-tool', authMiddleware, (req, res) => {
  // Destructure new parameters
  const { tool, host, hosts, dnsServer, recordType, packetSize, dontFrag, port, protocol, debug } = req.body;

  // Check if user has permission for this tool
  const toolPermission = `tool_${tool}`;
  const hasAdmin = req.user.permissions.includes('administration');
  const hasToolPerm = req.user.permissions.includes(toolPermission);

  if (!hasAdmin && !hasToolPerm) {
    return res.status(403).json({ error: `Permission denied: Access to ${tool} tool not granted` });
  }

  // --- Input Sanitization and Command Building ---

  // Whitelist allowed tools
  if (!['ping', 'nslookup', 'nslookup_bulk', 'traceroute', 'mtr', 'openssl_sconnect', 'curl'].includes(tool)) {
    return res.status(400).send('Error: Invalid tool specified.');
  }

  // Sanitize host: Allow FQDNs, IPv4, and IPv6
  // For bulk nslookup, host is not required
  if (tool !== 'nslookup_bulk' && (!host || !/^[a-zA-Z0-9\.:\-\_]+$/.test(host))) {
    return res.status(400).send('Error: Invalid hostname or IP address.');
  }

  // Validate hosts for bulk nslookup
  if (tool === 'nslookup_bulk' && !hosts) {
    return res.status(400).send('Error: Please provide hosts for bulk lookup.');
  }

  // Sanitize DNS server (if provided)
  if (dnsServer && !/^[a-zA-Z0-9\.:\-\_]+$/.test(dnsServer)) {
    return res.status(400).send('Error: Invalid DNS server address.');
  }

  // Validate and normalize record type (if provided)
  let validRecordType = null;
  if (recordType) {
    const allowedTypes = ['A','AAAA','CNAME','MX','TXT','NS','SOA','PTR','SRV','ANY'];
    const up = recordType.toString().toUpperCase();
    if (allowedTypes.includes(up)) {
      validRecordType = up;
    } else {
      return res.status(400).send('Error: Invalid DNS record type specified.');
    }
  }

  // Validate ping packet size and don't fragment (if provided)
  let validPacketSize = null;
  const dontFragment = !!dontFrag;
  if (packetSize) {
    const ps = parseInt(packetSize, 10);
    if (!isNaN(ps) && ps >= 0 && ps <= 65535) {
      validPacketSize = ps;
    } else {
      return res.status(400).send('Error: Invalid packet size specified.');
    }
  }
  
  // Sanitize Port (if provided)
  let validPort = null;
  if (port) {
    const parsedPort = parseInt(port, 10);
    if (!isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
      validPort = parsedPort;
    } else {
      return res.status(400).send('Error: Invalid port specified.');
    }
  }
  const connectPort = validPort || 443; // Default to 443
  
  // Sanitize Protocol (if provided)
  if (protocol) {
    const allowedProtocols = ['tcp', 'udp', 'http', 'https'];
    if (!allowedProtocols.includes(protocol)) {
      return res.status(400).send('Error: Invalid protocol specified.');
    }
  }
  
  // Sanitize Debug (if provided)
  const isDebug = !!debug;
  
  // --- End Sanitization ---

  // Log the tool usage
  logAudit(req.user.userId, `TOOL_EXECUTED`, tool, { host, tool }, req.ip);

  // Special handling for bulk nslookup
  if (tool === 'nslookup_bulk') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    (async () => {
      try {
        // Parse hosts from the input (one per line)
        const hostList = hosts
          .split('\n')
          .map(h => h.trim())
          .filter(h => h.length > 0);

        if (hostList.length === 0) {
          res.write('Error: No valid hosts provided.');
          res.end();
          return;
        }

        res.write(`Performing NSLookup on ${hostList.length} host(s)...\n\n`);

        // Process each host sequentially
        for (let i = 0; i < hostList.length; i++) {
          const queryHost = hostList[i];

          // Validate each host
          if (!/^[a-zA-Z0-9\.:\-\_]+$/.test(queryHost)) {
            res.write(`\n[${i + 1}/${hostList.length}] Skipping invalid host: ${queryHost}\n`);
            continue;
          }

          res.write(`\n[${i + 1}/${hostList.length}] NSLookup: ${queryHost}\n`);
          res.write(`${'='.repeat(60)}\n`);

          try {
            const args = [];
            if (isDebug) {
              args.push('-debug');
            }
            if (validRecordType) {
              args.push(`-type=${validRecordType}`);
            }
            args.push(queryHost);
            if (dnsServer) {
              args.push(dnsServer);
            }

            const output = await executeCommand('nslookup', args);
            res.write(output);
          } catch (err) {
            res.write(`Error executing nslookup: ${err.message}\n`);
          }
        }

        res.write(`\n\n--- Bulk NSLookup completed ---`);
        res.end();
      } catch (err) {
        console.error('Bulk nslookup error:', err);
        res.write(`\n--- ERROR: ${err.message} ---`);
        res.end();
      }
    })();
    return; // Exit early, don't process further
  }

  let command;
  let args = [];

  switch (tool) {
    case 'ping':
      command = 'ping';
      args = ['-c', '4'];
      if (validPacketSize !== null) {
        args.push('-s', validPacketSize.toString());
      }
      if (dontFragment) {
        // ping options vary; try common flags
        args.push('-M', 'do');
        args.push('-D');
      }
      args.push(host);
      break;
      
    case 'nslookup':
      command = 'nslookup';
      args = [];
      if (isDebug) {
        args.push('-debug');
      }
      if (validRecordType) {
        args.push(`-type=${validRecordType}`);
      }
      args.push(host);
      if (dnsServer) {
        args.push(dnsServer);
      }
      break;
    case 'traceroute':
      command = 'traceroute';
      args = ['-w', '3', '-q', '1', '-m', '20', host];
      break;
      
    case 'mtr':
      command = 'mtr';
      // -r (report mode), -c 5 (5 cycles), -n (no DNS)
      args = ['-r', '-w', '-b', '--tcp'];
      
      if (validPort) {
        args.push('-P', connectPort.toString());
      }
      args.push(host);
      break;

    case 'openssl_sconnect':
      command = 'timeout';
      args = [
        '10',
        'openssl',
        's_client',
        '-connect', `${host}:${connectPort}`, // host:port
        '-servername', host                 // SNI support
      ];      
      if (!isDebug) {
        args.push('-brief');
      } else {
        args.push('-showcerts');
      }
      break;

    case 'curl':
      command = 'curl';
      const curlProtocol = (protocol === 'http') ? 'http' : 'https';
      const curlPort = validPort ? `:${validPort}` : '';
      const curlUrl = `${curlProtocol}://${host}${curlPort}`;
      args = [
        '-s',
        '-S',
        '-o', '/dev/null',
        '-w', '\nHTTP Code: %{http_code}\nDNS Lookup: %{time_namelookup}s\nTLS Handshake: %{time_appconnect}s\nTime to First Byte: %{time_starttransfer}s\nTotal Time: %{time_total}s\n',
        curlUrl
      ];
      break;
  }

  // --- Process Execution ---
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Transfer-Encoding', 'chunked');

  const child = spawn(command, args);

  // For openssl s_client, we need to send 'Q' to cleanly exit
  if (tool === 'openssl_sconnect') {
    child.stdin.write('Q\n');
    child.stdin.end();
  }

  // Stream stdout
  child.stdout.on('data', (data) => {
    res.write(data);
  });

  // Stream stderr
  child.stderr.on('data', (data) => {
    res.write(data);
  });

  // Handle process exit
  child.on('close', (code) => {
    res.write(`\n--- Process finished ---`);
    res.end();
  });

  // Handle errors
  child.on('error', (err) => {
    console.error(`Failed to start subprocess: ${err}`);
    res.write(`\n--- ERROR: Failed to start subprocess ${err.message} ---`);
    res.end();
  });
});

// Serve additional pages
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// Serve static assets (if any)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`ZTNA Net-Tools listening on port ${port}`);
});

