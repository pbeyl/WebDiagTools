require('dotenv').config();
const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const net = require('net');

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
  getUserApiTokenMetadata,
  createOrRotateUserApiToken,
  extendUserApiTokenExpiry,
  revokeUserApiToken,
  getHeaderAuthConfig,
  updateHeaderAuthConfig,
  getAuthAuditLogs,
  logAuthAudit,
  verifyPassword
} = require('./db');

const { authMiddleware, requireAdmin, generateToken, tryHeaderAuth } = require('./auth');

const app = express();
const port = process.env.PORT || 8080;
const appUrl = process.env.APP_URL || '';
const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = appUrl.startsWith('https://') || (!appUrl && isProduction);

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', true);

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

// Public routes - serve login or dashboard page
app.get('/', (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    res.render('dashboard', { activePage: 'dashboard' });
    return;
  }

  const headerAuthResult = tryHeaderAuth(req);
  if (headerAuthResult.user) {
    // Log successful header-based session establishment
    const user = getUserById(headerAuthResult.user.userId);
    const responsePayload = { success: true, message: 'Session established via header authentication' };
    
    // Temporarily set req.user to allow getAuthTypeForAudit to work correctly
    req.user = headerAuthResult.user;
    
    logAuditEvent(req, {
      success: true,
      event: 'header_auth_session_established',
      user: user,
      responseStatus: 200,
      responseBody: responsePayload
    });
    
    res.render('dashboard', { activePage: 'dashboard' });
    return;
  }

  res.render('login');
});

// ======================
// AUTHENTICATION ROUTES
// ======================

// Login endpoint
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const normalizedUsername = typeof username === 'string' ? username.trim() : null;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);

  if (!username || !password) {
    const responsePayload = { error: 'Username and password required' };
    logAuditEvent(req, {
      success: false,
      event: 'password_login',
      user: { username: normalizedUsername },
      failureReason: 'missing_credentials',
      responseStatus: 400,
      responseBody: responsePayload
    });

    return res.status(400).json(responsePayload);
  }

  const user = getUserByUsername(username);

  if (!user || !verifyPassword(user.password_hash, password)) {
    const responsePayload = { error: 'Invalid username or password' };
    logAuditEvent(req, {
      success: false,
      event: 'password_login',
      user: { username: normalizedUsername },
      failureReason: 'invalid_credentials',
      responseStatus: 401,
      responseBody: responsePayload
    });

    return res.status(401).json(responsePayload);
  }

  if (user.status !== 'active') {
    const responsePayload = { error: 'User account is inactive' };
    logAuditEvent(req, {
      success: false,
      event: 'password_login',
      user: user,
      failureReason: 'inactive_user',
      responseStatus: 401,
      responseBody: responsePayload
    });

    return res.status(401).json(responsePayload);
  }

  const permissions = getUserPermissions(user.id);
  const token = generateToken(user, permissions);

  const responsePayload = {
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email
    }
  };

  logAuditEvent(req, {
    success: true,
    event: 'password_login',
    user: user,
    responseStatus: 200,
    responseBody: responsePayload
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });

  res.json(responsePayload);
});

// Logout endpoint
app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const responsePayload = { success: true };

  logAuditEvent(req, {
    success: true,
    event: 'logout',
    responseStatus: 200,
    responseBody: responsePayload
  });

  res.clearCookie('token');
  res.json(responsePayload);
});

// Get current user info
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = getUserById(req.user.userId);
  const permissions = getUserPermissions(req.user.userId);
  const apiToken = getUserApiTokenMetadata(req.user.userId);

  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      forcePasswordChange: !!user.force_password_change
    },
    permissions: permissions.map(p => p.name),
    apiToken
  });
});

// Update authenticated user's own profile
app.put('/api/auth/profile', authMiddleware, (req, res) => {
  const { email } = req.body;

  if (email !== undefined && email !== null && email !== '') {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      const responsePayload = { error: 'Invalid email format' };
      logAuditEvent(req, {
        success: false,
        event: 'profile_update',
        failureReason: 'invalid_email_format',
        responseStatus: 400,
        responseBody: responsePayload
      });
      return res.status(400).json({ error: 'Invalid email format' });
    }
  }

  try {
    updateUser(req.user.userId, {
      email: email === '' ? null : email
    });

    const updatedUser = getUserById(req.user.userId);

    const responsePayload = {
      success: true,
      user: {
        id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email || null
      }
    };

    logAuditEvent(req, {
      success: true,
      event: 'profile_update',
      user: updatedUser,
      additionalDetails: { email: updatedUser.email || null },
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('Profile update error:', err);
    const responsePayload = { error: 'Failed to update profile' };
    logAuditEvent(req, {
      success: false,
      event: 'profile_update',
      failureReason: 'profile_update_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

function parseLifetimeSeconds(value) {
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed <= 0) {
    return null;
  }

  const minSeconds = 60 * 5;
  const maxSeconds = 60 * 60 * 24 * 365;
  if (parsed < minSeconds || parsed > maxSeconds) {
    return null;
  }

  return parsed;
}

function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') {
    return null;
  }

  const trimmed = ip.trim();
  if (!trimmed) {
    return null;
  }

  const noMappedPrefix = trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
  return net.isIP(noMappedPrefix) ? noMappedPrefix : null;
}

function isValidIpOrCidr(value) {
  if (!value || typeof value !== 'string') {
    return false;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }

  if (!trimmed.includes('/')) {
    return !!normalizeIp(trimmed);
  }

  const [networkRaw, prefixRaw] = trimmed.split('/');
  const network = normalizeIp(networkRaw);
  const prefix = parseInt(prefixRaw, 10);

  if (!network || Number.isNaN(prefix)) {
    return false;
  }

  const version = net.isIP(network);
  if (version === 4) {
    return prefix >= 0 && prefix <= 32;
  }
  if (version === 6) {
    return prefix >= 0 && prefix <= 128;
  }

  return false;
}

function getAuthRequestHeaders(req) {
  const authorizationHeader = req.headers.authorization;
  let authorizationScheme = null;

  if (authorizationHeader && typeof authorizationHeader === 'string') {
    const [scheme] = authorizationHeader.split(/\s+/, 1);
    authorizationScheme = scheme || null;
  }

  return {
    userAgent: req.get('user-agent') || null,
    xForwardedFor: req.get('x-forwarded-for') || null,
    authorizationScheme
  };
}

// Helper to get the proper authType display name for audit logs
function getAuthTypeForAudit(req) {
  const authType = req.user?.authType;
  switch (authType) {
    case 'password':
      return 'password';
    case 'bearer':
      return 'bearer';
    case 'header':
      return 'header';
    default:
      return 'unauthenticated'; // default for unauthenticated/public endpoints
  }
}

// Helper function to log audit events with common fields auto-populated
function logAuditEvent(req, {
  success,
  event,
  user = null,
  failureReason = null,
  additionalDetails = {},
  responseStatus,
  responseBody
}) {
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const authenticatedUserId = req.user?.userId || null;

  let auditUser = user;
  if (!auditUser && authenticatedUserId) {
    auditUser = getUserById(authenticatedUserId);
  }
  
  // Get user info from either req.user (authenticated) or passed user object
  const userId = auditUser?.id || auditUser?.userId || authenticatedUserId || null;
  const username = auditUser?.username || req.user?.username || null;
  const roleName = auditUser?.role_name || req.user?.roleName || null;
  
  logAuthAudit({
    success,
    authType: getAuthTypeForAudit(req),
    userId,
    username,
    roleName,
    sourceIp: req.ip,
    requestMethod: req.method,
    requestPath,
    httpHeaders: requestHeaders,
    failureReason,
    details: {
      event,
      outcome: success ? 'succeeded' : 'failed',
      ...additionalDetails
    },
    responseData: { status: responseStatus, body: responseBody }
  });
}

function csvEscape(value) {
  if (value === null || value === undefined) {
    return '""';
  }

  const text = String(value).replace(/"/g, '""');
  return `"${text}"`;
}

// Get authenticated user's bearer token metadata (token value is never returned)
app.get('/api/auth/api-token', authMiddleware, (req, res) => {
  try {
    const metadata = getUserApiTokenMetadata(req.user.userId);
    const actorUser = getUserById(req.user.userId);
    const responsePayload = { apiToken: metadata };

    logAuditEvent(req, {
      success: true,
      event: 'api_token_metadata_read',
      user: actorUser,
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('API token metadata fetch error:', err);
    const responsePayload = { error: 'Failed to load API token metadata' };

    logAuditEvent(req, {
      success: false,
      event: 'api_token_metadata_read',
      failureReason: 'api_token_metadata_read_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });

    res.status(500).json(responsePayload);
  }
});

// Generate (or rotate) authenticated user's bearer token
app.post('/api/auth/api-token/generate', authMiddleware, (req, res) => {
  const { validitySeconds } = req.body;
  const lifetimeSeconds = parseLifetimeSeconds(validitySeconds);
  const actorUser = getUserById(req.user.userId);

  if (!lifetimeSeconds) {
    const responsePayload = { error: 'Invalid token validity period' };
    logAuditEvent(req, {
      success: false,
      event: 'api_token_generate',
      failureReason: 'invalid_token_validity_period',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json({ error: 'Invalid token validity period' });
  }

  try {
    const result = createOrRotateUserApiToken(req.user.userId, lifetimeSeconds);

    const responsePayload = {
      success: true,
      token: result.token,
      tokenLast4: result.tokenLast4,
      expiresAt: result.expiresAt,
      warning: 'Successfully generated token. Store it securely now.'
    };

    logAuditEvent(req, {
      success: true,
      event: 'api_token_generate',
      user: actorUser,
      additionalDetails: { expiresAt: result.expiresAt },
      responseStatus: 200,
      responseBody: { success: true, tokenLast4: result.tokenLast4, expiresAt: result.expiresAt }
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('API token generation error:', err);
    const responsePayload = { error: 'Failed to generate API token' };
    logAuditEvent(req, {
      success: false,
      event: 'api_token_generate',
      failureReason: 'api_token_generate_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json({ error: 'Failed to generate API token' });
  }
});

// Extend authenticated user's bearer token expiry
app.post('/api/auth/api-token/extend', authMiddleware, (req, res) => {
  const { extensionSeconds } = req.body;
  const extendSeconds = parseLifetimeSeconds(extensionSeconds);
  const actorUser = getUserById(req.user.userId);

  if (!extendSeconds) {
    const responsePayload = { error: 'Invalid token extension period' };
    logAuditEvent(req, {
      success: false,
      event: 'api_token_extend',
      failureReason: 'invalid_token_extension_period',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json({ error: 'Invalid token extension period' });
  }

  try {
    const updated = extendUserApiTokenExpiry(req.user.userId, extendSeconds);
    if (!updated) {
      const responsePayload = { error: 'No active API token to extend' };
      logAuditEvent(req, {
        success: false,
        event: 'api_token_extend',
        failureReason: 'no_active_api_token_to_extend',
        responseStatus: 404,
        responseBody: responsePayload
      });
      return res.status(404).json({ error: 'No active API token to extend' });
    }

    const responsePayload = { success: true, expiresAt: updated.expiresAt };

    logAuditEvent(req, {
      success: true,
      event: 'api_token_extend',
      user: actorUser,
      additionalDetails: { expiresAt: updated.expiresAt },
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('API token extension error:', err);
    const responsePayload = { error: 'Failed to extend API token' };
    logAuditEvent(req, {
      success: false,
      event: 'api_token_extend',
      failureReason: 'api_token_extend_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json({ error: 'Failed to extend API token' });
  }
});

// Revoke authenticated user's bearer token
app.post('/api/auth/api-token/revoke', authMiddleware, (req, res) => {
  const actorUser = getUserById(req.user.userId);

  try {
    const result = revokeUserApiToken(req.user.userId);
    if (!result || result.changes === 0) {
      const responsePayload = { error: 'No active API token to revoke' };
      logAuditEvent(req, {
        success: false,
        event: 'api_token_revoke',
        failureReason: 'no_active_api_token_to_revoke',
        responseStatus: 404,
        responseBody: responsePayload
      });
      return res.status(404).json({ error: 'No active API token to revoke' });
    }

    const responsePayload = { success: true };

    logAuditEvent(req, {
      success: true,
      event: 'api_token_revoke',
      user: actorUser,
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('API token revoke error:', err);
    const responsePayload = { error: 'Failed to revoke API token' };
    logAuditEvent(req, {
      success: false,
      event: 'api_token_revoke',
      failureReason: 'api_token_revoke_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json({ error: 'Failed to revoke API token' });
  }
});

// Change password for authenticated user
app.post('/api/auth/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword) {
    const responsePayload = { error: 'Current password required' };
    logAuditEvent(req, {
      success: false,
      event: 'password_change',
      failureReason: 'missing_current_password',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  if (!newPassword) {
    const responsePayload = { error: 'New password required' };
    logAuditEvent(req, {
      success: false,
      event: 'password_change',
      failureReason: 'missing_new_password',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  if (newPassword.length < 6) {
    const responsePayload = { error: 'Password must be at least 6 characters' };
    logAuditEvent(req, {
      success: false,
      event: 'password_change',
      failureReason: 'new_password_too_short',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    const authUser = getUserByUsername(req.user.username);
    if (!authUser || !verifyPassword(authUser.password_hash, currentPassword)) {
      const responsePayload = { error: 'Current password is incorrect' };
      logAuditEvent(req, {
        success: false,
        event: 'password_change',
        failureReason: 'invalid_current_password',
        responseStatus: 401,
        responseBody: responsePayload
      });
      return res.status(401).json(responsePayload);
    }

    updateUserPassword(req.user.userId, newPassword);

    const responsePayload = { success: true, message: 'Password changed successfully' };

    logAuditEvent(req, {
      success: true,
      event: 'password_change',
      user: authUser,
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    console.error('Error changing password:', err);
    const responsePayload = { error: 'Failed to change password' };
    logAuditEvent(req, {
      success: false,
      event: 'password_change',
      failureReason: 'password_change_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Request password reset
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    const responsePayload = { error: 'Email required' };
    logAuditEvent(req, {
      success: false,
      event: 'password_reset_request',
      failureReason: 'missing_email',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  const user = getUserByEmail(email);

  if (!user) {
    // Don't reveal if email exists
    const responsePayload = { success: true, message: 'If email exists, password reset link will be sent' };
    logAuditEvent(req, {
      success: true,
      event: 'password_reset_request',
      additionalDetails: { matchedUser: false },
      responseStatus: 200,
      responseBody: responsePayload
    });
    return res.json(responsePayload);
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
        const responsePayload = { error: 'Failed to send reset email' };
        logAuditEvent(req, {
          success: false,
          event: 'password_reset_request',
          user: user,
          failureReason: 'password_reset_email_send_failed',
          responseStatus: 500,
          responseBody: responsePayload
        });
        return res.status(500).json(responsePayload);
      }

      const responsePayload = { success: true, message: 'Password reset email sent' };
      logAuditEvent(req, {
        success: true,
        event: 'password_reset_request',
        user: user,
        additionalDetails: { matchedUser: true },
        responseStatus: 200,
        responseBody: responsePayload
      });
      res.json(responsePayload);
    });
  } catch (err) {
    console.error('Password reset error:', err);
    const responsePayload = { error: 'Invalid email configuration' };
    logAuditEvent(req, {
      success: false,
      event: 'password_reset_request',
      failureReason: 'password_reset_request_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Verify reset token and reset password
app.post('/api/auth/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    const responsePayload = { error: 'Token and new password required' };
    logAuditEvent(req, {
      success: false,
      event: 'password_reset_complete',
      failureReason: 'missing_reset_token_or_password',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  const userId = verifyPasswordResetToken(token);

  if (!userId) {
    const responsePayload = { error: 'Invalid or expired reset token' };
    logAuditEvent(req, {
      success: false,
      event: 'password_reset_complete',
      failureReason: 'invalid_or_expired_reset_token',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    const user = getUserById(userId);
    updateUserPassword(userId, newPassword);
    usePasswordResetToken(token);

    const responsePayload = { success: true, message: 'Password reset successfully' };

    logAuditEvent(req, {
      success: true,
      event: 'password_reset_complete',
      user: user,
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to reset password' };
    logAuditEvent(req, {
      success: false,
      event: 'password_reset_complete',
      user: { userId },
      failureReason: 'password_reset_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
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
  const adminUser = getUserById(req.user.userId);

  if (!username || !password) {
    const responsePayload = { error: 'Username and password required' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_create',
      user: adminUser,
      failureReason: 'missing_credentials',
      additionalDetails: { targetUsername: username },
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  if (getUserByUsername(username)) {
    const responsePayload = { error: 'Username already exists' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_create',
      user: adminUser,
      failureReason: 'username_exists',
      additionalDetails: { targetUsername: username },
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    const userId = createUser(username, email || null, password, roleId || null);

    const responsePayload = {
      success: true,
      user: {
        id: userId,
        username,
        email,
        role_id: roleId || null
      }
    };
    logAuditEvent(req, {
      success: true,
      event: 'admin_user_create',
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to create user' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_create',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Update user
app.put('/api/admin/users/:userId', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const { username, email, status, roleId } = req.body;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  const existingUser = getUserById(userId);
  if (!existingUser) {
    const responsePayload = { error: 'User not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_update',
      failureReason: 'user_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  const updates = {};
  if (username !== undefined) updates.username = username;
  if (email !== undefined) updates.email = email;
  if (status !== undefined) updates.status = status;
  if (roleId !== undefined) updates.role_id = roleId;

  try {
    updateUser(userId, updates);
    const updatedUser = getUserById(userId);

    const responsePayload = {
      success: true,
      user: updatedUser
    };
    logAuditEvent(req, {
      success: true,
      event: 'admin_user_update',
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to update user' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_update',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Update user password (Admin only)
app.post('/api/admin/users/:userId/password', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const { password } = req.body;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  if (!password) {
    const responsePayload = { error: 'New password required' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_password_change',
      failureReason: 'missing_password',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  const user = getUserById(userId);
  if (!user) {
    const responsePayload = { error: 'User not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_password_change',
      failureReason: 'user_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  try {
    updateUserPassword(userId, password);

    const responsePayload = { success: true, message: 'Password updated' };
    logAuditEvent(req, {
      success: true,
      event: 'admin_user_password_change',
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to update password' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_password_change',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Delete user
app.delete('/api/admin/users/:userId', authMiddleware, requireAdmin, (req, res) => {
  const { userId } = req.params;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  if (parseInt(userId) === req.user.userId) {
    const responsePayload = { error: 'Cannot delete your own user account' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_delete',
      failureReason: 'self_deletion_attempt',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  const user = getUserById(userId);
  if (!user) {
    const responsePayload = { error: 'User not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_delete',
      failureReason: 'user_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  try {
    deleteUser(userId);

    const responsePayload = { success: true };
    logAuditEvent(req, {
      success: true,
      event: 'admin_user_delete',
      responseStatus: 200,
      responseBody: responsePayload
    });

    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to delete user' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_user_delete',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
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
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  if (!name || !name.trim()) {
    const responsePayload = { error: 'Role name required' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_create',
      failureReason: 'missing_role_name',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  // Check if role name already exists
  const existingRoles = getAllRoles();
  if (existingRoles.some(r => r.name.toLowerCase() === name.toLowerCase())) {
    const responsePayload = { error: 'Role name already exists' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_create',
      failureReason: 'role_name_exists',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    const roleId = createRole(name, description || '');
    
    const responsePayload = { id: roleId, name, description };
    logAuditEvent(req, {
      success: true,
      event: 'admin_role_create',
      responseStatus: 200,
      responseBody: responsePayload
    });
    
    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to create role' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_create',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Update a role
app.put('/api/admin/roles/:roleId', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;
  const { name, description } = req.body;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  const role = getRoleById(roleId);
  if (!role) {
    const responsePayload = { error: 'Role not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_update',
      failureReason: 'role_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  // Prevent modifying system roles
  if (role.is_system) {
    const responsePayload = { error: 'Cannot modify system roles' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_update',
      failureReason: 'system_role_modification_attempt',
      responseStatus: 403,
      responseBody: responsePayload
    });
    return res.status(403).json(responsePayload);
  }

  if (!name || !name.trim()) {
    const responsePayload = { error: 'Role name required' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_update',
      failureReason: 'missing_role_name',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    updateRole(roleId, name, description || '');
    
    const responsePayload = { success: true };
    logAuditEvent(req, {
      success: true,
      event: 'admin_role_update',
      responseStatus: 200,
      responseBody: responsePayload
    });
    
    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to update role' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_update',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Delete a role
app.delete('/api/admin/roles/:roleId', authMiddleware, requireAdmin, (req, res) => {
  const { roleId } = req.params;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  const role = getRoleById(roleId);
  if (!role) {
    const responsePayload = { error: 'Role not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_delete',
      failureReason: 'role_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  // deleteRole returns false if role is system or default
  const deleted = deleteRole(roleId);
  if (!deleted) {
    const responsePayload = { error: 'Cannot delete system or default roles' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_role_delete',
      failureReason: 'system_role_deletion_attempt',
      responseStatus: 403,
      responseBody: responsePayload
    });
    return res.status(403).json(responsePayload);
  }

  const responsePayload = { success: true };
  logAuditEvent(req, {
    success: true,
    event: 'admin_role_delete',
    responseStatus: 200,
    responseBody: responsePayload
  });
  
  res.json(responsePayload);
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
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  if (!permissionName) {
    const responsePayload = { error: 'Permission name required' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_grant',
      failureReason: 'missing_permission_name',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  const role = getRoleById(roleId);
  if (!role) {
    const responsePayload = { error: 'Role not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_grant',
      failureReason: 'role_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  // Verify permission exists
  const allPermissions = getAllPermissions();
  if (!allPermissions.some(p => p.name === permissionName)) {
    const responsePayload = { error: 'Invalid permission name' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_grant',
      failureReason: 'invalid_permission',
      responseStatus: 400,
      responseBody: responsePayload
    });
    return res.status(400).json(responsePayload);
  }

  try {
    grantPermissionToRole(roleId, permissionName);
    
    const responsePayload = { success: true };
    logAuditEvent(req, {
      success: true,
      event: 'admin_permission_grant',
      responseStatus: 200,
      responseBody: responsePayload
    });
    
    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to grant permission to role' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_grant',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

// Revoke permission from a role
app.delete('/api/admin/roles/:roleId/permissions/:permissionName', authMiddleware, requireAdmin, (req, res) => {
  const { roleId, permissionName } = req.params;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);
  const adminUser = getUserById(req.user.userId);

  const role = getRoleById(roleId);
  if (!role) {
    const responsePayload = { error: 'Role not found' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_revoke',
      failureReason: 'role_not_found',
      responseStatus: 404,
      responseBody: responsePayload
    });
    return res.status(404).json(responsePayload);
  }

  try {
    revokePermissionFromRole(roleId, permissionName);
    
    const responsePayload = { success: true };
    logAuditEvent(req, {
      success: true,
      event: 'admin_permission_revoke',
      responseStatus: 200,
      responseBody: responsePayload
    });
    
    res.json(responsePayload);
  } catch (err) {
    const responsePayload = { error: 'Failed to revoke permission from role' };
    logAuditEvent(req, {
      success: false,
      event: 'admin_permission_revoke',
      failureReason: 'database_error',
      responseStatus: 500,
      responseBody: responsePayload
    });
    res.status(500).json(responsePayload);
  }
});

app.get('/api/admin/header-auth-settings', authMiddleware, requireAdmin, (req, res) => {
  try {
    res.json(getHeaderAuthConfig());
  } catch (err) {
    console.error('Failed to load header auth settings:', err);
    res.status(500).json({ error: 'Failed to load header authentication settings' });
  }
});

app.put('/api/admin/header-auth-settings', authMiddleware, requireAdmin, (req, res) => {
  const { enabled, usernameHeader, allowedRemoteIps } = req.body;
  const requestPath = req.originalUrl || req.url;
  const requestHeaders = getAuthRequestHeaders(req);

  const normalizedUsernameHeader = (usernameHeader || '').trim();
  if (!normalizedUsernameHeader || !/^[A-Za-z0-9\-]+$/.test(normalizedUsernameHeader)) {
    const responsePayload = { error: 'Invalid username header name' };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_settings_update',
      failureReason: 'invalid_header_auth_settings',
      responseStatus: 400,
      responseBody: responsePayload
    });

    return res.status(400).json(responsePayload);
  }

  const allowedText = (allowedRemoteIps || '').trim();
  if (!allowedText) {
    const responsePayload = { error: 'Allowed remote IP list is required' };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_settings_update',
      failureReason: 'invalid_header_auth_settings',
      responseStatus: 400,
      responseBody: responsePayload
    });

    return res.status(400).json(responsePayload);
  }

  const allowedEntries = allowedText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (allowedEntries.length === 0) {
    const responsePayload = { error: 'At least one allowed remote IP or CIDR is required' };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_settings_update',
      failureReason: 'invalid_header_auth_settings',
      responseStatus: 400,
      responseBody: responsePayload
    });

    return res.status(400).json(responsePayload);
  }

  const invalidEntry = allowedEntries.find((entry) => !isValidIpOrCidr(entry));
  if (invalidEntry) {
    const responsePayload = { error: `Invalid allowed remote IP/CIDR entry: ${invalidEntry}` };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_settings_update',
      failureReason: 'invalid_header_auth_settings',
      responseStatus: 400,
      responseBody: responsePayload
    });

    return res.status(400).json(responsePayload);
  }

  try {
    const updatedSettings = updateHeaderAuthConfig({
      enabled: !!enabled,
      usernameHeader: normalizedUsernameHeader,
      allowedRemoteIps: allowedEntries.join('\n')
    });

    logAuditEvent(req, {
      success: true,
      event: 'header_auth_settings_update',
      additionalDetails: {
        enabled: updatedSettings.enabled,
        usernameHeader: updatedSettings.usernameHeader,
        allowedRemoteIpsCount: allowedEntries.length
      },
      responseStatus: 200,
      responseBody: { success: true, settings: updatedSettings }
    });

    res.json({ success: true, settings: updatedSettings });
  } catch (err) {
    console.error('Failed to update header auth settings:', err);
    const responsePayload = { error: 'Failed to update header authentication settings' };

    logAuditEvent(req, {
      success: false,
      event: 'header_auth_settings_update',
      failureReason: 'header_auth_settings_update_failed',
      responseStatus: 500,
      responseBody: responsePayload
    });

    res.status(500).json(responsePayload);
  }
});

app.get('/api/admin/auth-audit-logs', authMiddleware, requireAdmin, (req, res) => {
  const search = typeof req.query.search === 'string' ? req.query.search : '';
  const limit = req.query.limit;
  const offset = req.query.offset;

  try {
    const result = getAuthAuditLogs({ search, limit, offset });

    const rows = result.rows.map((row) => ({
      ...row,
      success: !!row.success,
      http_headers: row.http_headers ? JSON.parse(row.http_headers) : null,
      details: row.details ? JSON.parse(row.details) : null,
      response_data: row.response_data ? JSON.parse(row.response_data) : null
    }));

    res.json({
      rows,
      total: result.total,
      limit: parseInt(limit, 10) || 100,
      offset: parseInt(offset, 10) || 0
    });
  } catch (err) {
    console.error('Failed to fetch auth audit logs:', err);
    res.status(500).json({ error: 'Failed to fetch auth audit logs' });
  }
});

app.get('/api/admin/auth-audit-logs/export.csv', authMiddleware, requireAdmin, (req, res) => {
  const search = typeof req.query.search === 'string' ? req.query.search : '';

  try {
    const { rows } = getAuthAuditLogs({ search, limit: 10000, offset: 0 });
    const header = [
      'occurred_at',
      'success',
      'auth_type',
      'username',
      'role_name',
      'source_ip',
      'request_method',
      'request_path',
      'failure_reason',
      'http_headers',
      'details'
    ];

    const csvLines = [header.map(csvEscape).join(',')];

    for (const row of rows) {
      csvLines.push([
        row.occurred_at,
        row.success ? 'success' : 'failure',
        row.auth_type,
        row.username,
        row.role_name,
        row.source_ip,
        row.request_method,
        row.request_path,
        row.failure_reason,
        row.http_headers,
        row.details
      ].map(csvEscape).join(','));
    }

    const timestamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const fileName = `auth-audit-log-${timestamp}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(csvLines.join('\n'));
  } catch (err) {
    console.error('Failed to export auth audit logs:', err);
    res.status(500).json({ error: 'Failed to export auth audit logs' });
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
        '-k',
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
  res.render('dashboard', { activePage: 'dashboard' });
});

app.get('/admin', authMiddleware, requireAdmin, (req, res) => {
  res.render('admin', { activePage: 'admin' });
});

app.get('/admin/audit-log', authMiddleware, requireAdmin, (req, res) => {
  res.redirect('/admin');
});

app.get('/reset-password', (req, res) => {
  res.render('reset-password');
});

// Serve static assets
app.use('/static', express.static(path.join(__dirname, 'static')));

app.listen(port, () => {
  console.log(`ZTNA Net-Tools listening on port ${port}`);
});

