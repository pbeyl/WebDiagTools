require('dotenv').config();
const express = require('express');
const { spawn } = require('child_process');
const jwt = require('jsonwebtoken');
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

const { authMiddleware, requireAdmin, generateToken, tryHeaderAuth, JWT_SECRET } = require('./auth');

const app = express();
const port = process.env.PORT || 8080;
const bindHost = process.env.BIND_HOST || '0.0.0.0';
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

function parsePositiveIntEnv(name, fallbackValue) {
  const rawValue = process.env[name];
  if (rawValue === undefined) {
    return fallbackValue;
  }

  const parsed = parseInt(rawValue, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return fallbackValue;
  }

  return parsed;
}

const API_RATE_LIMIT_MAX_REQUESTS = parsePositiveIntEnv('API_RATE_LIMIT_MAX_REQUESTS', 4);
const API_RATE_LIMIT_WINDOW_MS = parsePositiveIntEnv('API_RATE_LIMIT_WINDOW_MS', 1000);
const apiRateLimitStore = new Map();

function getHeaderAuthIdentity(req) {
  const config = getHeaderAuthConfig();
  if (!config || !config.enabled || !config.usernameHeader) {
    return null;
  }

  const headerName = String(config.usernameHeader).trim().toLowerCase();
  if (!headerName) {
    return null;
  }

  const rawValue = req.headers[headerName];
  const value = Array.isArray(rawValue) ? rawValue[0] : rawValue;
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  return normalized ? `header:${normalized}` : null;
}

function getBearerTokenIdentity(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return null;
  }

  const token = match[1].trim();
  if (!token) {
    return null;
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return `bearer:${tokenHash}`;
}

function getCookieUserIdentity(req) {
  const token = req.cookies?.token;
  if (!token || typeof token !== 'string') {
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded?.userId) {
      return `user:${decoded.userId}`;
    }
  } catch (err) {
    return null;
  }

  return null;
}

function getRateLimitKey(req) {
  return (
    getHeaderAuthIdentity(req)
    || getBearerTokenIdentity(req)
    || getCookieUserIdentity(req)
    || `ip:${req.ip || 'unknown'}`
  );
}

function apiRateLimitMiddleware(req, res, next) {
  const key = getRateLimitKey(req);
  const now = Date.now();
  const windowStart = now - (now % API_RATE_LIMIT_WINDOW_MS);

  let entry = apiRateLimitStore.get(key);
  if (!entry || entry.windowStart !== windowStart) {
    entry = { windowStart, count: 0 };
  }

  entry.count += 1;
  apiRateLimitStore.set(key, entry);

  const remaining = Math.max(0, API_RATE_LIMIT_MAX_REQUESTS - entry.count);
  res.setHeader('X-RateLimit-Limit', API_RATE_LIMIT_MAX_REQUESTS.toString());
  res.setHeader('X-RateLimit-Remaining', remaining.toString());
  res.setHeader('X-RateLimit-Window-Ms', API_RATE_LIMIT_WINDOW_MS.toString());

  if (entry.count > API_RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterSeconds = Math.ceil((windowStart + API_RATE_LIMIT_WINDOW_MS - now) / 1000);
    res.setHeader('Retry-After', Math.max(1, retryAfterSeconds).toString());
    return res.status(429).json({
      error: `Rate limit exceeded: maximum ${API_RATE_LIMIT_MAX_REQUESTS} requests per ${API_RATE_LIMIT_WINDOW_MS}ms`
    });
  }

  next();
}

setInterval(() => {
  const cutoff = Date.now() - (API_RATE_LIMIT_WINDOW_MS * 2);
  for (const [key, entry] of apiRateLimitStore.entries()) {
    if (entry.windowStart < cutoff) {
      apiRateLimitStore.delete(key);
    }
  }
}, 30000).unref();

app.use('/api', apiRateLimitMiddleware);

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

const NET_TOOL_REQUEST_TIMEOUT_MS = parsePositiveIntEnv('NET_TOOL_REQUEST_TIMEOUT_MS', 15000);
const NET_TOOL_MAX_OUTPUT_BYTES = parsePositiveIntEnv('NET_TOOL_MAX_OUTPUT_BYTES', 262144);
const PROCESS_KILL_GRACE_MS = 1000;

function terminateChildProcess(child) {
  if (!child || child.killed) {
    return;
  }

  child.kill('SIGTERM');
  setTimeout(() => {
    if (!child.killed) {
      child.kill('SIGKILL');
    }
  }, PROCESS_KILL_GRACE_MS).unref();
}

// Helper function to execute a command and return output as a promise
function executeCommand(command, args, options = {}) {
  const timeoutMs = options.timeoutMs || NET_TOOL_REQUEST_TIMEOUT_MS;
  const maxOutputBytes = options.maxOutputBytes || NET_TOOL_MAX_OUTPUT_BYTES;

  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let output = '';
    let outputBytes = 0;
    let timedOut = false;
    let outputLimitReached = false;

    const timeoutHandle = setTimeout(() => {
      timedOut = true;
      terminateChildProcess(child);
    }, timeoutMs);

    const appendChunk = (data) => {
      if (outputLimitReached) {
        return;
      }

      const buffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
      const remainingBytes = maxOutputBytes - outputBytes;

      if (remainingBytes <= 0) {
        outputLimitReached = true;
        terminateChildProcess(child);
        return;
      }

      if (buffer.length <= remainingBytes) {
        output += buffer.toString();
        outputBytes += buffer.length;
        return;
      }

      output += buffer.subarray(0, remainingBytes).toString();
      outputBytes += remainingBytes;
      outputLimitReached = true;
      terminateChildProcess(child);
    };

    child.stdout.on('data', (data) => {
      appendChunk(data);
    });

    child.stderr.on('data', (data) => {
      appendChunk(data);
    });

    child.on('close', (code) => {
      clearTimeout(timeoutHandle);

      if (timedOut) {
        output += '\n--- Command timeout exceeded; process terminated ---\n';
      } else if (outputLimitReached) {
        output += '\n--- Command output limit reached; process terminated ---\n';
      }

      resolve(output);
    });

    child.on('error', (err) => {
      clearTimeout(timeoutHandle);
      reject(err);
    });
  });
}

function formatCliCommand(command, args) {
  const shellSafePattern = /^[A-Za-z0-9_@%+=:,./:-]+$/;
  const formatArg = (value) => {
    const text = String(value);
    if (shellSafePattern.test(text)) {
      return text;
    }
    return `'${text.replace(/'/g, `'"'"'`)}'`;
  };

  return [command, ...args].map(formatArg).join(' ');
}

const TOOL_NAMES = ['ping', 'nslookup', 'nslookup_bulk', 'traceroute', 'mtr', 'openssl_sconnect', 'curl'];
const DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'ANY'];
const HOST_VALUE_PATTERN = /^[a-zA-Z0-9.:-_]+$/;
const MAX_HOST_VALUE_LENGTH = 255;
const MAX_BULK_HOSTS = 200;

const TOOL_INPUT_SCHEMAS = {
  ping: {
    required: ['tool', 'host'],
    optional: ['packetSize', 'dontFrag']
  },
  nslookup: {
    required: ['tool', 'host'],
    optional: ['dnsServer', 'recordType', 'debug']
  },
  nslookup_bulk: {
    required: ['tool', 'hosts'],
    optional: ['dnsServer', 'recordType', 'debug']
  },
  traceroute: {
    required: ['tool', 'host'],
    optional: []
  },
  mtr: {
    required: ['tool', 'host'],
    optional: ['port']
  },
  openssl_sconnect: {
    required: ['tool', 'host'],
    optional: ['port', 'debug']
  },
  curl: {
    required: ['tool', 'host'],
    optional: ['port', 'protocol']
  }
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeHostLikeValue(value, fieldName) {
  if (typeof value !== 'string') {
    throw new Error(`Invalid ${fieldName}: must be a string`);
  }

  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`Invalid ${fieldName}: value is required`);
  }

  if (trimmed.length > MAX_HOST_VALUE_LENGTH) {
    throw new Error(`Invalid ${fieldName}: value is too long`);
  }

  if (!HOST_VALUE_PATTERN.test(trimmed)) {
    throw new Error(`Invalid ${fieldName}`);
  }

  return trimmed;
}

function normalizeOptionalBoolean(value, fieldName) {
  if (value === undefined) {
    return false;
  }

  if (typeof value !== 'boolean') {
    throw new Error(`Invalid ${fieldName}: must be a boolean`);
  }

  return value;
}

function normalizeOptionalIntegerInRange(value, fieldName, min, max) {
  if (value === undefined) {
    return null;
  }

  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new Error(`Invalid ${fieldName}: must be an integer`);
  }

  if (value < min || value > max) {
    throw new Error(`Invalid ${fieldName}: must be between ${min} and ${max}`);
  }

  return value;
}

function validateToolInputSchema(body) {
  if (!isPlainObject(body)) {
    throw new Error('Invalid request body');
  }

  if (typeof body.tool !== 'string') {
    throw new Error('Invalid tool specified.');
  }

  const tool = body.tool.trim();
  if (!TOOL_NAMES.includes(tool)) {
    throw new Error('Invalid tool specified.');
  }

  const schema = TOOL_INPUT_SCHEMAS[tool];
  const allowedKeys = new Set(['tool', ...schema.required.filter((key) => key !== 'tool'), ...schema.optional]);
  const unknownKey = Object.keys(body).find((key) => !allowedKeys.has(key));
  if (unknownKey) {
    throw new Error(`Unexpected field: ${unknownKey}`);
  }

  const missingField = schema.required.find((field) => body[field] === undefined);
  if (missingField) {
    throw new Error(`Missing required field: ${missingField}`);
  }

  const normalized = { tool };

  if (tool === 'nslookup_bulk') {
    if (typeof body.hosts !== 'string') {
      throw new Error('Invalid hosts: must be a string');
    }

    const hostList = body.hosts
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

    if (hostList.length === 0) {
      throw new Error('Please provide hosts for bulk lookup.');
    }

    if (hostList.length > MAX_BULK_HOSTS) {
      throw new Error(`Too many hosts provided. Maximum is ${MAX_BULK_HOSTS}.`);
    }

    normalized.hostList = hostList.map((hostValue) => normalizeHostLikeValue(hostValue, 'host'));
  } else {
    normalized.host = normalizeHostLikeValue(body.host, 'host');
  }

  if (body.dnsServer !== undefined) {
    normalized.dnsServer = normalizeHostLikeValue(body.dnsServer, 'dnsServer');
  } else {
    normalized.dnsServer = null;
  }

  if (body.recordType !== undefined) {
    if (typeof body.recordType !== 'string') {
      throw new Error('Invalid DNS record type specified.');
    }
    const up = body.recordType.trim().toUpperCase();
    if (!DNS_RECORD_TYPES.includes(up)) {
      throw new Error('Invalid DNS record type specified.');
    }
    normalized.recordType = up;
  } else {
    normalized.recordType = null;
  }

  normalized.packetSize = normalizeOptionalIntegerInRange(body.packetSize, 'packetSize', 0, 65535);
  normalized.dontFrag = normalizeOptionalBoolean(body.dontFrag, 'dontFrag');
  normalized.port = normalizeOptionalIntegerInRange(body.port, 'port', 1, 65535);

  if (body.protocol !== undefined) {
    if (typeof body.protocol !== 'string') {
      throw new Error('Invalid protocol specified.');
    }

    const protocolValue = body.protocol.trim().toLowerCase();
    if (!['http', 'https'].includes(protocolValue)) {
      throw new Error('Invalid protocol specified.');
    }

    normalized.protocol = protocolValue;
  } else {
    normalized.protocol = null;
  }

  normalized.debug = normalizeOptionalBoolean(body.debug, 'debug');

  return normalized;
}

// API endpoint to run network tools
app.post('/api/net-tool', authMiddleware, (req, res) => {
  let validatedInput;
  try {
    validatedInput = validateToolInputSchema(req.body);
  } catch (err) {
    return res.status(400).send(`Error: ${err.message}`);
  }

  const {
    tool,
    host,
    hostList,
    dnsServer,
    recordType,
    packetSize,
    dontFrag,
    port,
    protocol,
    debug
  } = validatedInput;

  // Check if user has permission for this tool
  const toolPermissionCandidates =
    tool === 'openssl_sconnect'
      ? ['tool_openssl']
      : [`tool_${tool}`];
  const hasAdmin = req.user.permissions.includes('administration');
  const hasToolPerm = toolPermissionCandidates.some((permission) => req.user.permissions.includes(permission));

  if (!hasAdmin && !hasToolPerm) {
    return res.status(403).json({ error: `Permission denied: Access to ${tool} tool not granted` });
  }

  const connectPort = port || 443;

  // Special handling for bulk nslookup
  if (tool === 'nslookup_bulk') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    const requestStartedAt = Date.now();
    const requestDeadline = requestStartedAt + NET_TOOL_REQUEST_TIMEOUT_MS;
    let outputBytes = 0;
    let responseClosed = false;

    const writeWithLimit = (chunk) => {
      if (responseClosed) {
        return false;
      }

      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      const remainingBytes = NET_TOOL_MAX_OUTPUT_BYTES - outputBytes;

      if (remainingBytes <= 0) {
        return false;
      }

      if (buffer.length <= remainingBytes) {
        res.write(buffer);
        outputBytes += buffer.length;
        return true;
      }

      res.write(buffer.subarray(0, remainingBytes));
      outputBytes += remainingBytes;
      return false;
    };

    const endBulkResponse = (message) => {
      if (responseClosed) {
        return;
      }
      res.write(`\n--- ${message} ---`);
      res.end();
      responseClosed = true;
    };

    (async () => {
      try {
        if (!writeWithLimit(`Performing NSLookup on ${hostList.length} host(s)...\n\n`)) {
          endBulkResponse('Output limit reached; request terminated');
          return;
        }

        // Process each host sequentially
        for (let i = 0; i < hostList.length; i++) {
          if (Date.now() >= requestDeadline) {
            endBulkResponse('Request timeout exceeded; processing terminated');
            return;
          }

          const queryHost = hostList[i];

          if (!writeWithLimit(`\n[${i + 1}/${hostList.length}] NSLookup: ${queryHost}\n`)) {
            endBulkResponse('Output limit reached; request terminated');
            return;
          }

          if (!writeWithLimit(`${'='.repeat(60)}\n`)) {
            endBulkResponse('Output limit reached; request terminated');
            return;
          }

          try {
            const args = [];
            if (debug) {
              args.push('-debug');
            }
            if (recordType) {
              args.push(`-type=${recordType}`);
            }
            args.push(queryHost);
            if (dnsServer) {
              args.push(dnsServer);
            }

            const displayedCommand = formatCliCommand('nslookup', args);
            if (!writeWithLimit(`Command: ${displayedCommand}\n\n`)) {
              endBulkResponse('Output limit reached; request terminated');
              return;
            }

            const remainingRequestMs = requestDeadline - Date.now();
            if (remainingRequestMs <= 0) {
              endBulkResponse('Request timeout exceeded; processing terminated');
              return;
            }

            const remainingOutputBytes = NET_TOOL_MAX_OUTPUT_BYTES - outputBytes;
            if (remainingOutputBytes <= 0) {
              endBulkResponse('Output limit reached; request terminated');
              return;
            }

            const output = await executeCommand('nslookup', args, {
              timeoutMs: remainingRequestMs,
              maxOutputBytes: remainingOutputBytes
            });

            if (!writeWithLimit(output)) {
              endBulkResponse('Output limit reached; request terminated');
              return;
            }
          } catch (err) {
            if (!writeWithLimit(`Error executing nslookup: ${err.message}\n`)) {
              endBulkResponse('Output limit reached; request terminated');
              return;
            }
          }
        }

        writeWithLimit(`\n\n--- Bulk NSLookup completed ---`);
        res.end();
        responseClosed = true;
      } catch (err) {
        console.error('Bulk nslookup error:', err);
        endBulkResponse(`ERROR: ${err.message}`);
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
      if (packetSize !== null) {
        args.push('-s', packetSize.toString());
      }
      if (dontFrag) {
        // ping options vary; try common flags
        args.push('-M', 'do');
        args.push('-D');
      }
      args.push(host);
      break;
      
    case 'nslookup':
      command = 'nslookup';
      args = [];
      if (debug) {
        args.push('-debug');
      }
      if (recordType) {
        args.push(`-type=${recordType}`);
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
      args = ['-r', '-c 1', '-w', '-b', '--tcp'];
      
      if (port) {
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
      if (!debug) {
        args.push('-brief');
      } else {
        args.push('-showcerts');
      }
      break;

    case 'curl':
      command = 'curl';
      const curlProtocol = (protocol === 'http') ? 'http' : 'https';
      const curlPort = port ? `:${port}` : '';
      const curlUrl = `${curlProtocol}://${host}${curlPort}`;
      args = [
        '-s',
        '-S',
        '-k',
        '-o', '/dev/null',
        '-w', '\nHTTP Code, DNS Lookup(sec), TLS Handshake(sec), Time to First Byte(sec), Total Time(sec)\n%{http_code}, %{time_namelookup}, %{time_appconnect}, %{time_starttransfer}, %{time_total}\n',
        curlUrl
      ];
      break;
  }

  // --- Process Execution ---
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Transfer-Encoding', 'chunked');

  let outputBytes = 0;
  let responseClosed = false;
  let terminationReason = null;

  const writeWithLimit = (chunk) => {
    if (responseClosed) {
      return false;
    }

    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    const remainingBytes = NET_TOOL_MAX_OUTPUT_BYTES - outputBytes;

    if (remainingBytes <= 0) {
      return false;
    }

    if (buffer.length <= remainingBytes) {
      res.write(buffer);
      outputBytes += buffer.length;
      return true;
    }

    res.write(buffer.subarray(0, remainingBytes));
    outputBytes += remainingBytes;
    return false;
  };

  const endStreamResponse = (message) => {
    if (responseClosed) {
      return;
    }

    if (message) {
      res.write(message);
    }
    res.end();
    responseClosed = true;
  };

  const displayedCommand = formatCliCommand(command, args);
  if (!writeWithLimit(`Command: ${displayedCommand}\n\n`)) {
    return endStreamResponse('\n--- Output limit reached; request terminated ---');
  }

  const child = spawn(command, args);

  const timeoutHandle = setTimeout(() => {
    terminationReason = 'timeout';
    terminateChildProcess(child);
  }, NET_TOOL_REQUEST_TIMEOUT_MS);

  // For openssl s_client, we need to send 'Q' to cleanly exit
  if (tool === 'openssl_sconnect') {
    child.stdin.write('Q\n');
    child.stdin.end();
  }

  // Stream stdout
  child.stdout.on('data', (data) => {
    if (!writeWithLimit(data)) {
      terminationReason = 'output_cap';
      terminateChildProcess(child);
    }
  });

  // Stream stderr
  child.stderr.on('data', (data) => {
    if (!writeWithLimit(data)) {
      terminationReason = 'output_cap';
      terminateChildProcess(child);
    }
  });

  // Handle process exit
  child.on('close', (code) => {
    clearTimeout(timeoutHandle);

    if (terminationReason === 'timeout') {
      endStreamResponse('\n--- Request timeout exceeded; process terminated ---');
      return;
    }

    if (terminationReason === 'output_cap') {
      endStreamResponse('\n--- Output limit reached; process terminated ---');
      return;
    }

    endStreamResponse(`\n--- Process finished ---`);
  });

  // Handle errors
  child.on('error', (err) => {
    clearTimeout(timeoutHandle);
    console.error(`Failed to start subprocess: ${err}`);
    endStreamResponse(`\n--- ERROR: Failed to start subprocess ${err.message} ---`);
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

app.listen(port, bindHost, () => {
  console.log(`ZTNA Net-Tools listening on ${bindHost}:${port}`);
});

